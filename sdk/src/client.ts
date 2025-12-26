import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionSignature,
  ComputeBudgetProgram,
  Signer,
} from '@solana/web3.js';
import {
  VerifierConfig,
  VKUploadResult,
  VerificationResult,
  VerifyOptions,
  VerificationState,
  VerificationPhase,
  PhaseResult,
  PROOF_SIZE,
  VK_SIZE,
  BUFFER_HEADER_SIZE,
  VK_HEADER_SIZE,
  STATE_SIZE,
  DEFAULT_CHUNK_SIZE,
  DEFAULT_COMPUTE_UNIT_LIMIT,
  RECEIPT_SEED,
  RECEIPT_SIZE,
} from './types.js';
import {
  createInitVKBufferInstruction,
  createUploadVKChunkInstruction,
  createInitBufferInstruction,
  createUploadChunkInstruction,
  createSetPublicInputsInstruction,
  createPhase1Instruction,
  createPhase2RoundsInstruction,
  createPhase2dAnd3aInstruction,
  createPhase3bCombinedInstruction,
  createPhase3cAndPairingInstruction,
  createAccountInstruction,
  createReceiptInstruction,
  createCloseAccountsInstruction,
} from './instructions.js';
// @ts-ignore - no types available
import { keccak256 } from 'js-sha3';

/**
 * Client for verifying Noir UltraHonk proofs on Solana
 *
 * @example
 * ```typescript
 * const verifier = new SolanaNoirVerifier(connection, {
 *   programId: new PublicKey('...')
 * });
 *
 * // Upload VK once per circuit
 * const { vkAccount } = await verifier.uploadVK(payer, vkBytes);
 *
 * // Verify proofs using the VK account
 * const result = await verifier.verify(payer, proof, publicInputs, vkAccount);
 * console.log('Verified:', result.verified);
 * ```
 */
export class SolanaNoirVerifier {
  private connection: Connection;
  private programId: PublicKey;
  private chunkSize: number;
  private computeUnitLimit: number;

  constructor(connection: Connection, config: VerifierConfig) {
    this.connection = connection;
    this.programId = config.programId;
    this.chunkSize = config.chunkSize ?? DEFAULT_CHUNK_SIZE;
    this.computeUnitLimit = config.computeUnitLimit ?? DEFAULT_COMPUTE_UNIT_LIMIT;
  }

  /**
   * Upload a verification key to the chain
   *
   * @param payer - The keypair paying for the transaction
   * @param vk - The verification key bytes (1,760 bytes)
   * @returns VK account public key and upload details
   */
  async uploadVK(payer: Keypair, vk: Buffer): Promise<VKUploadResult> {
    if (vk.length !== VK_SIZE) {
      throw new Error(`Invalid VK size: expected ${VK_SIZE}, got ${vk.length}`);
    }

    const vkAccount = Keypair.generate();
    const vkBufferSize = VK_HEADER_SIZE + VK_SIZE;
    const rent = await this.connection.getMinimumBalanceForRentExemption(vkBufferSize);
    const signatures: TransactionSignature[] = [];

    // Create VK account + initialize
    const setupTx = new Transaction()
      .add(createAccountInstruction(
        payer.publicKey,
        vkAccount.publicKey,
        rent,
        vkBufferSize,
        this.programId
      ))
      .add(createInitVKBufferInstruction(this.programId, vkAccount.publicKey));

    const setupSig = await this.sendAndConfirm(setupTx, [payer, vkAccount]);
    signatures.push(setupSig);

    // Upload VK chunks in parallel
    const chunks = this.splitIntoChunks(vk);
    const blockhash = await this.connection.getLatestBlockhash();

    const uploadTxs = chunks.map(({ offset, data }) => {
      const tx = new Transaction().add(
        createUploadVKChunkInstruction(this.programId, vkAccount.publicKey, offset, data)
      );
      tx.feePayer = payer.publicKey;
      tx.recentBlockhash = blockhash.blockhash;
      return tx;
    });

    // Send all, then confirm all
    const uploadSigs = await Promise.all(
      uploadTxs.map(tx => this.connection.sendTransaction(tx, [payer], { skipPreflight: true }))
    );
    await Promise.all(
      uploadSigs.map(sig =>
        this.connection.confirmTransaction({ signature: sig, ...blockhash }, 'confirmed')
      )
    );
    signatures.push(...uploadSigs);

    return {
      vkAccount: vkAccount.publicKey,
      signatures,
      numChunks: chunks.length,
    };
  }

  /**
   * Verify a proof on-chain
   *
   * @param payer - The keypair paying for transactions
   * @param proof - The proof bytes (16,224 bytes)
   * @param publicInputs - Array of public input buffers (32 bytes each)
   * @param vkAccount - The VK account public key
   * @param options - Optional verification options
   * @returns Verification result
   */
  async verify(
    payer: Keypair,
    proof: Buffer,
    publicInputs: Buffer[],
    vkAccount: PublicKey,
    options?: VerifyOptions
  ): Promise<VerificationResult> {
    if (proof.length !== PROOF_SIZE) {
      throw new Error(`Invalid proof size: expected ${PROOF_SIZE}, got ${proof.length}`);
    }

    const signatures: TransactionSignature[] = [];
    let totalCUs = 0;
    let numSteps = 0; // Sequential steps (parallel uploads = 1 step)
    const phases: PhaseResult[] = []; // Per-phase CU tracking
    const autoClose = options?.autoClose ?? true; // Default to true
    let recoveredLamports = 0;
    let accountsClosed = false;

    // Concatenate public inputs
    const piBuffer = Buffer.concat(publicInputs);
    const numPi = publicInputs.length;

    // Create accounts
    const proofAccount = Keypair.generate();
    const stateAccount = Keypair.generate();
    const proofBufferSize = BUFFER_HEADER_SIZE + piBuffer.length + PROOF_SIZE;
    const proofRent = await this.connection.getMinimumBalanceForRentExemption(proofBufferSize);
    const stateRent = await this.connection.getMinimumBalanceForRentExemption(STATE_SIZE);

    options?.onProgress?.('setup', 0, 1);

    // TX size limit is 1232 bytes. Calculate what fits:
    // - Bundled TX (2 CreateAccount + Init + SetPI): ~350 bytes overhead → max ~880 bytes PI
    // - Separate PI TX: ~130 bytes overhead → max ~1100 bytes PI (~34 public inputs)
    const PI_BUNDLE_THRESHOLD = 800;
    const PI_SINGLE_TX_MAX = 1100;

    if (piBuffer.length > PI_SINGLE_TX_MAX) {
      throw new Error(
        `Public inputs too large: ${piBuffer.length} bytes (max ~${PI_SINGLE_TX_MAX}). ` +
        `Max ~34 public inputs supported.`
      );
    }

    try {
      // --- Verification logic wrapped in try-finally for cleanup ---

      if (piBuffer.length <= PI_BUNDLE_THRESHOLD) {
        // Create accounts + init + set public inputs in one TX
        const setupTx = new Transaction()
          .add(createAccountInstruction(payer.publicKey, proofAccount.publicKey, proofRent, proofBufferSize, this.programId))
          .add(createAccountInstruction(payer.publicKey, stateAccount.publicKey, stateRent, STATE_SIZE, this.programId))
          .add(createInitBufferInstruction(this.programId, proofAccount.publicKey, numPi))
          .add(createSetPublicInputsInstruction(this.programId, proofAccount.publicKey, piBuffer));

        const setupSig = await this.sendAndConfirm(setupTx, [payer, proofAccount, stateAccount]);
        signatures.push(setupSig);
        numSteps++;
      } else {
        // Split: accounts + init in one TX, PI in another
        const accountsTx = new Transaction()
          .add(createAccountInstruction(payer.publicKey, proofAccount.publicKey, proofRent, proofBufferSize, this.programId))
          .add(createAccountInstruction(payer.publicKey, stateAccount.publicKey, stateRent, STATE_SIZE, this.programId))
          .add(createInitBufferInstruction(this.programId, proofAccount.publicKey, numPi));

        const accountsSig = await this.sendAndConfirm(accountsTx, [payer, proofAccount, stateAccount]);
        signatures.push(accountsSig);

        const piTx = new Transaction()
          .add(createSetPublicInputsInstruction(this.programId, proofAccount.publicKey, piBuffer));

        const piSig = await this.sendAndConfirm(piTx, [payer]);
        signatures.push(piSig);
        numSteps += 2;
      }

    // Upload proof chunks in parallel
    options?.onProgress?.('upload', 0, 1);
    const chunks = this.splitIntoChunks(proof);
    const blockhash = await this.connection.getLatestBlockhash();

    const uploadTxs = chunks.map(({ offset, data }) => {
      const tx = new Transaction().add(
        createUploadChunkInstruction(this.programId, proofAccount.publicKey, offset, data)
      );
      tx.feePayer = payer.publicKey;
      tx.recentBlockhash = blockhash.blockhash;
      return tx;
    });

    const uploadSigs = await Promise.all(
      uploadTxs.map(tx => this.connection.sendTransaction(tx, [payer], { skipPreflight: true }))
    );
    await Promise.all(
      uploadSigs.map(sig =>
        this.connection.confirmTransaction({ signature: sig, ...blockhash }, 'confirmed')
      )
    );
    signatures.push(...uploadSigs);
    numSteps++; // Parallel uploads = 1 step

    // Phase 1: Challenge generation
    options?.onProgress?.('phase1', 0, 1);
    const phase1Result = await this.executePhase(
      payer,
      createPhase1Instruction(this.programId, stateAccount.publicKey, proofAccount.publicKey, vkAccount)
    );
    signatures.push(phase1Result.signature);
    totalCUs += phase1Result.cus;
    numSteps++;
    phases.push({ name: 'Phase 1: Challenges', cus: phase1Result.cus });

    // Get log_n from state for sumcheck rounds
    const logN = await this.getLogN(stateAccount.publicKey);
    const roundsPerTx = 6;

    // Phase 2: Sumcheck rounds
    let roundTx = 0;
    const totalRoundTxs = Math.ceil(logN / roundsPerTx);
    for (let r = 0; r < logN; r += roundsPerTx) {
      options?.onProgress?.('phase2_rounds', roundTx, totalRoundTxs);
      const endRound = Math.min(r + roundsPerTx, logN);
      const result = await this.executePhase(
        payer,
        createPhase2RoundsInstruction(this.programId, stateAccount.publicKey, proofAccount.publicKey, r, endRound),
        true
      );
      signatures.push(result.signature);
      totalCUs += result.cus;
      numSteps++;
      phases.push({ name: `Phase 2: Rounds ${r}-${endRound - 1}`, cus: result.cus });
      roundTx++;
    }

    // Combined Phase 2d+3a: Relations + Weights (~1.1M CUs, saves 1 TX)
    options?.onProgress?.('phase2d_and_3a', 0, 1);
    const relationsAnd3aResult = await this.executePhase(
      payer,
      createPhase2dAnd3aInstruction(this.programId, stateAccount.publicKey, proofAccount.publicKey),
      true
    );
    signatures.push(relationsAnd3aResult.signature);
    totalCUs += relationsAnd3aResult.cus;
    numSteps++;
    phases.push({ name: 'Phase 2d+3a: Relations+Weights', cus: relationsAnd3aResult.cus });

    // Combined Phase 3b: Folding + Gemini (~800K CUs, saves 1 TX)
    options?.onProgress?.('phase3b_combined', 0, 1);
    const p3bResult = await this.executePhase(
      payer,
      createPhase3bCombinedInstruction(this.programId, stateAccount.publicKey, proofAccount.publicKey),
      true
    );
    signatures.push(p3bResult.signature);
    totalCUs += p3bResult.cus;
    numSteps++;
    phases.push({ name: 'Phase 3b: Folding+Gemini', cus: p3bResult.cus });

    // Phase 3c + 4: MSM + Pairing
    options?.onProgress?.('phase3c_pairing', 0, 1);
    const finalResult = await this.executePhase(
      payer,
      createPhase3cAndPairingInstruction(this.programId, stateAccount.publicKey, proofAccount.publicKey, vkAccount),
      true
    );
    signatures.push(finalResult.signature);
    totalCUs += finalResult.cus;
    numSteps++;
    phases.push({ name: 'Phase 3c+4: MSM+Pairing', cus: finalResult.cus });

      // Read final state
      const state = await this.getVerificationState(stateAccount.publicKey);

      return {
        verified: state.verified,
        stateAccount: stateAccount.publicKey,
        proofAccount: proofAccount.publicKey,
        totalCUs,
        numTransactions: signatures.length,
        numSteps,
        signatures,
        phases: options?.verbose ? phases : undefined,
        recoveredLamports: accountsClosed ? recoveredLamports : undefined,
        accountsClosed: accountsClosed ? true : undefined,
      };
    } finally {
      // Clean up accounts to reclaim rent (on both success and failure)
      if (autoClose) {
        try {
          const closeResult = await this.closeAccounts(payer, stateAccount.publicKey, proofAccount.publicKey);
          recoveredLamports = closeResult.recoveredLamports;
          accountsClosed = true;
          signatures.push(closeResult.signature);
        } catch (closeError) {
          // Log but don't throw - cleanup is best-effort
          console.warn('Failed to close accounts:', closeError);
        }
      }
    }
  }

  /**
   * Read verification state from an account
   */
  async getVerificationState(stateAccount: PublicKey): Promise<VerificationState> {
    const accountInfo = await this.connection.getAccountInfo(stateAccount);
    if (!accountInfo) {
      throw new Error('State account not found');
    }

    const data = accountInfo.data;
    // Parse state: [phase: u8, challenge_sub_phase: u8, sumcheck_sub_phase: u8, log_n: u8, ...]
    const phase = data[0] as VerificationPhase;
    const logN = data[3];

    // The verified flag is at offset (data.length - 32) - at the end before final padding
    // This matches the on-chain VerificationState struct layout
    const verified = data[data.length - 32] === 1;

    return { phase, logN, verified };
  }

  /**
   * Derive the receipt PDA for a given VK and public inputs
   *
   * @param vkAccount - The VK account public key
   * @param publicInputs - Array of public input buffers (32 bytes each)
   * @returns The receipt PDA public key and bump
   */
  deriveReceiptPda(vkAccount: PublicKey, publicInputs: Buffer[]): [PublicKey, number] {
    // Hash public inputs using keccak256 (matches on-chain solana_program::keccak)
    const piBuffer = Buffer.concat(publicInputs);
    const piHash = Buffer.from(keccak256.arrayBuffer(piBuffer));

    const [pda, bump] = PublicKey.findProgramAddressSync(
      [Buffer.from(RECEIPT_SEED), vkAccount.toBuffer(), piHash],
      this.programId
    );

    return [pda, bump];
  }

  /**
   * Create a verification receipt after successful verification
   *
   * @param payer - The keypair paying for the transaction
   * @param stateAccount - The verification state account (must be Complete)
   * @param proofAccount - The proof buffer account
   * @param vkAccount - The VK account
   * @param publicInputs - Array of public input buffers (for PDA derivation)
   * @returns The receipt PDA public key
   */
  async createReceipt(
    payer: Keypair,
    stateAccount: PublicKey,
    proofAccount: PublicKey,
    vkAccount: PublicKey,
    publicInputs: Buffer[]
  ): Promise<PublicKey> {
    const [receiptPda] = this.deriveReceiptPda(vkAccount, publicInputs);

    const tx = new Transaction().add(
      createReceiptInstruction(
        this.programId,
        stateAccount,
        proofAccount,
        vkAccount,
        receiptPda,
        payer.publicKey
      )
    );

    await this.sendAndConfirm(tx, [payer]);
    return receiptPda;
  }

  /**
   * Get a verification receipt if it exists
   *
   * This checks if a proof was verified by looking up the receipt PDA.
   * The receipt exists only if CreateReceipt was called after verification.
   *
   * @param vkAccount - The VK account
   * @param publicInputs - The public inputs that were proven
   * @returns Receipt info if exists, null if not verified or no receipt created
   */
  async getReceipt(
    vkAccount: PublicKey,
    publicInputs: Buffer[]
  ): Promise<{ receiptPda: PublicKey; verifiedSlot: bigint; verifiedTimestamp: bigint } | null> {
    const [receiptPda] = this.deriveReceiptPda(vkAccount, publicInputs);

    const accountInfo = await this.connection.getAccountInfo(receiptPda);
    if (!accountInfo || accountInfo.data.length < RECEIPT_SIZE) {
      return null;
    }

    // Check owner
    if (!accountInfo.owner.equals(this.programId)) {
      return null;
    }

    // Read verified_slot (offset 0, 8 bytes LE)
    const verifiedSlot = accountInfo.data.readBigUInt64LE(0);
    // Read verified_timestamp (offset 8, 8 bytes LE signed)
    const verifiedTimestamp = accountInfo.data.readBigInt64LE(8);

    return { receiptPda, verifiedSlot, verifiedTimestamp };
  }

  /**
   * Close proof and state accounts to recover rent
   * 
   * @param payer - The keypair that receives the recovered lamports
   * @param stateAccount - The state account to close
   * @param proofAccount - The proof buffer account to close
   * @returns The recovered lamports amount and transaction signature
   */
  async closeAccounts(
    payer: Keypair,
    stateAccount: PublicKey,
    proofAccount: PublicKey
  ): Promise<{ recoveredLamports: number; signature: TransactionSignature }> {
    // Get current balances
    const stateInfo = await this.connection.getAccountInfo(stateAccount);
    const proofInfo = await this.connection.getAccountInfo(proofAccount);
    const recoveredLamports = (stateInfo?.lamports ?? 0) + (proofInfo?.lamports ?? 0);

    const tx = new Transaction().add(
      createCloseAccountsInstruction(
        this.programId,
        stateAccount,
        proofAccount,
        payer.publicKey
      )
    );

    const signature = await this.sendAndConfirm(tx, [payer], true);

    return { recoveredLamports, signature };
  }

  private async getLogN(stateAccount: PublicKey): Promise<number> {
    const state = await this.getVerificationState(stateAccount);
    return state.logN;
  }

  private async executePhase(
    payer: Keypair,
    instruction: import('@solana/web3.js').TransactionInstruction,
    skipSimulation = false
  ): Promise<{ signature: TransactionSignature; cus: number }> {
    const tx = new Transaction()
      .add(ComputeBudgetProgram.setComputeUnitLimit({ units: this.computeUnitLimit }))
      .add(instruction);

    const sig = await this.sendAndConfirm(tx, [payer], skipSimulation);

    // Get CUs from transaction
    const txDetails = await this.connection.getTransaction(sig, {
      maxSupportedTransactionVersion: 0,
    });
    const cus = txDetails?.meta?.computeUnitsConsumed ?? 0;

    return { signature: sig, cus };
  }

  private async sendAndConfirm(
    tx: Transaction,
    signers: Signer[],
    skipPreflight = false
  ): Promise<TransactionSignature> {
    tx.feePayer = signers[0].publicKey;
    tx.recentBlockhash = (await this.connection.getLatestBlockhash()).blockhash;

    const sig = await this.connection.sendTransaction(tx, signers, { skipPreflight });

    // Poll for confirmation
    for (let i = 0; i < 30; i++) {
      await this.sleep(500);
      const status = await this.connection.getSignatureStatus(sig);
      if (
        status.value?.confirmationStatus === 'confirmed' ||
        status.value?.confirmationStatus === 'finalized'
      ) {
        if (status.value?.err) {
          throw new Error(`Transaction failed: ${JSON.stringify(status.value.err)}`);
        }
        return sig;
      }
    }
    throw new Error('Transaction confirmation timeout');
  }

  private splitIntoChunks(data: Buffer): Array<{ offset: number; data: Buffer }> {
    const chunks: Array<{ offset: number; data: Buffer }> = [];
    let offset = 0;
    while (offset < data.length) {
      const chunkSize = Math.min(this.chunkSize, data.length - offset);
      chunks.push({
        offset,
        data: data.subarray(offset, offset + chunkSize),
      });
      offset += chunkSize;
    }
    return chunks;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

