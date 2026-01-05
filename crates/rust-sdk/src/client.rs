//! Main client for verifying Noir UltraHonk proofs on Solana

use crate::{
    error::{Result, VerifierError},
    instructions,
    types::*,
};
use sha3::{Digest, Keccak256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;

// Compute budget program ID
const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey::Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

/// Build a SetComputeUnitLimit instruction
fn set_compute_unit_limit(units: u32) -> Instruction {
    // Instruction code 2 = SetComputeUnitLimit
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction::new_with_bytes(COMPUTE_BUDGET_PROGRAM_ID, &data, vec![])
}
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Client for verifying Noir UltraHonk proofs on Solana
///
/// # Example
///
/// ```ignore
/// use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig};
///
/// let verifier = SolanaNoirVerifier::new(
///     Arc::new(RpcClient::new("http://localhost:8899")),
///     VerifierConfig::new(program_id),
/// );
///
/// // Upload VK once per circuit
/// let vk_result = verifier.upload_vk(&payer, &vk_bytes)?;
///
/// // Verify proofs
/// let result = verifier.verify(&payer, &proof, &public_inputs, &vk_result.vk_account, None)?;
/// ```
pub struct SolanaNoirVerifier {
    client: Arc<RpcClient>,
    config: VerifierConfig,
}

impl SolanaNoirVerifier {
    /// Create a new verifier client
    pub fn new(client: Arc<RpcClient>, config: VerifierConfig) -> Self {
        Self { client, config }
    }

    /// Upload a verification key to the chain
    ///
    /// # Arguments
    /// * `payer` - The keypair paying for the transaction
    /// * `vk` - The verification key bytes (1,760 bytes)
    ///
    /// # Returns
    /// VK account public key and upload details
    pub fn upload_vk(&self, payer: &Keypair, vk: &[u8]) -> Result<VkUploadResult> {
        if vk.len() != VK_SIZE {
            return Err(VerifierError::InvalidVkSize {
                expected: VK_SIZE,
                actual: vk.len(),
            });
        }

        let vk_account = Keypair::new();
        let vk_buffer_size = VK_HEADER_SIZE + VK_SIZE;
        let rent = self
            .client
            .get_minimum_balance_for_rent_exemption(vk_buffer_size)?;
        let mut signatures = Vec::new();

        // Create VK account + initialize
        let setup_ix = vec![
            system_instruction::create_account(
                &payer.pubkey(),
                &vk_account.pubkey(),
                rent,
                vk_buffer_size as u64,
                &self.config.program_id,
            ),
            instructions::init_vk_buffer(&self.config.program_id, &vk_account.pubkey()),
        ];

        let setup_sig = self.send_and_confirm(payer, &[&vk_account], setup_ix, false)?;
        signatures.push(setup_sig);

        // Upload VK chunks
        let chunks = self.split_into_chunks(vk);
        let num_chunks = chunks.len();

        for (offset, chunk_data) in chunks {
            let ix = instructions::upload_vk_chunk(
                &self.config.program_id,
                &vk_account.pubkey(),
                offset as u16,
                chunk_data,
            );
            let sig = self.send_and_confirm(payer, &[], vec![ix], true)?;
            signatures.push(sig);
        }

        Ok(VkUploadResult {
            vk_account: vk_account.pubkey(),
            signatures,
            num_chunks,
        })
    }

    /// Verify a proof on-chain
    ///
    /// # Arguments
    /// * `payer` - The keypair paying for transactions
    /// * `proof` - The proof bytes (16,224 bytes)
    /// * `public_inputs` - Concatenated public inputs (32 bytes each)
    /// * `vk_account` - The VK account public key
    /// * `options` - Optional verification options
    ///
    /// # Returns
    /// Verification result
    pub fn verify(
        &self,
        payer: &Keypair,
        proof: &[u8],
        public_inputs: &[u8],
        vk_account: &Pubkey,
        options: Option<VerifyOptions>,
    ) -> Result<VerificationResult> {
        if proof.len() != PROOF_SIZE {
            return Err(VerifierError::InvalidProofSize {
                expected: PROOF_SIZE,
                actual: proof.len(),
            });
        }

        let options = options.unwrap_or_default();
        let mut signatures = Vec::new();
        let mut total_cus = 0u64;
        let mut num_steps = 0usize;
        let mut recovered_lamports = None;
        let mut accounts_closed = false;

        let num_pi = public_inputs.len() / 32;

        // Create accounts
        let proof_account = Keypair::new();
        let state_account = Keypair::new();
        let proof_buffer_size = BUFFER_HEADER_SIZE + public_inputs.len() + PROOF_SIZE;
        let proof_rent = self
            .client
            .get_minimum_balance_for_rent_exemption(proof_buffer_size)?;
        let state_rent = self
            .client
            .get_minimum_balance_for_rent_exemption(STATE_SIZE)?;

        // Closure for cleanup
        let cleanup = |client: &SolanaNoirVerifier,
                       payer: &Keypair,
                       state_account: &Pubkey,
                       proof_account: &Pubkey|
         -> Option<(u64, Signature)> {
            match client.close_accounts(payer, state_account, proof_account) {
                Ok(result) => Some(result),
                Err(e) => {
                    log::warn!("Failed to close accounts: {:?}", e);
                    None
                }
            }
        };

        // Setup: Create accounts + init + set public inputs
        // TX size limit is 1232 bytes. Calculate what fits.
        const PI_BUNDLE_THRESHOLD: usize = 800;
        const PI_SINGLE_TX_MAX: usize = 1100;

        if public_inputs.len() > PI_SINGLE_TX_MAX {
            return Err(VerifierError::PublicInputsTooLarge {
                size: public_inputs.len(),
                max_size: PI_SINGLE_TX_MAX,
            });
        }

        if public_inputs.len() <= PI_BUNDLE_THRESHOLD {
            // Bundle: accounts + init + public inputs in one TX
            let setup_ix = vec![
                system_instruction::create_account(
                    &payer.pubkey(),
                    &proof_account.pubkey(),
                    proof_rent,
                    proof_buffer_size as u64,
                    &self.config.program_id,
                ),
                system_instruction::create_account(
                    &payer.pubkey(),
                    &state_account.pubkey(),
                    state_rent,
                    STATE_SIZE as u64,
                    &self.config.program_id,
                ),
                instructions::init_buffer(
                    &self.config.program_id,
                    &proof_account.pubkey(),
                    num_pi as u16,
                ),
                instructions::set_public_inputs(
                    &self.config.program_id,
                    &proof_account.pubkey(),
                    public_inputs,
                ),
            ];

            let sig = self.send_and_confirm(
                payer,
                &[&proof_account, &state_account],
                setup_ix,
                options.skip_preflight,
            )?;
            signatures.push(sig);
            num_steps += 1;
        } else {
            // Split: accounts + init in one TX, PI in another
            let accounts_ix = vec![
                system_instruction::create_account(
                    &payer.pubkey(),
                    &proof_account.pubkey(),
                    proof_rent,
                    proof_buffer_size as u64,
                    &self.config.program_id,
                ),
                system_instruction::create_account(
                    &payer.pubkey(),
                    &state_account.pubkey(),
                    state_rent,
                    STATE_SIZE as u64,
                    &self.config.program_id,
                ),
                instructions::init_buffer(
                    &self.config.program_id,
                    &proof_account.pubkey(),
                    num_pi as u16,
                ),
            ];

            let sig = self.send_and_confirm(
                payer,
                &[&proof_account, &state_account],
                accounts_ix,
                options.skip_preflight,
            )?;
            signatures.push(sig);

            let pi_ix = vec![instructions::set_public_inputs(
                &self.config.program_id,
                &proof_account.pubkey(),
                public_inputs,
            )];

            let sig = self.send_and_confirm(payer, &[], pi_ix, options.skip_preflight)?;
            signatures.push(sig);
            num_steps += 2;
        }

        // Upload proof chunks
        let chunks = self.split_into_chunks(proof);
        for (offset, chunk_data) in chunks {
            let ix = instructions::upload_chunk(
                &self.config.program_id,
                &proof_account.pubkey(),
                offset as u16,
                chunk_data,
            );
            let sig = self.send_and_confirm(payer, &[], vec![ix], true)?;
            signatures.push(sig);
        }
        num_steps += 1; // Count all uploads as 1 step

        // Phase 1: Challenge generation
        let (sig, cus) = self.execute_phase(
            payer,
            instructions::phase1_full(
                &self.config.program_id,
                &state_account.pubkey(),
                &proof_account.pubkey(),
                vk_account,
            ),
            options.skip_preflight,
        )?;
        signatures.push(sig);
        total_cus += cus;
        num_steps += 1;

        // Get log_n from state
        let log_n = self.get_log_n(&state_account.pubkey())?;
        let rounds_per_tx = 6u8;

        // Phase 2: Sumcheck rounds
        let mut r = 0u8;
        while r < log_n {
            let end_round = std::cmp::min(r + rounds_per_tx, log_n);
            let (sig, cus) = self.execute_phase(
                payer,
                instructions::phase2_rounds(
                    &self.config.program_id,
                    &state_account.pubkey(),
                    &proof_account.pubkey(),
                    r,
                    end_round,
                ),
                true,
            )?;
            signatures.push(sig);
            total_cus += cus;
            num_steps += 1;
            r += rounds_per_tx;
        }

        // Combined Phase 2d+3a: Relations + Weights
        let (sig, cus) = self.execute_phase(
            payer,
            instructions::phase2d_and_3a(
                &self.config.program_id,
                &state_account.pubkey(),
                &proof_account.pubkey(),
            ),
            true,
        )?;
        signatures.push(sig);
        total_cus += cus;
        num_steps += 1;

        // Combined Phase 3b: Folding + Gemini
        let (sig, cus) = self.execute_phase(
            payer,
            instructions::phase3b_combined(
                &self.config.program_id,
                &state_account.pubkey(),
                &proof_account.pubkey(),
            ),
            true,
        )?;
        signatures.push(sig);
        total_cus += cus;
        num_steps += 1;

        // Phase 3c + 4: MSM + Pairing
        let (sig, cus) = self.execute_phase(
            payer,
            instructions::phase3c_and_pairing(
                &self.config.program_id,
                &state_account.pubkey(),
                &proof_account.pubkey(),
                vk_account,
            ),
            true,
        )?;
        signatures.push(sig);
        total_cus += cus;
        num_steps += 1;

        // Read final state
        let state = self.get_verification_state(&state_account.pubkey())?;

        // Auto-close accounts to reclaim rent
        if options.auto_close {
            if let Some((lamports, close_sig)) = cleanup(
                self,
                payer,
                &state_account.pubkey(),
                &proof_account.pubkey(),
            ) {
                recovered_lamports = Some(lamports);
                accounts_closed = true;
                signatures.push(close_sig);
            }
        }

        Ok(VerificationResult {
            verified: state.verified,
            state_account: state_account.pubkey(),
            proof_account: proof_account.pubkey(),
            total_cus,
            num_transactions: signatures.len(),
            num_steps,
            signatures,
            recovered_lamports,
            accounts_closed,
        })
    }

    /// Read verification state from an account
    pub fn get_verification_state(&self, state_account: &Pubkey) -> Result<VerificationState> {
        let account_info = self
            .client
            .get_account(state_account)
            .map_err(|_| VerifierError::StateAccountNotFound)?;

        let data = &account_info.data;
        // Minimum size check - the smallest valid state is around 6376 bytes
        if data.len() < 4 {
            return Err(VerifierError::InvalidStateData);
        }

        // Parse state: [phase: u8, challenge_sub_phase: u8, sumcheck_sub_phase: u8, log_n: u8, ...]
        // See phased.rs VerificationState struct for layout
        let phase_raw = data[0];
        let phase = match phase_raw {
            0 => VerificationPhase::NotStarted, // Uninitialized
            1 => VerificationPhase::NotStarted, // ChallengesInProgress
            2 => VerificationPhase::ChallengesGenerated,
            3 => VerificationPhase::NotStarted, // SumcheckInProgress
            4 => VerificationPhase::SumcheckComplete,
            5 => VerificationPhase::NotStarted, // MsmInProgress
            6 => VerificationPhase::MsmComplete,
            7 => VerificationPhase::Verified, // Complete
            255 => VerificationPhase::Failed,
            _ => VerificationPhase::NotStarted,
        };
        let log_n = data[3];

        // The verified flag is at the end before final 31-byte padding
        // Use actual data length, not hardcoded SIZE (handles version differences)
        let verified = data.len() >= 32 && data[data.len() - 32] == 1;

        Ok(VerificationState {
            phase,
            log_n,
            verified,
        })
    }

    /// Derive the receipt PDA for a given VK and public inputs
    pub fn derive_receipt_pda(&self, vk_account: &Pubkey, public_inputs: &[u8]) -> (Pubkey, u8) {
        // Hash public inputs using keccak256
        let pi_hash = Keccak256::digest(public_inputs);

        Pubkey::find_program_address(
            &[RECEIPT_SEED, vk_account.as_ref(), &pi_hash],
            &self.config.program_id,
        )
    }

    /// Create a verification receipt after successful verification
    pub fn create_receipt(
        &self,
        payer: &Keypair,
        state_account: &Pubkey,
        proof_account: &Pubkey,
        vk_account: &Pubkey,
        public_inputs: &[u8],
    ) -> Result<Pubkey> {
        let (receipt_pda, _) = self.derive_receipt_pda(vk_account, public_inputs);

        let ix = instructions::create_receipt(
            &self.config.program_id,
            state_account,
            proof_account,
            vk_account,
            &receipt_pda,
            &payer.pubkey(),
        );

        self.send_and_confirm(payer, &[], vec![ix], false)?;
        Ok(receipt_pda)
    }

    /// Get a verification receipt if it exists
    pub fn get_receipt(
        &self,
        vk_account: &Pubkey,
        public_inputs: &[u8],
    ) -> Result<Option<ReceiptInfo>> {
        let (receipt_pda, _) = self.derive_receipt_pda(vk_account, public_inputs);

        let account_info = match self.client.get_account(&receipt_pda) {
            Ok(info) => info,
            Err(_) => return Ok(None),
        };

        if account_info.data.len() < RECEIPT_SIZE {
            return Ok(None);
        }

        if account_info.owner != self.config.program_id {
            return Ok(None);
        }

        // Read verified_slot (offset 0, 8 bytes LE)
        let verified_slot = u64::from_le_bytes(account_info.data[0..8].try_into().unwrap());
        // Read verified_timestamp (offset 8, 8 bytes LE signed)
        let verified_timestamp = i64::from_le_bytes(account_info.data[8..16].try_into().unwrap());

        Ok(Some(ReceiptInfo {
            receipt_pda,
            verified_slot,
            verified_timestamp,
        }))
    }

    /// Close proof and state accounts to recover rent
    pub fn close_accounts(
        &self,
        payer: &Keypair,
        state_account: &Pubkey,
        proof_account: &Pubkey,
    ) -> Result<(u64, Signature)> {
        // Get current balances
        let state_info = self.client.get_account(state_account).ok();
        let proof_info = self.client.get_account(proof_account).ok();
        let recovered = state_info.map(|a| a.lamports).unwrap_or(0)
            + proof_info.map(|a| a.lamports).unwrap_or(0);

        let ix = instructions::close_accounts(
            &self.config.program_id,
            state_account,
            proof_account,
            &payer.pubkey(),
        );

        let sig = self.send_and_confirm(payer, &[], vec![ix], true)?;
        Ok((recovered, sig))
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn get_log_n(&self, state_account: &Pubkey) -> Result<u8> {
        let state = self.get_verification_state(state_account)?;
        Ok(state.log_n)
    }

    fn execute_phase(
        &self,
        payer: &Keypair,
        instruction: solana_sdk::instruction::Instruction,
        skip_preflight: bool,
    ) -> Result<(Signature, u64)> {
        let cu_ix = set_compute_unit_limit(self.config.compute_unit_limit);
        let instructions = vec![cu_ix, instruction];

        let sig = self.send_and_confirm(payer, &[], instructions, skip_preflight)?;

        // Get CUs from transaction - use default encoding config
        let config = solana_rpc_client_api::config::RpcTransactionConfig {
            encoding: Some(solana_rpc_client_api::config::UiTransactionEncoding::Json),
            commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };
        let tx_details = self.client.get_transaction_with_config(&sig, config);

        let cus = tx_details
            .ok()
            .and_then(|t| t.transaction.meta)
            .and_then(|m| m.compute_units_consumed.into())
            .unwrap_or(0);

        Ok((sig, cus))
    }

    fn send_and_confirm(
        &self,
        payer: &Keypair,
        additional_signers: &[&Keypair],
        instructions: Vec<solana_sdk::instruction::Instruction>,
        skip_preflight: bool,
    ) -> Result<Signature> {
        let recent_blockhash = self.client.get_latest_blockhash()?;

        let mut signers: Vec<&Keypair> = vec![payer];
        signers.extend(additional_signers);

        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&payer.pubkey()),
            &signers,
            recent_blockhash,
        );

        let config = solana_client::rpc_config::RpcSendTransactionConfig {
            skip_preflight,
            ..Default::default()
        };

        let sig = self.client.send_transaction_with_config(&tx, config)?;

        // Poll for confirmation - matches test_phased.rs approach
        // 30 attempts × 200ms = 6 second timeout per TX
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(200));
            match self.client.get_signature_status(&sig)? {
                Some(result) => {
                    if let Err(e) = result {
                        return Err(VerifierError::TransactionFailed(e.to_string()));
                    }
                    return Ok(sig);
                }
                None => continue,
            }
        }

        Err(VerifierError::ConfirmationTimeout)
    }

    fn split_into_chunks<'a>(&self, data: &'a [u8]) -> Vec<(usize, &'a [u8])> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let chunk_size = std::cmp::min(self.config.chunk_size, data.len() - offset);
            chunks.push((offset, &data[offset..offset + chunk_size]));
            offset += chunk_size;
        }
        chunks
    }
}
