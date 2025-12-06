# Spec: Noir Plonk/KZG Verifier on Solana (BN254, per‑circuit)

## 0. Goals and non‑goals

### Goals

- Implement a **circuit‑specific verifier** for Noir circuits on Solana.
- Target Noir’s **Barretenberg backend** (UltraPlonk/UltraHonk style Plonkish, KZG over BN254).
- Use Solana’s **alt_bn128 (BN254) syscalls** for G1/G2 arithmetic and pairing.
- Build a **single, Solana‑native verification code path**, used:

  - On‑chain (BPF program).
  - In local tests (`solana-program-test`).

- Verify **Noir‑generated proofs** (via Nargo + Barretenberg) against Barretenberg as ground truth.
- Support a **small number of fixed circuits**, each with its own verifier program (or entrypoint), with VK embedded as constants (per‑circuit verifier, like Solidity).

### Non‑goals

- No universal “arbitrary VK from account” verifier in v1 (can be added later).
- No proving; only verification.
- No custom SRS generation; we assume we use the same SRS Barretenberg uses.
- No attempt to support all possible Plonk variants; we target the specific Noir/Barretenberg version you fix.

---

## 1. High‑level overview

We want a pipeline:

1. **Write Noir circuit** → compile with Nargo → prove with Barretenberg.
2. Export:

   - Verification key (`vk.json`).
   - Proof (`proof.json` or binary).
   - Public inputs.

3. **Codegen** a Solana verifier:

   - A Rust module with embedded VK constants.
   - A Solana program entrypoint that:

     - Deserializes proof + public inputs.
     - Calls a generic `verify_plonk_kzg()` function.

4. Test the program using:

   - Barretenberg’s verifier off‑chain as the “oracle”.
   - `solana-program-test` to exercise the actual on‑chain code.

5. Deploy per‑circuit verifier programs to Solana.

Architecturally this is very similar to:

- Barretenberg’s **Solidity verifier generator** (per‑circuit verifier contracts).
- Light Protocol’s **`groth16-solana`** verifier (Groth16 on BN254 using Solana’s alt_bn128 syscalls).

---

## 2. External references (must‑read)

An implementer should **read or at least skim**:

- **Noir docs** – language, Nargo, backends.
- **Barretenberg** repo and docs, in particular:

  - Plonk/UltraPlonk/UltraHonk overview.
  - “Generate a Solidity Verifier” guide (for inspiration on codegen, VK layout).

- **Light Protocol `groth16-solana`**:

  - Uses **BN254 syscalls** and codegen of VK into Rust.

- **Solana SDK** – `solana-program` crate and alt_bn128 module (BN254 syscalls).
- **KZG polynomial commitments** – conceptual explanation.
- Optionally: ZKVerify’s **UltraHonk verifier spec** (Noir+Barretenberg → Substrate verifier).

These are the reference points for protocol details and APIs.

---

## 3. Protocol background (what we’re actually verifying)

### 3.1 Curves and commitments

- Curve: **BN254** (a.k.a. alt_bn128), pairing‑friendly.
- Commitment scheme: **KZG polynomial commitments** over BN254:

  - Prover commits to a polynomial ( f(X) ) by a G1 point ( [C] ).
  - To prove ( f(z) = y ), prover sends an opening proof ( [\pi] ) such that a pairing relation holds.

- Solana exposes BN254 operations via **alt_bn128 syscalls**, e.g., add, scalar mul, pairing.

### 3.2 Plonkish (Barretenberg flavor)

Noir + Barretenberg gives us Plonkish proofs (UltraPlonk / UltraHonk):

- The circuit is encoded as a set of **polynomials over the scalar field**:

  - Wire polynomials: ( W_1, W_2, \dots ) (“columns” of witness values).
  - Selector polynomials: ( Q_L, Q_R, Q_M, Q_O, Q_C, \dots ).
  - Permutation polynomials: ( \sigma_1, \sigma_2, \dots ).
  - Lookup‑related polynomials (for Ultra).

- All constraints are combined into a **single polynomial identity** over a domain ( H ) of size ( n ), with vanishing polynomial ( Z_H(X) = X^n - 1 ).

On prover side, they build a **quotient polynomial** ( T(X) ) that encodes all constraints; on verifier side we only check that:

- Certain constraint equations hold at a randomly chosen point ( \zeta ).
- The stated polynomial evaluations at ( \zeta ) are consistent with KZG commitments.

Barretenberg uses **Fiat–Shamir** (hashing commitments, public inputs, etc.) to derive challenges (e.g., ( \beta, \gamma, \alpha, \zeta, \dots )) and a KZG multi‑opening to reduce many evaluation checks into one pairing.

The verifier:

1. Recomputes Fiat–Shamir challenges from VK, proof and public inputs.
2. Reconstructs constraint expressions at ( \zeta ) using:

   - VK commitments and their evaluations.
   - Proof evaluations (wires, permutation grand product, lookup accumulators).

3. Checks the main Plonkish relation (informally):

[
\text{lhs}(\zeta) = Z_H(\zeta),T(\zeta)
]

with lhs being a linear combination of gate, permutation, lookup, and boundary terms with random coefficients ((\alpha), etc.). 4. Verifies the underlying KZG opening(s) for all claimed evaluations.

Exact formulas must be taken from the target Barretenberg version (or from an existing spec like ZKVerify’s UltraHonk pallet if using UltraHonk).

---

## 4. Artifacts from Noir / Barretenberg

### 4.1 Noir & Barretenberg pipeline

Using Nargo (Noir CLI) with Barretenberg backend:

- Developer writes a Noir circuit (e.g., `main.nr`).
- They run commands like:

  - `nargo prove <circuit>` → generates:

    - proof file
    - verification key

  - Or via Noir integration with Barretenberg / noir-rs, etc.

The implementation should:

- Fix a specific Noir and Barretenberg version and document it.
- Use the **standard VK + proof export format** from Barretenberg as canonical.

### 4.2 Required exported data

For each circuit, we need to export:

1. **Verification Key (VK)** in JSON (or equivalent):

   - Domain info: circuit size ( n ), maybe ( \log_2(n) ), root of unity ( \omega ).
   - Scalar field modulus (or implied).
   - G1 commitments:

     - Selector polynomials ( [Q_L], [Q_R], [Q_M], [Q_O], [Q_C], \dots ).
     - Permutation polynomials ( [\sigma_i] ).
     - Lookup / fixed polynomials (as needed).

   - G2 elements for KZG (e.g., `[h]`, `[h^\tau]` or similar).
   - Public input wiring / encoding info.

2. **Proof** (JSON or binary):

   - G1 commitments to:

     - Wire polynomials ( [W_i] ).
     - Quotient chunks ( [T_0], [T_1], \dots ).
     - Grand product polynomial ( [Z] ).
     - Any lookup‑related polynomials.

   - Scalar evaluations at challenge point(s) ( \zeta, \zeta\omega, \dots ) for:

     - Wires.
     - Z, lookups, etc.

   - KZG opening proof(s) in G1 (often batched into a single element).

3. **Public inputs**:

   - List of field elements `[Fr]` in the order expected by the circuit.

We treat Barretenberg’s own CLI and/or Noir integration as **the source of truth** for:

- Serialization (endianness, limb order).
- Field and group encodings.
- Challenge schedule.

---

## 5. Project layout

Use a Rust workspace with the following packages:

- `plonk-solana-core`

  - `no_std`‑friendly core verification logic (Plonk/KZG, transcript).
  - Depends on `solana-program`’s alt_bn128 module (or thin wrapper) for BN254.

- `plonk-solana-vk-codegen` (binary)

  - CLI that reads `vk.json` (Barretenberg format) and generates:

    - A Rust module with `const` VK values for that circuit.

- `plonk-solana-program-<circuit>`

  - Solana BPF program:

    - Includes core verifier crate.
    - Includes generated VK module for a specific circuit.
    - Exposes Solana entrypoint that verifies proofs for that circuit.

- `tests/` (integration tests)

  - Use `solana-program-test` to:

    - Spin up a local validator.
    - Deploy verifier program.
    - Feed Noir/Barretenberg proofs as instruction data and assert verification.

This structure mirrors `groth16-solana` + Barretenberg’s Solidity verifier patterns.

---

## 6. Core components spec

### 6.1 Field and curve layer

**Goal:** Provide basic BN254 field and group operations via Solana syscalls.

- Use `solana-program`’s `alt_bn128` module or the dedicated `solana-bn254` crate.
- Provide types:

  - `Fr`: scalar field (circuit field).
  - `G1`, `G2`: BN254 groups.

- Provide operations:

  - `G1` add, sub, scalar mul.
  - Multi‑pairing: verify `∏ e(a_i, b_i) == 1` via syscall.

- Provide serialization/deserialization:

  - Inputs/outputs as big‑endian u8 arrays, matching syscall expectations.

Implementation details (coordinate representation, etc.) are flexible, but **must**:

- Match the wire format used by Barretenberg for G1/G2 elements.
- Use the Solana syscalls for all heavy group/pairing operations, not pure Rust.

### 6.2 Transcript and Fiat–Shamir

**Goal:** Reproduce Barretenberg’s exact challenge derivation.

- Implement a `Transcript` object that:

  - Starts from a domain separator for the protocol.
  - Supports:

    - `append_commitment(label, G1/G2)`
    - `append_scalar(label, Fr)`
    - `challenge(label) -> Fr`

- Hash function: follow Barretenberg’s choice for the targeted Plonk variant (e.g., Blake2s, Poseidon, Keccak, etc.); verify via docs or by instrumenting Barretenberg.
- The **order** in which you absorb:

  - VK commitments,
  - public inputs,
  - proof commitments,
  - evaluations,
    must match Barretenberg’s implementation exactly.

**Testing requirement:** For a test circuit, dump all challenges from Barretenberg (via logging or debug mode) and assert your transcript produces identical byte sequences for:

- `beta, gamma, alpha, zeta, ...`

### 6.3 KZG verifier

**Goal:** Verify KZG openings over BN254 using SRS info from VK.

#### Single opening

Given:

- Commitment ( [C] \in G1 )
- Point ( x \in Fr )
- Claimed evaluation ( y \in Fr )
- Proof ( [\pi] \in G1 )
- SRS G2 elements ( [h], [h^\tau] )

Verify pairing equation (schematically):

[
e([C] - y[G], [h]) \stackrel{?}{=} e([\pi], [h^\tau - x h])
]

Exact expression depends on Barretenberg’s KZG encoding; implementers must follow its KZG spec.

#### Batched opening

Barretenberg typically reduces multiple evaluation claims to a single KZG opening using random coefficients from the transcript:

- For claims ( (C_j, x_j, y_j) ), compute:

  - Combined commitment ( C^\* = \sum r_j C_j )
  - Combined evaluation ( y^\* = \sum r_j y_j )

- Verify one opening ( (C^_, x^_, y^_, \pi^_) ) where ( x^\* ) and coefficients are defined by the protocol.

**Spec requirement:** Implement the same batching strategy as the targeted Barretenberg version (consult code/spec).

**Testing requirement:**

- Use small polynomials and commit/open via Barretenberg.
- Confirm your KZG verifier accepts valid openings and rejects tampered ones.

### 6.4 Plonkish verifier core

**Goal:** Implement the Plonk/UltraPlonk/UltraHonk verification logic in a backend‑agnostic way (only depends on field + curve operations).

At a high level, verifier does:

1. **Parse VK and proof** into internal structures:

   - VK: commitments, SRS, metadata.
   - Proof: commitments, evaluations, opening proof(s).
   - Public inputs: field elements.

2. **Reconstruct transcript and challenges**:

   - Absorb VK, public inputs, proof commitments/evals in the correct order.
   - Derive challenges: `beta, gamma, alpha, zeta, ...` as per Barretenberg.

3. **Check basic boundary conditions** (example for simple Plonk):

   - Grand product polynomial ( Z(X) ) constraints at domain endpoints:

     - e.g., ( Z(1) = 1 ), ( Z(\omega^{n-1}) = \prod(...)) or variant.

   - Public inputs correctly injected into wires at specific positions.

4. **Gate constraints at ζ**:

   - For each gate type, define its polynomial relation. Simple Plonk example:

     [
     G(\zeta) =
     Q_L(\zeta) a(\zeta) +
     Q_R(\zeta) b(\zeta) +
     Q_M(\zeta) a(\zeta) b(\zeta) +
     Q_O(\zeta) c(\zeta) +
     Q_C(\zeta)
     ]

   - Ultra/Honk adds custom gates, ecc, etc.; follow Barretenberg’s exact relations.

5. **Permutation argument at ζ**:

   - Use `beta, gamma` to combine wire values and permutation polys into a grand product relation involving ( Z(\zeta) ), ( Z(\zeta\omega) ), and selectors ( \sigma_i(\zeta) ).
   - Formula must match Barretenberg’s implementation of the permutation argument (consult code/spec).

6. **Lookup argument at ζ** (if Ultra / UltraHonk):

   - Implement the specific lookup scheme used (e.g., aggregation of input/table values into accumulators).
   - Copy Barretenberg’s formulas for:

     - Table polynomial.
     - Lookup selectors.
     - Running product / accumulator polynomials.

7. **Combine constraints into quotient relation**:

   - Use challenge `alpha` (and possibly powers of it) to fold:

     - Gate constraints.
     - Permutation constraints.
     - Lookup constraints.
     - Boundary conditions.

   - Ensure that:

     [
     \text{CombinedNumerator}(\zeta)
     = Z_H(\zeta) \cdot T(\zeta)
     ]

     where ( Z_H(X) = X^n - 1 ) and ( T(\zeta) ) is the quotient evaluation from the proof.

8. **Multi‑opening construction**:

   - Collect all polynomial commitments and claimed evaluations that appear in the verification equations (wires, selectors, Z, T, lookup polys).
   - Use Barretenberg’s batching scheme (e.g. additional random challenge `nu`, `mu`, etc.) to combine them into a single KZG opening check.

9. **Call KZG verifier**:

   - Run the batched KZG pairing check using SRS from VK and proof’s opening element(s).
   - If pairing passes and all scalar checks (steps 3–7) pass, the proof is valid.

**Important:**
The **exact formulas** and the **set of polynomials** involved are protocol‑specific; implementers must derive them from:

- The targeted Barretenberg Plonk/UltraPlonk/UltraHonk implementation, or
- A written spec such as ZKVerify’s UltraHonk verifier docs (which explicitly target Noir+Barretenberg proofs).

### 6.5 Circuit‑specific VK embedding

**Goal:** Embed VK into the program as `const` values for a specific circuit (per‑circuit verifier).

- `plonk-solana-vk-codegen` reads `vk.json` exported from Barretenberg and produces:

  ```rust
  pub const DOMAIN_SIZE: u32 = ...;
  pub const ROOT_OF_UNITY: Fr = ...;
  pub const Q_L: G1 = G1 { /* coordinates */ };
  pub const Q_R: G1 = ...;
  // ...
  pub const SIGMA_1: G1 = ...;
  pub const G2_H: G2 = ...;
  pub const G2_H_TAU: G2 = ...;
  ```

- At runtime, the program calls a helper:

  ```rust
  pub fn circuit_vk() -> VerifierKey {
      // materialize VerifierKey from consts
  }
  ```

VK structure should contain:

- Domain parameters.
- KZG SRS info (at least relevant G2 elements; G1 SRS may not be needed in verifier).
- All fixed polynomial commitments (selectors, sigmas, lookup tables).
- Public input layout metadata.

### 6.6 Solana program interface

**Goal:** Provide a simple, deterministic interface to verify a proof for a given circuit.

- Program entrypoint signature:

  ```rust
  pub fn process_instruction(
      program_id: &Pubkey,
      accounts: &[AccountInfo],
      instruction_data: &[u8],
  ) -> ProgramResult
  ```

- Define an instruction format in `instruction_data`, e.g.:

  - `[u8; 1]` opcode (e.g. `0x01 = VerifyProof`).
  - Length‑prefixed public inputs (as Fr).
  - Length‑prefixed proof bytes (as per your proof serialization).

- Entry handler steps:

  1. Parse instruction and decode `public_inputs` and `proof`.
  2. Construct `VerifierKey` from embedded `const` values.
  3. Call core verifier:

     ```rust
     if verify_plonk_kzg(&vk, &proof, &public_inputs) {
         Ok(())
     } else {
         Err(ProgramError::Custom(VERR_INVALID_PROOF))
     }
     ```

- There is **no state** mutated; this is a pure stateless verifier program.

For multiple circuits you can:

- Deploy separate programs, each with its own VK and entrypoint; or
- Have one program with a circuit ID field in the instruction and dispatch to different embedded VKs.

---

## 7. Development & testing strategy

### 7.1 Fixing toolchain versions

- Pin explicit versions of:

  - Noir / Nargo.
  - Barretenberg backend.
  - Solana toolchain (including version with alt_bn128 syscalls).

Record them in the repo (e.g., `README`, `flake.nix`, or Dockerfile).

### 7.2 Test circuits and vectors

For each protocol feature you implement (basic gates, permutation, lookups, etc.):

1. Write a **minimal Noir circuit** that uses that feature.
2. Use Nargo/Barretenberg to:

   - Generate `vk.json`, `proof.json` and public inputs.
   - Verify the proof using Barretenberg’s own verifier to confirm validity.

3. Store these test artifacts in the repo (under `tests/resources/…`).

### 7.3 Unit tests (off‑chain, but still Solana‑compatible)

In `plonk-solana-core` (can use `std` for tests):

- **Field/curve serialization tests**:

  - Round‑trip G1/G2/Fr encoding → decoding via your types.
  - Cross‑check a few known points with Barretenberg exports.

- **KZG tests**:

  - Use Barretenberg to generate commit+open for random polynomials.
  - Feed into your KZG verifier and assert success/failure.

- **Transcript tests**:

  - Dump challenge values `(beta, gamma, alpha, zeta, …)` from Barretenberg for a given VK+proof.
  - Assert your transcript reproduces the same challenges bit‑for‑bit.

### 7.4 Integration tests with `solana-program-test`

For each circuit:

1. Build `plonk-solana-program-<circuit>`.
2. Create a `program-test` integration test:

   - Spin up local validator.
   - Deploy the verifier program.
   - Load `vk.json`, `proof.json`, `public_inputs.json`.
   - Serialize public inputs + proof into instruction data.
   - Invoke the program.

3. Assert:

   - Valid proof → program returns `Ok(())`.
   - Tampered proof (e.g., flip one byte) → `ProgramError::Custom(VERR_INVALID_PROOF)`.

This is effectively what `groth16-solana` does for Groth16 proofs; model the tests on that.

### 7.5 Incremental feature rollout

Implement and test in stages:

1. **Stage 1: KZG only**

   - Ignore Plonk; just exercise KZG verification using dummy polynomials.

2. **Stage 2: Minimal Plonk (no Ultra features)**

   - Circuit: only basic arithmetic gates.
   - Implement:

     - Gate constraints.
     - Permutation argument (for 2–3 wires).
     - Quotient relation.
     - Single evaluation point.

3. **Stage 3: Ultra features**

   - Add lookup argument; test with simple lookup circuit.
   - Add any extra selectors/custom gates used by Noir defaults.

4. **Stage 4: UltraHonk / full Noir backend**

   - Align exactly with the Plonkish variant Noir uses for your chosen version, using Barretenberg and/or ZKVerify UltraHonk spec as reference.

At each stage:

- Add new test circuits and Barretenberg‑verified proofs.
- Keep old tests passing.

---

## 8. Security and correctness considerations

- **VK–proof binding**:

  - Each circuit’s verifier must use the correct VK for that circuit; don’t allow arbitrary VK injection in v1.
  - If you support multiple circuits in one program, ensure the VK is selected only by an explicit circuit ID and never influenced by untrusted data in a way that allows mixing.

- **SRS assumptions**:

  - You trust the SRS (KZG setup). This is inherited from Barretenberg. No attempt is made here to verify SRS correctness.

- **Serialization robustness**:

  - Reject malformed proofs or public inputs (length checks, group validity checks).
  - Avoid panics; surface verification failure as a program error.

- **Constant‑time vs. Solana compute limits**:

  - Use syscalls for expensive operations; avoid naive Rust pairings.
  - Follow patterns and compute budget constraints observed in `groth16-solana` (their verifier fits under ~200k compute units).

---

## 9. Future extensions (out of v1 scope, but worth documenting)

- **Universal verifier**:

  - Load VK from an account instead of embedding it as constants.
  - Allow many user circuits without redeploying programs.

- **Multi‑proof aggregation**:

  - Verify several proofs in one transaction by batching more aggressively at the KZG level.

- **Different commitment schemes**:

  - IPA/Fri‑based commitments if Noir’s backend changes.

- **Better tooling**:

  - GUI/CLI to generate circuits, proofs, and deploy Solana verifiers end‑to‑end.

---

This spec is enough for an implementer (human or AI) to:

- Learn the necessary Noir, Barretenberg, and Solana pieces.
- Set up a project.
- Implement the Plonk/KZG verifier core.
- Embed Noir VKs per circuit.
- Test everything against Barretenberg locally.
- And finally deploy a working, circuit‑specific Noir verifier on Solana.
