# BTX Shielded Pool Threat Model

## 1. Assets

The shielded pool protects three categories of information:

| Asset | Description | Protection mechanism |
|-------|-------------|---------------------|
| **Transaction values** | Input/output amounts (up to 51-bit, covering MAX_MONEY) | Lattice Pedersen commitments + range proofs |
| **Sender identity** | Which UTXO is actually being spent | Ring signature over the configured anonymity set (default 8, supported 8..32) |
| **Receiver identity** | Destination of funds | ML-KEM encrypted notes (IND-CCA2) |
| **Transaction graph** | Links between spends and outputs | Key images (nullifiers) are unlinkable to ring members |
| **Note plaintext** | Value, blinding factor, memo | ChaCha20-Poly1305 AEAD under ML-KEM shared secret |

## 2. Adversary Model

### 2.1 Passive network observer

Can see all P2P traffic including serialized `MatRiCTProof` bundles, encrypted notes, and nullifiers. **Goal**: deanonymize senders, learn values, or link transactions.

- Sees commitments, ring members, key images, and `EncryptedNote` ciphertexts.
- Cannot determine the real signer within a ring (MLWE anonymity).
- Cannot determine values from commitments (hiding property).
- Cannot decrypt notes without the recipient's ML-KEM secret key.
- **Residual risk**: traffic timing and volume analysis can narrow sender candidates.

### 2.2 Malicious miner

Controls block inclusion and ordering. **Goal**: censor, reorder, or forge shielded transactions.

- Can censor specific transactions but cannot forge proofs (MSIS unforgeability).
- Can observe which nullifiers appear but cannot link them to ring members.
- Cannot inflate supply because `VerifyBalanceProof` enforces `sum(inputs) = sum(outputs) + fee`.
- Cannot double-spend on behalf of a user because key image derivation requires the spending key.

### 2.3 Compromised peer

Has access to a node's mempool and can inject crafted messages. **Goal**: crash nodes, extract timing data, or mount resource exhaustion.

- Deserialization bounds (`MAX_MATRICT_INPUTS`, `MAX_MATRICT_OUTPUTS`, `MAX_RING_SIGNATURE_INPUTS`, `MAX_AEAD_CIPHERTEXT_SIZE`) limit memory amplification.
- Proof verification is stateless and thread-safe (`VerifyMatRiCTProof`, `VerifyRingSignature`) -- a peer cannot cause state corruption.
- **Residual risk**: verification CPU cost enables DoS if rate-limiting is insufficient.

### 2.4 Quantum adversary

Has access to a cryptographically relevant quantum computer. **Goal**: break confidentiality or forge signatures.

- Lattice commitments, ring signatures, and proofs are based on MLWE/MSIS over module lattices with parameters matching Dilithium/CRYSTALS (POLY_Q = 8380417, MODULE_RANK = 4). These problems are believed quantum-hard.
- Note encryption uses ML-KEM (FIPS 203), which provides IND-CCA2 security against quantum adversaries.
- **Residual risk**: SHA-256 (used for Fiat-Shamir transcripts, nullifier derivation, commitment hashing) offers only ~128-bit quantum security via Grover's algorithm. This is considered sufficient but is not post-quantum in the same formal sense as the lattice primitives.

## 3. Security Properties

### 3.1 Unforgeability -- MSIS hardness

A valid `RingSignature` requires knowledge of a short vector solving the Module-SIS relation for at least one ring member. Without the spending key, an adversary must solve MSIS with parameters (n=256, k=4, q=8380417, beta=60), which is conjectured hard for both classical and quantum computers.

**Reduction**: Forging a ring signature implies finding a vector **z** with `||z||_inf <= GAMMA_RESPONSE` (131072) satisfying the verification equation, which is an MSIS instance.

### 3.2 Anonymity -- MLWE hardness

The ring signature is constructed so that all `RING_SIZE` (default 8) per-member challenge/response pairs are computationally indistinguishable from each other. Distinguishing the real signer reduces to solving MLWE with rank 4 over the Dilithium ring.

**Mechanism**: `RingInputProof` contains per-member `responses` and `challenges` vectors. The Fiat-Shamir transcript binds all members symmetrically.

### 3.3 Confidentiality -- range proof hiding

Values are hidden inside lattice Pedersen commitments: `C = A * blind + g * value (mod q)`. The `RangeProof` decomposes the value into `VALUE_BITS` (51) bit commitments, each proven to be 0 or 1 via an OR-proof (`RangeBitProof`), and a Schnorr-style relation proof binds the decomposition to the original commitment.

**Hiding**: The commitment scheme is computationally hiding under MLWE -- recovering `value` from `C` requires solving MLWE.

### 3.4 Balance -- balance proof soundness

`BalanceProof` is a Schnorr-style proof that `sum(input_commitments) - sum(output_commitments) - Commit(fee, 0) = Commit(0, delta_blind)`. Soundness means an adversary cannot create a valid proof when inputs do not equal outputs plus fee, unless they can solve MSIS.

**Binding**: The commitment scheme is computationally binding under MSIS -- finding two different openings for the same commitment requires solving MSIS.

### 3.5 Non-repudiation / double-spend prevention -- nullifier binding

Each spend publishes a deterministic `Nullifier` derived from the key image (`ComputeNullifierFromKeyImage`). The `NullifierSet` (LevelDB-backed with in-memory cache) enforces uniqueness: `AnyExist()` rejects transactions reusing a nullifier. The binding between key image and nullifier is verified by `VerifyRingSignatureNullifierBinding`.

**Determinism**: `DeriveInputNullifier(spending_key, ring_member_commitment)` is deterministic, so the same note always produces the same nullifier regardless of which ring it appears in.

## 4. Cryptographic Assumptions

| Assumption | Used by | Consequence if broken |
|------------|---------|----------------------|
| **MLWE** (Module Learning With Errors) | Commitment hiding, ring signature anonymity, note encryption (ML-KEM) | Values and sender identity revealed |
| **MSIS** (Module Short Integer Solution) | Commitment binding, ring signature unforgeability, balance proof soundness | Supply inflation, unauthorized spending |
| **SHA-256 collision resistance** | Fiat-Shamir transcripts (`challenge_seed`, `transcript_hash`), nullifier derivation, `CommitmentHash`, `RingSignatureMessageHash` | Proof malleability, nullifier collisions |
| **SHA-256 preimage resistance** | Nullifier binding, view tag computation | Nullifier forgery |
| **ML-KEM IND-CCA2** (FIPS 203) | `NoteEncryption::Encrypt` / `TryDecrypt` | Note plaintext (value, blinding, memo) disclosed to passive observer |
| **ChaCha20-Poly1305 AEAD** | Symmetric encryption layer in note encryption | Note plaintext disclosed if shared secret is known |
| **HKDF-SHA256 PRF** | Key derivation from ML-KEM shared secret to AEAD key | AEAD key predictable |

## 5. Parameter Justification

### POLY_Q = 8380417

The Dilithium/CRYSTALS prime, chosen because:
- `q ≡ 1 (mod 2n)` where `n = 256`, enabling efficient NTT.
- 23-bit prime fits in `int32_t` with room for lazy reduction.
- Supports Montgomery multiplication with `QINV = 58728449` and `MONT = 4193792`.
- Provides a security/efficiency sweet spot validated by NIST PQC standardization.

### MODULE_RANK = 4

Matches Dilithium-III / ML-DSA-65 security level (~192-bit classical, ~128-bit quantum). Rank 4 over degree-256 polynomials yields lattice dimension 1024, which is well above known attack thresholds for both primal and dual lattice attacks.

### Default RING_SIZE = 8 (supported 8..32)

The launch default ring of 8 members provides a 1-in-8 anonymity set per input,
while the current wire / consensus surface already supports larger configured
rings up to 32 without a transaction-family change. This is a pragmatic
trade-off:
- Proof size scales linearly with ring size (each `RingInputProof` contains `RING_SIZE` responses and challenges).
- Verification cost scales linearly.
- Defaulting to 8 reduces launch-surface proof size and improves effective TPS.
- Operators can progressively raise the configured ring size within the
  supported 8..32 range as privacy requirements grow and throughput budgets
  allow.

### BETA_CHALLENGE = 60

The infinity-norm bound on challenge polynomials in the Fiat-Shamir transform. This value:
- Ensures the challenge space is large enough for 128-bit soundness: the number of ternary polynomials with coefficients in `[-60, 60]` over degree 256 far exceeds `2^128`.
- Keeps the product `BETA_CHALLENGE * GAMMA_RESPONSE` small relative to `q/2` to maintain correctness of rejection sampling.

### GAMMA_RESPONSE = 131072 (2^17)

The infinity-norm bound on response vectors in the signature/proof. This value:
- Sets the rejection sampling threshold: responses with `||z||_inf > GAMMA_RESPONSE` are rejected and re-sampled.
- `GAMMA_RESPONSE >> BETA_CHALLENGE * s` (where `s` is the secret key norm) ensures the rejection sampling distribution is statistically close to uniform, preventing secret key leakage.
- `GAMMA_RESPONSE = 2^17` is a power of two for efficient comparison and matches Dilithium's `gamma1` parameter at security level III.

### VALUE_BITS = 51

- Covers `MAX_MONEY` (2.1 * 10^15 satoshis, which requires ~51 bits).
- Each bit adds one `RangeBitProof` (two challenges + two response vectors), so minimizing bits reduces proof size.
- 51 bits vs. 64 bits saves ~20% on range proof size with no loss of expressiveness.

## 6. Known Limitations

### 6.1 Ring-size policy is a launch default, not a fixed wire-format ceiling

The launch default anonymity set per transaction input is 8, with the current
consensus / wire surface already supporting larger configured rings up to 32.
Repeated spending patterns, timing correlation, or poor decoy selection can
reduce effective anonymity below the nominal configured ring size. An adversary
observing many transactions over time may use intersection attacks to narrow
the true sender.

**Mitigation**: Protocol-level decoy selection should use a recent-biased distribution matching the actual spend-age profile.

### 6.2 Timing side-channels in rejection sampling

The `CreateRingSignature` and `CreateRangeProof` functions use rejection sampling (responses exceeding `GAMMA_RESPONSE` are discarded and re-sampled). The number of rejections leaks information about the secret key norm through timing.

**Mitigation**: Proof creation should run in constant-time with respect to externally observable behavior. The `rng_entropy` parameter in `CreateRingSignature` and `CreateMatRiCTProof` supports deterministic testing but production use must ensure high-quality randomness.

### 6.3 Hash functions are not post-quantum in the strongest sense

SHA-256 provides ~128-bit security against Grover's algorithm. While this is generally considered adequate, the lattice primitives target higher post-quantum security margins. A future hash function migration (e.g., to a 384-bit hash) could close this gap.

### 6.4 View tag reduces trial-decryption cost but leaks 8 bits

The `view_tag` field (1 byte, computed from KEM ciphertext and public key) allows recipients to quickly reject non-matching notes. However, it leaks 8 bits of information about the recipient identity to an observer who can test candidate public keys.

### 6.5 Nullifier cache bounds

The `NullifierSet` in-memory cache is capped at `NULLIFIER_CACHE_MAX_ENTRIES` (2,000,000). Beyond this threshold, lookups fall through to LevelDB, increasing I/O. Under sustained high shielded transaction volume, this could become a performance bottleneck.

## 7. Attack Surface

### 7.1 P2P deserialization

All proof structures implement bounds-checked `Unserialize` methods:

| Structure | Bound enforced |
|-----------|---------------|
| `MatRiCTProof` | `MAX_MATRICT_INPUTS`, `MAX_MATRICT_OUTPUTS`, cross-field size consistency |
| `RingSignature` | `MAX_RING_SIGNATURE_INPUTS`, key image / offset / input proof count match |
| `RingInputProof` | Response count <= supported max ring size, challenge count == response count |
| `RangeProof` | Exactly `VALUE_BITS` bit commitments and bit proofs |
| `EncryptedNote` | `MAX_AEAD_CIPHERTEXT_SIZE` (2048 bytes) |

**Residual risk**: Deserialization allocates `std::vector` memory proportional to declared sizes before validation. An attacker declaring `MAX_RING_SIGNATURE_INPUTS` (128) inputs, each with `MAX_RING_SIZE` (32) polynomial vectors of rank 4, could trigger significant allocation before proof verification fails. Rate-limiting and per-peer memory budgets are essential.

### 7.2 Proof verification DoS

`VerifyMatRiCTProof` is stateless and thread-safe but computationally expensive:
- Ring signature verification: O(inputs * ring_size * MODULE_RANK) polynomial multiplications.
- Range proof verification: O(outputs * VALUE_BITS) OR-proof checks.
- Balance proof verification: O(inputs + outputs) commitment arithmetic.

A transaction with `MAX_MATRICT_INPUTS` inputs and `MAX_MATRICT_OUTPUTS` outputs at the supported max ring size triggers worst-case verification cost.

**Mitigation**: Consensus-layer limits on shielded spends/outputs per transaction (`MAX_SHIELDED_SPENDS_PER_TX`, `MAX_SHIELDED_OUTPUTS_PER_TX`). Mempool policy should apply stricter limits and prioritize by fee rate.

### 7.3 Ring selection heuristics

The security of ring signatures depends critically on how decoy ring members are selected. Attacks include:

- **Age heuristic**: If decoys are chosen uniformly but real spends skew recent, intersection over time reveals the true input.
- **Dusty output exclusion**: If implementations skip low-value outputs as decoys, the effective ring shrinks.
- **Output reuse in rings**: If the same output appears in many rings but is never spent, it becomes a known decoy.
- **Chain reaction**: Once one ring member is identified as spent (its nullifier appears), it can be excluded from other rings retroactively.

**Mitigation**: Standardize decoy selection in consensus or policy rules. Use a gamma distribution matching empirical spend-age curves. Require minimum output age before ring eligibility.

### 7.4 Nullifier set integrity

The `NullifierSet` is the sole mechanism preventing double-spends of shielded notes. Corruption of the LevelDB backing store or a bug in `Insert`/`Remove` during reorgs could allow a nullifier to be removed, re-enabling a spent note.

**Mitigation**: The `NullifierSet` uses a shared/exclusive lock (`std::shared_mutex`) for thread safety. Database flushes use fsync barriers. Reorg handling must be carefully tested -- `Remove()` on disconnect must exactly reverse `Insert()` on connect.

### 7.5 Key management

The `spending_key` (passed as `Span<const unsigned char>`) is the root secret for all shielded operations. Compromise of this key allows:
- Spending all associated notes.
- Deriving all nullifiers (revealing spend history).
- Creating valid ring signatures for any ring containing the user's commitments.

The ML-KEM secret key (`mlkem::SecretKey`) controls note decryption. Compromise reveals all received note plaintexts.

**Mitigation**: Keys should be stored in memory using `secure_allocator` and wiped on destruction. Hardware wallet integration should be considered for high-value use cases.
