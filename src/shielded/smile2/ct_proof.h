// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_CT_PROOF_H
#define BTX_SHIELDED_SMILE2_CT_PROOF_H

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <support/cleanse.h>

#include <array>
#include <cstdint>
#include <optional>
#include <uint256.h>
#include <vector>

namespace smile2 {

/**
 * SMILE CT Proof (Appendix E, Figures 12-17 of SMILE paper)
 *
 * Combines:
 * - Amortized membership proofs for m inputs (sharing single z vector)
 * - Balance proof (Σ a_in = Σ a_out via carry polynomial)
 * - Serial number proof (sn_i = ⟨b_1, s_i⟩)
 * - Range proof (amounts in base-4 via NTT slots)
 *
 * All under a SINGLE BDLOP commitment and SINGLE masked opening z.
 */

// Input coin: public key + coin commitment from the anonymity set
struct CTInput {
    size_t secret_index;             // index in anonymity set
    SmileSecretKey sk;               // secret key for this input
    // Coin opening material for the full Appendix E statement.
    // The live reset-chain DIRECT_SMILE verifier uses this in the batched
    // coin-opening proof that authenticates the selected public coin against
    // the Figure 17-style public statement. Remaining work on the
    // account-registry branch is about registry activation, not completion of
    // the base DIRECT_SMILE launch relation.
    SmilePolyVec coin_r;
    int64_t amount;                  // secret amount

    ~CTInput()
    {
        for (auto& poly : coin_r) {
            poly.SecureClear();
        }
        memory_cleanse(&amount, sizeof(amount));
    }
};

// Output coin: new coin to create
struct CTOutput {
    int64_t amount;                  // secret amount
    SmilePolyVec coin_r;             // deterministic or wallet-supplied opening

    ~CTOutput()
    {
        for (auto& poly : coin_r) {
            poly.SecureClear();
        }
        memory_cleanse(&amount, sizeof(amount));
    }
};

// Public data for a CT transaction
struct CTPublicAccount {
    uint256 note_commitment;
    SmilePublicKey public_key;
    BDLOPCommitment public_coin;
    uint256 account_leaf_commitment;

    [[nodiscard]] bool IsValid() const;
};

struct CTPublicData {
    // Anonymity set (shared across all inputs)
    std::vector<SmilePublicKey> anon_set;

    // Public input coin commitments for each shared ring.
    // The live reset-chain DIRECT_SMILE verifier authenticates these through
    // the batched coin-opening checks. The public statement itself carries
    // first-class coin commitments rather than extracted placeholder
    // polynomials.
    std::vector<std::vector<BDLOPCommitment>> coin_rings;

    // Canonical public-account tuples for each input ring member. When
    // present, each tuple binds the note commitment, public key, and public
    // coin for the same hidden ring position. The full Figure 17 rewrite uses
    // these tuples as the public statement surface instead of the current
    // split anon_set / coin_rings view.
    std::vector<std::vector<CTPublicAccount>> account_rings;
};

/**
 * Monomial-tuned rejection-sampling log-acceptance helper for the current CT
 * prover.
 *
 * The launch CT path still uses a monomial Fiat-Shamir challenge plus the
 * small response-width parameters encoded on wire today. A blind port of the
 * membership proof's generic Figure 10 `ln(M)` / `Rej1` rule breaks basic 1x1
 * and 2x2 CT proving under those live parameters, so the CT helper remains
 * intentionally distinct until the proof relation and response encoding are
 * retuned together.
 */
[[nodiscard]] double ComputeCtRejectionLogAccept(
    const SmilePolyVec& z,
    const SmilePolyVec& cv,
    int64_t sigma);

/**
 * Inverse of the monomial Fiat-Shamir challenge used on the current CT path.
 * Exposed for regression coverage of the k=0 case.
 */
[[nodiscard]] SmilePoly InvertMonomialChallenge(const SmilePoly& challenge);

struct SmileCoinOpeningProof {
    // Masked opening z_coin = y_coin + c * sum_i(challenge_i * r_i)
    SmilePolyVec z;

    // Digest of the pre-challenge opening surface. The reset-chain optimized
    // wire format no longer serializes the raw `w0` rows or `f` polynomial;
    // the verifier reconstructs them after challenge recovery and checks this
    // digest instead.
    std::array<uint8_t, 32> binding_digest{};

    // Optional in-memory cache of the pre-challenge B0 * y_coin rows.
    // These are not serialized on the hard-fork wire format.
    SmilePolyVec w0;

    // Optional in-memory cache of the pre-challenge message-link polynomial.
    // This is not serialized on the hard-fork wire format.
    SmilePoly f;
};

struct SmileInputTupleProof {
    // First-round hidden opening for the selected input coin randomness.
    // This is carried under c0 so the verifier can construct the selected
    // account-tuple x1 rows directly from proof state instead of only from a
    // recovered public ring index.
    SmilePolyVec z_coin;

    // First-round hidden opening for the selected input amount polynomial.
    SmilePoly z_amount;

    // First-round hidden opening for the selected consumed account-leaf
    // commitment row. This binds the hidden spender index to the public
    // registry-leaf ring carried in the Figure 17 tuple-account statement.
    SmilePoly z_leaf;
};

// The full CT proof
struct SmileCTProof {
    static constexpr uint8_t WIRE_VERSION_LEGACY{1};
    static constexpr uint8_t WIRE_VERSION_M4_HARDENED{2};

    // Legacy proofs are versionless on the wire. Post-61000 hardened proofs
    // carry an explicit wire header and set this to WIRE_VERSION_M4_HARDENED.
    uint8_t wire_version{WIRE_VERSION_LEGACY};

    // Output coin commitments (minted in protocol)
    std::vector<BDLOPCommitment> output_coins;

    // Auxiliary BDLOP commitment t' (single commitment for ALL proof components)
    BDLOPCommitment aux_commitment;

    // Masked opening z = y' + c·r' (amortized across all inputs)
    SmilePolyVec z;

    // Masked key openings z0_i = y0_i + c0·s_i (per input, bimodal)
    std::vector<SmilePolyVec> z0;

    // First-round hidden tuple-opening state for the selected input public
    // account / public coin witness. This is the genesis-reset proof-format
    // expansion that moves the selected public coin/account relation into the
    // proof object itself instead of reconstructing it only from the legacy
    // key-only `A*z_0 - w_0 = c_0*pk_j` shortcut.
    std::vector<SmileInputTupleProof> input_tuples;

    // Pre-c0 aggregated first-round tuple-opening accumulator weighted by
    // transcript-derived input compression challenges. This hard-fork
    // format replaces one exact tuple-opening polynomial per input with a
    // single verifier-checkable aggregate commitment.
    SmilePoly tuple_opening_acc;

    // Batched masked opening for the real input coin commitments selected by
    // the membership proof plus the minted public output coin commitments.
    // The reset-chain hard-fork codec carries one combined opening response
    // for both surfaces and authenticates the hidden input portion through
    // the tuple-account relation instead of recovering a public ring index.
    SmileCoinOpeningProof coin_opening;

    // Serial numbers (revealed publicly for double-spend detection)
    std::vector<SmilePoly> serial_numbers;

    // Post-challenge residues for auxiliary BDLOP message slots.
    //
    // On the reset-chain live CT surface, the large W0/X/G/Psi tail is no
    // longer serialized as near-uniform commitment rows. The verifier
    // reconstructs those omitted commitment rows from z and these residues
    // after challenge recovery.
    std::vector<SmilePoly> aux_residues;

    // Transcript-binding digest for the live round-1 selector/input/output
    // amount commitment surface. The exact selector and amount t_msg rows are
    // no longer serialized on the hard-fork wire; the verifier recovers them
    // from z plus aux_residues after c and checks this digest before using
    // the recovered rows.
    std::array<uint8_t, 32> round1_aux_binding_digest{};

    // Optional in-memory cache of the exact gamma-compressed first-round W0
    // commitment surface. This is not serialized on the hard-fork wire.
    std::vector<SmilePoly> w0_commitment_accs;

    // Gamma-compressed post-challenge W0 residues for each input.
    // The verifier checks these directly from z and the compressed W0
    // commitments instead of reconstructing six exact omitted W0 residues
    // per input.
    std::vector<SmilePoly> w0_residue_accs;

    // Aggregate transcript-binding digests for the omitted live-m1 aux
    // commitment tail. The pre-h2 root binds the compressed W0 commitment
    // accumulators, compressed X slots, and public garbage slot together.
    // The post-h2 root binds the final Psi/framework surface.
    std::array<uint8_t, 32> pre_h2_binding_digest{};
    std::array<uint8_t, 32> post_h2_binding_digest{};

    // Weak-opening accumulator over the auxiliary BDLOP commitment.
    // This is the CT analogue of the membership proof's omega binding: it
    // compresses the masked-opening residues derived from z and aux_commitment
    // into one verifier-checkable polynomial. This is cached in memory but not
    // serialized on the hard-fork wire; the verifier recomputes it directly.
    SmilePoly omega;

    // Figure 17 / framework accumulator for the hidden tuple-account
    // one-out-of-many relation on the live direct-spend path. This is
    // separate from `omega`, which remains the weak-opening accumulator for
    // the auxiliary BDLOP commitment. This is cached in memory but not
    // serialized on the hard-fork wire; the transcript binds its digest.
    SmilePoly framework_omega;

    // Optional in-memory cache of the public garbage polynomial g0 for the
    // launch-surface Figure 17-style framework relation. The hard-fork wire
    // no longer serializes this exact polynomial; the verifier recovers it
    // from the committed G slot and checks the transcript via the round-1 and
    // pre-h2 aggregate binding digests.
    SmilePoly g0;

    // Framework proof polynomial h2 (first d/l=4 coefficients must be 0)
    SmilePoly h2;

    // Fiat-Shamir seeds
    std::array<uint8_t, 32> fs_seed;
    std::array<uint8_t, 32> seed_c0;
    std::array<uint8_t, 32> seed_c;

    // Proof binding hash: H(transcript || z) computed after masked opening.
    // Binds z to the full Fiat-Shamir transcript so that tampering with z,
    // aux_commitment t_msg, or any other proof component is detectable.
    std::array<uint8_t, 32> seed_z;

    // Serialized size measurement
    size_t SerializedSize() const;
};

// Encode a non-negative amount into the canonical SMILE amount polynomial.
// The value is represented as 32 base-4 digits placed in the constant
// coefficient of each NTT slot so the verifier's slot-wise range equations can
// reason about the amount directly.
std::optional<SmilePoly> EncodeAmountToSmileAmountPoly(int64_t amount);

// Decode a canonical SMILE amount polynomial back into an integer amount.
std::optional<int64_t> DecodeAmountFromSmileAmountPoly(const SmilePoly& amount_poly);

// Check whether a polynomial is in the canonical SMILE amount encoding.
bool IsCanonicalSmileAmountPoly(const SmilePoly& amount_poly);

// Prove a confidential transaction
// inputs: secret input coins
// outputs: output amounts
// pub: public anonymity set and coin rings
// rng_seed: deterministic seed for randomness
std::optional<SmileCTProof> TryProveCT(
    const std::vector<CTInput>& inputs,
    const std::vector<CTOutput>& outputs,
    const CTPublicData& pub,
    uint64_t rng_seed,
    int64_t public_fee = 0,
    bool bind_anonset_context = false);

// Legacy wrapper used by existing tests and helper call sites that still
// treat failure as an empty/default proof object.
SmileCTProof ProveCT(
    const std::vector<CTInput>& inputs,
    const std::vector<CTOutput>& outputs,
    const CTPublicData& pub,
    uint64_t rng_seed,
    int64_t public_fee = 0,
    bool bind_anonset_context = false);

[[nodiscard]] size_t GetCtRejectionRetryBudget();
[[nodiscard]] size_t GetCtTimingPaddingAttemptLimit();

// Verify a confidential transaction proof
bool VerifyCT(
    const SmileCTProof& proof,
    size_t num_inputs,
    size_t num_outputs,
    const CTPublicData& pub,
    int64_t public_fee = 0,
    bool bind_anonset_context = false);

// Compute serial number: sn = ⟨b_1, s⟩ (deterministic from key)
SmilePoly ComputeSerialNumber(
    const BDLOPCommitmentKey& ck,
    const SmileSecretKey& sk);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_CT_PROOF_H
