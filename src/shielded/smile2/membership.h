// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_MEMBERSHIP_H
#define BTX_SHIELDED_SMILE2_MEMBERSHIP_H

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <support/cleanse.h>

#include <array>
#include <cstdint>
#include <vector>

namespace smile2 {

inline constexpr int64_t MEMBERSHIP_SIGMA_MASK = 384;
inline constexpr int64_t MEMBERSHIP_SIGMA_KEY = 2048;
inline constexpr size_t MEMBERSHIP_Z_COEFF_BITS = 13;
inline constexpr size_t MEMBERSHIP_Z0_COEFF_BITS = 15;

/**
 * SMILE recursive membership proof wrapper for the current BTX direct-spend
 * prototype.
 *
 * The intended target is Section 4 / Figures 8-9 of the SMILE paper. The
 * local working mirrors used for this rewrite live at
 * `doc/research/smile-2021-564-working-mirror.md` and
 * `doc/research/smile-2021-564.txt`.
 *
 * The in-tree proof object still models the prototype recursion instead of the
 * paper's verifier object. In particular, the current implementation:
 *
 * - now uses the paper-shaped first-round transcript and challenge surfaces
 *   on both the large-ring and single-round paths: Eq. (39) binds
 *   `w = B_0 * y` and `m` into `c_0`, Eq. (21) compression is performed as
 *   the full `gamma^T * P` row product, and the post-compression state is
 *   committed through the public `x` relation without a public-key
 *   unique-match scan;
 * - keeps a vestigial `w0_vals` field only so the verifier can reject legacy
 *   payloads that still try to route through the old effective-row object; and
 * - still does not expose the exact final public verifier object needed to
 *   encode the paper's Figure 9 equations on every path.
 *
 * The remaining launch blocker is a proof-object / prover / verifier rewrite
 * that aligns those challenge dimensions and x-relations with the paper.
 */

// Public key structure: A ∈ R_q^{k×ℓ}, pk = A·s
struct SmilePublicKey {
    std::vector<std::vector<SmilePoly>> A;  // A[row][col], k rows × ℓ cols
    SmilePolyVec pk;                         // pk = A·s, k polynomials
};

// Secret key: s ∈ R_q^ℓ (short)
struct SmileSecretKey {
    SmilePolyVec s;  // ℓ polynomials

    ~SmileSecretKey()
    {
        for (auto& poly : s) {
            poly.SecureClear();
        }
    }
};

// Key pair generation from seed
struct SmileKeyPair {
    SmilePublicKey pub;
    SmileSecretKey sec;

    // Generate a key pair: A from seed, s sampled ternary
    static SmileKeyPair Generate(const std::array<uint8_t, 32>& seed, uint64_t key_seed);
    static SmileKeyPair Generate(const std::array<uint8_t, 32>& seed,
                                 const std::array<uint8_t, 32>& key_seed);
};

// The membership proof
struct SmileMembershipProof {
    // BDLOP commitment (single commitment covering all message slots)
    BDLOPCommitment commitment;

    // Polynomial h = g + y_1 + ... + y_m (first d/l=4 coefficients must be zero)
    SmilePoly h;

    // Masked opening z = y + c·r (randomness masking)
    SmilePolyVec z;

    // Masked key opening z_0 = y_0 + c_0·s (secret key masking)
    SmilePolyVec z0;

    // Garbage verification value omega
    SmilePoly omega;

    // Legacy compatibility field. New proofs leave this empty and the
    // verifier rejects any non-empty payload.
    SmilePolyVec w0_vals;

    // Fiat-Shamir seeds for challenge derivation
    std::array<uint8_t, 32> seed_c0;  // derives c_0
    std::array<uint8_t, 32> seed_c;   // derives c (final challenge)

    // Serialized size measurement
    size_t SerializedSize() const;
};

// Compute P_{j+1} from P_j and challenge alpha_j (Equation 21)
// P_j has kl rows, l^{m-j} cols. Challenge alpha is l scalars.
// P_{j+1} has kl rows, l^{m-j-1} cols.
// P_{j+1}[row][col_out] = Σ_{d=0}^{l-1} alpha[d] · P_j[row][d * stride + col_out]
// where stride = l^{m-j-1}.
std::vector<std::vector<NttSlot>> ComputeNextP(
    const std::vector<std::vector<NttSlot>>& P_j,
    const std::array<int64_t, NUM_NTT_SLOTS>& alpha,
    size_t cols_next);

// Matrix-vector product in NTT domain: P · v where v is scalar one-hot
// P has rows of NttSlots, v ∈ Z_q^n
// Result: vector of NttSlots (one per row)
std::vector<NttSlot> MatVecProduct(
    const std::vector<std::vector<NttSlot>>& P,
    const std::vector<int64_t>& v);

// Prove set membership
// anon_set: vector of public keys (the anonymity set)
// secret_index: which key the prover owns
// sk: the prover's secret key
// rng_seed: deterministic seed for randomness generation
SmileMembershipProof ProveMembership(
    const std::vector<SmilePublicKey>& anon_set,
    size_t secret_index,
    const SmileSecretKey& sk,
    uint64_t rng_seed,
    bool bind_anonset_context = false);

[[nodiscard]] size_t GetMembershipRejectionRetryBudget();
[[nodiscard]] size_t GetMembershipTimingPaddingAttemptLimit();

// Verify set membership proof
bool VerifyMembership(
    const std::vector<SmilePublicKey>& anon_set,
    const SmileMembershipProof& proof,
    bool bind_anonset_context = false);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_MEMBERSHIP_H
