// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_BDLOP_H
#define BTX_SHIELDED_SMILE2_BDLOP_H

#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/ntt.h>

#include <array>
#include <cstdint>
#include <vector>

namespace smile2 {

/**
 * BDLOP Commitment Scheme (Baum-Damgård-Lyubashevsky-Oechsner-Peikert)
 *
 * Public parameters generated from a seed:
 *   B_0 ∈ R_q^{(α+β) × (α+β+n_msg)}    (binding matrix for t_0)
 *   b_i ∈ R_q^{α+β+n_msg}               (message encoding vectors, i=1..n_msg)
 *
 * Commit(m_1, ..., m_n; r):
 *   r ∈ R_q^{α+β+n_msg}                 (short randomness, ternary ±1)
 *   t_0 = B_0 · r mod q                  (binding part, α+β polynomials)
 *   t_i = ⟨b_i, r⟩ + m_i mod q          (message part, 1 polynomial each)
 *
 * Commitment = (t_0, t_1, ..., t_n)
 */

struct BDLOPCommitmentKey {
    size_t n_msg;  // number of message slots

    // Total randomness dimension: α+β+n_msg
    size_t rand_dim() const { return BDLOP_RAND_DIM_BASE + n_msg; }

    // B_0: (α+β) rows × rand_dim columns
    // Each entry is a polynomial in R_q
    std::vector<std::vector<SmilePoly>> B0;  // B0[row][col]
    std::vector<std::vector<NttForm>> B0_ntt; // cached NTT form of B0[row][col]

    // b_i: n_msg vectors, each of length rand_dim
    std::vector<std::vector<SmilePoly>> b;   // b[i][col], i=0..n_msg-1
    std::vector<std::vector<NttForm>> b_ntt; // cached NTT form of b[i][col]

    // Generate commitment key deterministically from a seed
    static BDLOPCommitmentKey Generate(const std::array<uint8_t, 32>& seed, size_t n_msg);

    // Rebuild cached NTT forms after any deliberate in-place key mutation.
    void RebuildNttCache();
};

struct BDLOPCommitment {
    SmilePolyVec t0;                    // binding part: α+β polynomials
    std::vector<SmilePoly> t_msg;       // message parts: n_msg polynomials
};

struct BDLOPOpening {
    SmilePolyVec r;                     // randomness vector: α+β+n_msg polynomials
};

// Commit to n_msg messages under a single randomness vector r
// r is sampled as ternary {-1, 0, 1}
BDLOPCommitment Commit(const BDLOPCommitmentKey& ck,
                        const std::vector<SmilePoly>& messages,
                        const SmilePolyVec& r);

// Sample short ternary randomness for commitment
SmilePolyVec SampleTernary(size_t dim, uint64_t seed);
SmilePolyVec SampleTernaryStrong(size_t dim, uint64_t seed);
SmilePolyVec SampleTernaryStrong(size_t dim, const std::array<uint8_t, 32>& seed);

// Verify commitment opening: check t_0 = B_0·r and t_i = ⟨b_i, r⟩ + m_i
bool VerifyOpening(const BDLOPCommitmentKey& ck,
                   const BDLOPCommitment& com,
                   const std::vector<SmilePoly>& messages,
                   const SmilePolyVec& r);

// Weak opening verification:
// Given z = y + c·r, check B_0·z = w_0 + c·t_0
// and ⟨b_i, z⟩ - c·t_i = ⟨b_i, y⟩ - c·m_i (= f_i)
bool VerifyWeakOpening(const BDLOPCommitmentKey& ck,
                       const BDLOPCommitment& com,
                       const SmilePolyVec& z,
                       const SmilePolyVec& w0,
                       const SmilePoly& c_chal,
                       const std::vector<SmilePoly>& f);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_BDLOP_H
