// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_NTT_H
#define BTX_SHIELDED_SMILE2_NTT_H

#include <shielded/smile2/poly.h>

namespace smile2 {

// Forward NTT: decompose polynomial into 32 degree-4 slots
// p̂_j = p mod (X^4 - ζ^(2j+1))  for j = 0..31
NttForm NttForward(const SmilePoly& p);

// Inverse NTT: reconstruct polynomial from 32 degree-4 slots via CRT
SmilePoly NttInverse(const NttForm& ntt);

// Multiply two polynomials via NTT: a*b = INTT(NTT(a) ⊙ NTT(b))
SmilePoly NttMul(const SmilePoly& a, const SmilePoly& b);

// Slot inner product: ⟨v, w⟩ where v, w are NttForm vectors
// Returns Σ_{j=0}^{l-1} v_j · w_j  (each product in its own slot ring)
// The result is an NttForm where slot j = v_j * w_j
NttForm SlotPointwiseMul(const NttForm& a, const NttForm& b);

// Tensor product of one-hot vectors: v1 ⊗ v2 ⊗ ... ⊗ vm
// Input: m vectors of length l=32, each one-hot
// Output: vector of length l^m with exactly one 1
std::vector<int64_t> TensorProduct(const std::vector<std::array<int64_t, NUM_NTT_SLOTS>>& vectors);

// Decompose index into one-hot vectors for tensor product
// index ∈ [0, l^m), returns m one-hot vectors of length l
std::vector<std::array<int64_t, NUM_NTT_SLOTS>> DecomposeIndex(size_t index, size_t m);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_NTT_H
