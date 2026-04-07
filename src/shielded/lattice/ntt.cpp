// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/lattice/ntt.h>

extern "C" {
void pqcrystals_dilithium2_ref_ntt(int32_t a[256]);
void pqcrystals_dilithium2_ref_invntt_tomont(int32_t a[256]);
int32_t pqcrystals_dilithium2_ref_montgomery_reduce(int64_t a);
int32_t pqcrystals_dilithium2_ref_reduce32(int32_t a);
int32_t pqcrystals_dilithium2_ref_caddq(int32_t a);
int32_t pqcrystals_dilithium2_ref_freeze(int32_t a);
}

namespace shielded::lattice {

void NTT(std::array<int32_t, POLY_N>& coeffs)
{
    pqcrystals_dilithium2_ref_ntt(coeffs.data());
}

void InverseNTT(std::array<int32_t, POLY_N>& coeffs)
{
    pqcrystals_dilithium2_ref_invntt_tomont(coeffs.data());
}

int32_t MontgomeryReduce(int64_t value)
{
    return pqcrystals_dilithium2_ref_montgomery_reduce(value);
}

int32_t Reduce32(int32_t value)
{
    return pqcrystals_dilithium2_ref_reduce32(value);
}

int32_t CAddQ(int32_t value)
{
    return pqcrystals_dilithium2_ref_caddq(value);
}

int32_t Freeze(int32_t value)
{
    return pqcrystals_dilithium2_ref_freeze(value);
}

} // namespace shielded::lattice
