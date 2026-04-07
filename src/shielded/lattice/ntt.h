// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_NTT_H
#define BTX_SHIELDED_LATTICE_NTT_H

#include <shielded/lattice/params.h>

#include <array>
#include <cstdint>

namespace shielded::lattice {

/** Forward NTT transform using Dilithium reference implementation. */
void NTT(std::array<int32_t, POLY_N>& coeffs);

/** Inverse NTT transform using Dilithium reference implementation. */
void InverseNTT(std::array<int32_t, POLY_N>& coeffs);

/** Montgomery reduction modulo q. */
[[nodiscard]] int32_t MontgomeryReduce(int64_t value);

/** Fast Barrett-like reduction used by Dilithium. */
[[nodiscard]] int32_t Reduce32(int32_t value);

/** Conditionally adds q to map to non-negative representative. */
[[nodiscard]] int32_t CAddQ(int32_t value);

/** Fully reduced coefficient in canonical [0, q) range. */
[[nodiscard]] int32_t Freeze(int32_t value);

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_NTT_H
