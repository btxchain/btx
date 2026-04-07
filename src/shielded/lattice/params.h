// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_LATTICE_PARAMS_H
#define BTX_SHIELDED_LATTICE_PARAMS_H

#include <cstddef>
#include <cstdint>

namespace shielded::lattice {

// Ring parameters (match Dilithium's NTT domain parameters).
static constexpr size_t POLY_N{256};
static constexpr int32_t POLY_Q{8380417};
static constexpr int32_t QINV{58728449};
static constexpr int32_t MONT{4193792};

// MatRiCT+ ring-size policy.
static constexpr size_t MIN_RING_SIZE{8};
static constexpr size_t DEFAULT_RING_SIZE{8};
static constexpr size_t MAX_RING_SIZE{32};
static constexpr size_t RING_SIZE{DEFAULT_RING_SIZE};
static constexpr size_t MODULE_RANK{4};
// 51 bits safely covers MAX_MONEY (2.1e15 sat) while reducing range-proof footprint.
static constexpr size_t VALUE_BITS{51};
static constexpr int32_t BETA_CHALLENGE{60};
static constexpr int32_t GAMMA_RESPONSE{1 << 17};
static constexpr int32_t SECRET_SMALL_ETA{2};

[[nodiscard]] constexpr bool IsSupportedRingSize(size_t ring_size)
{
    return ring_size >= MIN_RING_SIZE && ring_size <= MAX_RING_SIZE;
}

} // namespace shielded::lattice

#endif // BTX_SHIELDED_LATTICE_PARAMS_H
