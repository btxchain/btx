// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PQ_PQ_KEYDERIVATION_H
#define BITCOIN_PQ_PQ_KEYDERIVATION_H

#include <pqkey.h>
#include <span.h>

#include <array>
#include <optional>
#include <vector>

namespace pq {

/** Derive a deterministic 32-byte seed for PQ key generation from a wallet master seed. */
std::array<unsigned char, 32> DerivePQSeedFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

/** Derive a deterministic PQ key using path semantics m/87h/coin_typeh/accounth/change/index. */
std::optional<CPQKey> DerivePQKeyFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

} // namespace pq

#endif // BITCOIN_PQ_PQ_KEYDERIVATION_H
