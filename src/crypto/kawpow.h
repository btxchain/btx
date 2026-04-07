// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_KAWPOW_H
#define BITCOIN_CRYPTO_KAWPOW_H

#include <uint256.h>

#include <cstdint>
#include <optional>

class CBlockHeader;

namespace kawpow {
struct Result {
    uint256 mix_hash;
    uint256 final_hash;
};

uint256 GetHeaderHash(const CBlockHeader& block, uint32_t block_height);
std::optional<Result> Hash(const CBlockHeader& block, uint32_t block_height);
uint256 HashWithMix(const CBlockHeader& block, uint32_t block_height);
} // namespace kawpow

#endif // BITCOIN_CRYPTO_KAWPOW_H
