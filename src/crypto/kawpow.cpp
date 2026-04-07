// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/kawpow.h>

#include <crypto/ethash/helpers.hpp>
#include <crypto/ethash/include/ethash/ethash.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <hash.h>
#include <primitives/block.h>

namespace {
struct CKAWPOWInput {
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nHeight;

    SERIALIZE_METHODS(CKAWPOWInput, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nHeight);
    }
};
} // namespace

namespace kawpow {
uint256 GetHeaderHash(const CBlockHeader& block, uint32_t block_height)
{
    const CKAWPOWInput input{
        block.nVersion,
        block.hashPrevBlock,
        block.hashMerkleRoot,
        block.nTime,
        block.nBits,
        block_height,
    };
    return (HashWriter{} << input).GetHash();
}

std::optional<Result> Hash(const CBlockHeader& block, uint32_t block_height)
{
    const int epoch_number{ethash::get_epoch_number(static_cast<int>(block_height))};
    const auto* const context{ethash_get_global_epoch_context(epoch_number)};
    if (context == nullptr) return std::nullopt;

    const auto header_hash{to_hash256(GetHeaderHash(block, block_height).GetHex())};
    const auto result{progpow::hash(*context, static_cast<int>(block_height), header_hash, block.nNonce64)};
    const auto mix_hash{uint256::FromHex(to_hex(result.mix_hash))};
    const auto final_hash{uint256::FromHex(to_hex(result.final_hash))};
    if (!mix_hash || !final_hash) return std::nullopt;

    return Result{*mix_hash, *final_hash};
}

uint256 HashWithMix(const CBlockHeader& block, uint32_t block_height)
{
    const auto header_hash{to_hash256(GetHeaderHash(block, block_height).GetHex())};
    const auto final_hash{progpow::hash_no_verify(
        static_cast<int>(block_height),
        header_hash,
        to_hash256(block.mix_hash.GetHex()),
        block.nNonce64)};

    const auto final_hash_uint256{uint256::FromHex(to_hex(final_hash))};
    return final_hash_uint256.value_or(uint256{});
}
} // namespace kawpow
