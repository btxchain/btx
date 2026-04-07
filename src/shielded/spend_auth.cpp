// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/spend_auth.h>

#include <crypto/sha3.h>
#include <hash.h>
#include <shielded/ringct/matrict.h>
#include <streams.h>

#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace shielded {
namespace {

constexpr std::string_view TAG_SPEND_AUTH_V1{"BTX_Shielded_SpendAuth_V1"};
constexpr std::string_view TAG_SPEND_AUTH_V2{"BTX_Shielded_SpendAuth_V2"};
constexpr std::string_view TAG_SPEND_AUTH_V3{"BTX_Shielded_SpendAuth_V3"};
constexpr std::string_view TAG_SPEND_AUTH_V3_COMBINER{"BTX_Shielded_SpendAuth_V3_Combiner"};

[[nodiscard]] uint256 ComputeSpendAuthHybridDigest(Span<const unsigned char> preimage)
{
    uint256 sha256_digest;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(sha256_digest.begin());

    std::array<unsigned char, SHA3_256::OUTPUT_SIZE> sha3_bytes{};
    SHA3_256().Write(preimage).Finalize(sha3_bytes);

    uint256 sha3_digest;
    std::memcpy(sha3_digest.begin(), sha3_bytes.data(), sha3_bytes.size());

    HashWriter combiner;
    combiner << std::string{TAG_SPEND_AUTH_V3_COMBINER};
    combiner << sha256_digest;
    combiner << sha3_digest;
    return combiner.GetSHA256();
}

template <typename TxType>
uint256 ComputeShieldedSpendAuthSigHashImpl(const TxType& tx,
                                           size_t input_index,
                                           const Consensus::Params* consensus,
                                           int32_t validation_height)
{
    if (!tx.HasShieldedBundle()) return uint256{};
    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    if (input_index >= bundle.shielded_inputs.size()) return uint256{};

    // Reuse the shared stripped-tx hash to avoid duplicating the
    // proof/ring_positions stripping logic (previously R3-015).
    const uint256 stripped_hash = consensus != nullptr
        ? ringct::ComputeMatRiCTBindingHash(tx, *consensus, validation_height)
        : ringct::ComputeMatRiCTBindingHash(tx);

    const bool use_hybrid_hash =
        consensus != nullptr && consensus->IsShieldedMatRiCTDisabled(validation_height);

    std::vector<unsigned char> preimage;
    VectorWriter writer{preimage, 0};
    if (use_hybrid_hash) {
        writer << std::string{TAG_SPEND_AUTH_V3};
        writer << consensus->hashGenesisBlock;
        writer << static_cast<uint32_t>(consensus->nShieldedMatRiCTDisableHeight);
    } else if (consensus != nullptr) {
        writer << std::string{TAG_SPEND_AUTH_V2};
        writer << consensus->hashGenesisBlock;
        writer << static_cast<uint32_t>(consensus->nShieldedMatRiCTDisableHeight);
    } else {
        writer << std::string{TAG_SPEND_AUTH_V1};
    }
    writer << stripped_hash;
    writer << static_cast<uint32_t>(input_index);
    writer << bundle.shielded_inputs[input_index].nullifier;

    if (use_hybrid_hash) {
        return ComputeSpendAuthHybridDigest(preimage);
    }

    HashWriter hw;
    hw.write(MakeByteSpan(preimage));
    return hw.GetSHA256();
}

} // namespace

uint256 ComputeShieldedSpendAuthSigHash(const CTransaction& tx, size_t input_index)
{
    return ComputeShieldedSpendAuthSigHashImpl(tx, input_index, nullptr, std::numeric_limits<int32_t>::max());
}

uint256 ComputeShieldedSpendAuthSigHash(const CMutableTransaction& tx, size_t input_index)
{
    return ComputeShieldedSpendAuthSigHashImpl(tx, input_index, nullptr, std::numeric_limits<int32_t>::max());
}

uint256 ComputeShieldedSpendAuthSigHash(const CTransaction& tx,
                                        size_t input_index,
                                        const Consensus::Params& consensus,
                                        int32_t validation_height)
{
    return ComputeShieldedSpendAuthSigHashImpl(tx, input_index, &consensus, validation_height);
}

uint256 ComputeShieldedSpendAuthSigHash(const CMutableTransaction& tx,
                                        size_t input_index,
                                        const Consensus::Params& consensus,
                                        int32_t validation_height)
{
    return ComputeShieldedSpendAuthSigHashImpl(tx, input_index, &consensus, validation_height);
}

} // namespace shielded
