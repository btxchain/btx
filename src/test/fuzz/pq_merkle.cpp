// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pqm.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>

#include <algorithm>
#include <vector>

namespace {

uint256 ConsumeUint256(FuzzedDataProvider& fuzzed_data_provider)
{
    auto bytes = fuzzed_data_provider.ConsumeBytes<unsigned char>(32);
    if (bytes.size() < 32) bytes.resize(32, 0);
    uint256 value;
    std::copy(bytes.begin(), bytes.end(), value.begin());
    return value;
}

} // namespace

FUZZ_TARGET(pq_merkle)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const uint8_t leaf_version = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
    const std::vector<unsigned char> script = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096));
    const uint256 leaf_hash = ComputeP2MRLeafHash(leaf_version, script);

    std::vector<uint256> leaves;
    const size_t leaf_count = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 16);
    leaves.reserve(leaf_count);
    for (size_t i = 0; i < leaf_count; ++i) {
        leaves.push_back(ConsumeUint256(fuzzed_data_provider));
    }
    (void)ComputeP2MRMerkleRoot(leaves);

    const std::vector<unsigned char> control = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1 + 32 * 8));
    const std::vector<unsigned char> program = fuzzed_data_provider.ConsumeBytes<unsigned char>(
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 32));
    (void)VerifyP2MRCommitment(control, program, leaf_hash);
}
