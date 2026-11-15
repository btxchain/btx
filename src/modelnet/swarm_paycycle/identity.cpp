// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paycycle/identity.h>

#include <hash.h>
#include <span.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

void AppendField(std::vector<unsigned char>& buf, const std::string& field, bool separate)
{
    if (separate) {
        buf.push_back(0);
    }
    for (const char ch : field) {
        buf.push_back(static_cast<unsigned char>(ch));
    }
}

} // namespace

bool SwarmPayCycleAcceptObjective(const std::string& objective)
{
    return objective == "model-improvement" || objective == "specialist-training" || objective == "inference-service" ||
           objective == "evaluation" || objective == "application";
}

std::string SwarmPayCyclePoolId(const std::string& chain, const std::string& lineage, const std::string& nonce,
                                const std::string& objective, const std::string& policy)
{
    // Hash() is HASH256 (double SHA-256). HexStr prints that digest in forward byte order.
    std::vector<unsigned char> joined;
    joined.reserve(chain.size() + lineage.size() + nonce.size() + objective.size() + policy.size() + 4);
    AppendField(joined, chain, false);
    AppendField(joined, lineage, true);
    AppendField(joined, nonce, true);
    AppendField(joined, objective, true);
    AppendField(joined, policy, true);
    const uint256 digest = Hash(joined);
    const Span<const uint8_t> bytes(reinterpret_cast<const uint8_t*>(digest.data()), digest.size());
    return HexStr(bytes);
}

} // namespace modelnet
