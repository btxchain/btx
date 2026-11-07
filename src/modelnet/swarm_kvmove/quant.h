// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVMOVE_QUANT_H
#define BITCOIN_MODELNET_SWARM_KVMOVE_QUANT_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * How a put would sit in the family and the KV cache.
 * Reject stores nothing.
 * Family is "4bit": in the family, not in KV, body dropped.
 * Kv is "full" with a non-empty body.
 */
enum class SwarmKvMoveQuant : int {
    Reject = 0,
    Family = 1,
    Kv = 2,
};

/**
 * Classify a quantization string.
 * "4bit" is family-only. The body is ignored.
 * "full" is KV only when body is non-empty.
 * Every other string, including "full" with an empty body, is Reject.
 */
SwarmKvMoveQuant SwarmKvMoveClassifyQuant(const std::string& quantization, const std::vector<unsigned char>& body);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVMOVE_QUANT_H
