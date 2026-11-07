// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_IDENTITY_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_IDENTITY_H

#include <string>

namespace modelnet {

/**
 * True for model-improvement, specialist-training, inference-service,
 * evaluation, and application. Any other string is refused.
 */
bool SwarmPayCycleAcceptObjective(const std::string& objective);

/**
 * Hex HASH256 of chain, lineage, nonce, objective, and policy.
 * Fields are joined by one 0 byte. A different policy is a different id.
 */
std::string SwarmPayCyclePoolId(const std::string& chain, const std::string& lineage, const std::string& nonce,
                                const std::string& objective, const std::string& policy);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_IDENTITY_H
