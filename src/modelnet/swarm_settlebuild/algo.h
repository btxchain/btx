// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_ALGO_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_ALGO_H

#include <pqkey.h>

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/** PQAlgorithm used for claim and refund leaves. */
PQAlgorithm SwarmSettleBuildAlgorithm();

/**
 * Public-key size required by SwarmSettleBuildAlgorithm().
 * Zero means the enum size and the published size disagree, so every key is refused.
 */
std::size_t SwarmSettleBuildPubkeySize();

/**
 * True when pubkey is non-empty and its size equals SwarmSettleBuildPubkeySize().
 * A refusal sets err to KEY. This function does not build a script.
 */
bool SwarmSettleBuildPubkeyAccepted(const std::vector<unsigned char>& pubkey, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_ALGO_H
