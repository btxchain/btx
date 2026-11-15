// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_ALLOW_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_ALLOW_H

#include <modelnet/swarm_agentexec/book.h>

#include <string>

namespace modelnet {

/**
 * Empty prefix is PATH and stores nothing.
 * A non-empty prefix is stored.
 * A second identical prefix is REPLAY and keeps the first.
 * A different prefix is stored beside the first.
 */
bool SwarmAgentExecAllow(SwarmAgentExecBook& book, const std::string& prefix, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_ALLOW_H
