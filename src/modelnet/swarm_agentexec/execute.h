// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_EXECUTE_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_EXECUTE_H

#include <modelnet/swarm_agentexec/book.h>
#include <modelnet/swarm_agentexec/journal.h>
#include <modelnet/swarm_agentexec/result.h>

#include <string>

namespace modelnet {

/**
 * Decide whether a tool may run, then hash inside this process.
 * Empty tool is TOOL.
 * Tool net is NET_DENIED. connected() is not set. ran() is not set by this call.
 * A path that does not begin with a stored prefix is DENIED.
 * A path that begins with private/ is PRIVATE_DATA after a prefix matched,
 * and nothing is stored, even when that prefix was allowed.
 * An empty payload is PAYLOAD and does not set ran().
 * Any other tool name is TOOL.
 * sha256 with an allowed path and a non-empty payload computes the digest.
 * A second sha256 of the same path and payload is REPLAY and keeps the first digest.
 */
bool SwarmAgentExecExecute(const SwarmAgentExecBook& book,
                           SwarmAgentExecJournal& journal,
                           SwarmAgentExecResult& result,
                           const std::string& tool,
                           const std::string& path,
                           const std::string& payload,
                           std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_EXECUTE_H
