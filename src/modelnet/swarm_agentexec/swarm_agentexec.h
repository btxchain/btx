// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_H

#include <modelnet/swarm_agentexec/book.h>
#include <modelnet/swarm_agentexec/journal.h>
#include <modelnet/swarm_agentexec/quiet.h>
#include <modelnet/swarm_agentexec/result.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process tool executor.
 * Allow stores a path prefix. Execute runs a tool in this process.
 * The sha256 tool computes HexStr(Hash(payload)) and stores that hex.
 * ran() becomes true only after that digest is stored.
 *
 * launched() stays false because no child process exists.
 * connected() stays false. gpu() stays false. broadcast() stays false.
 * atoms_moved() stays 0. automatic_spend() stays "0".
 * This executor does not spawn, fork, exec, or start another daemon.
 *
 * Allow: an empty prefix is PATH and stores nothing. A non-empty prefix is
 * stored. A second identical prefix is REPLAY and keeps the first.
 *
 * Execute: an empty tool is TOOL. Tool net is NET_DENIED, does not connect,
 * and does not set ran(). A path that does not begin with a stored prefix is
 * DENIED. A path that begins with the bytes private/ is PRIVATE_DATA and
 * stores nothing, even when that prefix was allowed. An empty payload is
 * PAYLOAD and does not set ran(). Any other tool name is TOOL. Tool sha256
 * with an allowed path and a non-empty payload stores the digest, sets ran()
 * true, and returns true. A second sha256 of the same path and payload is
 * REPLAY and keeps the first digest.
 */
class SwarmAgentExec {
public:
    bool Allow(const std::string& prefix, std::string& err);
    bool Execute(const std::string& tool, const std::string& path, const std::string& payload, std::string& err);

    bool ran() const;
    std::string result() const;
    bool launched() const;
    bool connected() const;
    bool gpu() const;
    bool broadcast() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;

private:
    SwarmAgentExecBook m_book;
    SwarmAgentExecJournal m_journal;
    SwarmAgentExecResult m_result;
    SwarmAgentExecQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_H
