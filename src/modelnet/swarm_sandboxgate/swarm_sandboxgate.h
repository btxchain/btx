// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_H

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/journal.h>
#include <modelnet/swarm_sandboxgate/quiet.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process sandbox policy.
 * This plane decides whether a worker action would be allowed.
 * It does not exec a helper, spawn a process, open a socket, or read
 * the filesystem. Paths and host ids are opaque strings.
 *
 * Grant stores worker, path_prefix, capabilities, network, and until_ms.
 * Empty worker is WORKER and stores nothing. Empty path_prefix is PATH
 * and stores nothing. until_ms below 0 is TIMEOUT and stores nothing.
 * An empty capabilities vector is CAPABILITY and stores nothing.
 * A second grant of the same worker and the same path_prefix is REPLAY
 * and keeps the first capabilities, network flag, and until_ms.
 * A worker may hold more than one path prefix.
 *
 * Act records an action when a live grant's prefix is a strict bytewise
 * prefix of path and that grant lists capability.
 * An unknown worker is NOT_GRANTED. now_ms >= until_ms on every matching
 * grant is EXPIRED and the action is not recorded. A path with no stored
 * prefix is DENIED. A path that begins with "private/" is PRIVATE_DATA
 * even when that prefix was granted, and nothing is recorded.
 * An empty capability is CAPABILITY. A capability missing from every live
 * match is NOT_ACTED and nothing is recorded.
 *
 * Net is a policy permit. An empty host_id is NET. An unknown worker is
 * NOT_GRANTED. now_ms >= until_ms is EXPIRED. A worker with no network
 * grant is NET_DENIED. A live grant with network set returns true.
 * connected() stays false.
 *
 * Run always returns false with SANDBOX_ABSENT. An unknown worker is
 * still SANDBOX_ABSENT. launched() stays false.
 *
 * launched(), connected(), and gpu() stay false. bytes_moved() stays 0.
 * automatic_spend() stays "0". There is no method that sets launched()
 * or connected() true.
 */
class SwarmSandboxGate {
public:
    bool Grant(const std::string& worker,
               const std::string& path_prefix,
               const std::vector<std::string>& capabilities,
               bool network,
               int64_t until_ms,
               std::string& err);
    bool Act(const std::string& worker,
             const std::string& path,
             const std::string& capability,
             int64_t now_ms,
             std::string& err);
    bool Net(const std::string& worker, const std::string& host_id, int64_t now_ms, std::string& err);
    bool Run(const std::string& worker, std::string& err);

    bool granted(const std::string& worker) const;
    std::size_t action_count() const;
    bool network_permitted(const std::string& worker, int64_t now_ms) const;
    bool launched() const;
    bool connected() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;

private:
    SwarmSandboxGateBook m_book;
    SwarmSandboxGateJournal m_journal;
    SwarmSandboxGateQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_H
