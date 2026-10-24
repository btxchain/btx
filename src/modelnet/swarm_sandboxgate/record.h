// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_RECORD_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_RECORD_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One stored grant.
 * worker and path_prefix are opaque strings. capabilities are opaque names.
 * network is a policy flag. until_ms is the first stored deadline.
 * A grant does not launch a process or open a socket.
 */
struct SwarmSandboxGateGrant {
    std::string worker;
    std::string path_prefix;
    std::vector<std::string> capabilities;
    bool network{false};
    int64_t until_ms{0};
};

/**
 * One recorded action.
 * Recorded only after Act allows the path and capability.
 * A private path is never a recorded action.
 */
struct SwarmSandboxGateAction {
    std::string worker;
    std::string path;
    std::string capability;
    int64_t now_ms{0};
};

SwarmSandboxGateGrant SwarmSandboxGateMakeGrant(const std::string& worker,
                                                const std::string& path_prefix,
                                                const std::vector<std::string>& capabilities,
                                                bool network,
                                                int64_t until_ms);

SwarmSandboxGateAction SwarmSandboxGateMakeAction(const std::string& worker,
                                                  const std::string& path,
                                                  const std::string& capability,
                                                  int64_t now_ms);

/** Non-empty worker, non-empty prefix, non-empty capabilities, until_ms >= 0. */
bool SwarmSandboxGateGrantUsable(const SwarmSandboxGateGrant& grant);

/** Non-empty worker, path, and capability. A private path is not usable. */
bool SwarmSandboxGateActionUsable(const SwarmSandboxGateAction& action);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_RECORD_H
