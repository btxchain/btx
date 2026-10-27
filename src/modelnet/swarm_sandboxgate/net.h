// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Policy permit for a network flag.
 * On success err is cleared and the function returns true.
 * connected stays false. host_id is an opaque string and is not stored.
 * This does not open a socket.
 */
bool SwarmSandboxGateNetPermit(const SwarmSandboxGateBook& book,
                               const std::string& worker,
                               const std::string& host_id,
                               int64_t now_ms,
                               std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_NET_H
