// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_REPLAY_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_REPLAY_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <string>

namespace modelnet {

/**
 * True when worker and path_prefix are already stored.
 * An empty worker or prefix is not a replay. The stored capabilities,
 * network flag, and until_ms are not compared and are not replaced.
 */
bool SwarmSandboxGateIsReplay(const SwarmSandboxGateBook& book,
                              const std::string& worker,
                              const std::string& path_prefix);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_REPLAY_H
