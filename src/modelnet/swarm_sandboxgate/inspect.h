// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_INSPECT_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_INSPECT_H

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/journal.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/** True when worker has at least one stored grant. Expiry does not erase it. */
bool SwarmSandboxGateGranted(const SwarmSandboxGateBook& book, const std::string& worker);

/** Number of actions recorded by successful Act calls. */
std::size_t SwarmSandboxGateActionCount(const SwarmSandboxGateJournal& journal);

/**
 * True when worker has a grant with network set and now_ms < until_ms.
 * This does not open a socket and does not require a host id.
 */
bool SwarmSandboxGateNetworkPermitted(const SwarmSandboxGateBook& book,
                                      const std::string& worker,
                                      int64_t now_ms);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_INSPECT_H
