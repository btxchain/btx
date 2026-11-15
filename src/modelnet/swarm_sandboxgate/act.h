// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_H

#include <modelnet/swarm_sandboxgate/book.h>
#include <modelnet/swarm_sandboxgate/journal.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Record an action when a live matching grant lists capability and the path
 * is not private. On success err is cleared and the journal grows by one.
 * On failure nothing is recorded.
 * launched stays false. This does not exec a helper.
 */
bool SwarmSandboxGateActApply(const SwarmSandboxGateBook& book,
                              SwarmSandboxGateJournal& journal,
                              const std::string& worker,
                              const std::string& path,
                              const std::string& capability,
                              int64_t now_ms,
                              std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_H
