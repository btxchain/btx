// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_RUN_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_RUN_H

#include <string>

namespace modelnet {

/**
 * Refuse a run because the sandbox is absent.
 * Always returns false and sets SANDBOX_ABSENT.
 * An unknown worker is the same refusal. Nothing is recorded.
 * This does not start a process. launched stays false.
 */
bool SwarmSandboxGateRunRefuse(const std::string& worker, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_RUN_H
