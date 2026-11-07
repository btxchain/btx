// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_BLANK_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_BLANK_H

#include <string>

namespace modelnet {

/**
 * True when text is empty.
 * The check does not trim. An empty worker, prefix, capability, or host id
 * is blank. A non-empty opaque string is not blank.
 */
bool SwarmSandboxGateBlank(const std::string& text);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_BLANK_H
