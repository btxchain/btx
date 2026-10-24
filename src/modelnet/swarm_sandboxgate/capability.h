// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_CAPABILITY_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_CAPABILITY_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * True when the capability vector is empty.
 * An empty vector is not stored. Entries are compared later as opaque bytes.
 */
bool SwarmSandboxGateCapabilitiesEmpty(const std::vector<std::string>& capabilities);

/**
 * True when the capability name is empty.
 * An empty name is not an action. The check does not trim.
 */
bool SwarmSandboxGateCapabilityBlank(const std::string& capability);

/**
 * True when capability is a non-empty entry of capabilities.
 * Comparison is bytewise. An empty capability is not listed.
 */
bool SwarmSandboxGateCapabilityListed(const std::vector<std::string>& capabilities,
                                      const std::string& capability);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_CAPABILITY_H
