// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_BLANK_H
#define BITCOIN_MODELNET_SWARM_CAPACT_BLANK_H

#include <string>

namespace modelnet {

/**
 * An empty capability name cannot be granted or acted.
 * Names are compared exactly: case-sensitive, and not trimmed.
 */
bool SwarmCapActBlank(const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_BLANK_H
