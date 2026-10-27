// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_BLANK_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_BLANK_H

#include <string>

namespace modelnet {

/**
 * True when value is empty.
 * The check does not trim. A session, model id, engine name, or prompt
 * of only spaces is not blank.
 */
bool SwarmTokenGateBlank(const std::string& value);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_BLANK_H
