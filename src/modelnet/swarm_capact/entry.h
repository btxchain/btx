// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_ENTRY_H
#define BITCOIN_MODELNET_SWARM_CAPACT_ENTRY_H

#include <string>

namespace modelnet {

/**
 * One recorded action.
 * The name is the capability the action ran under. Recording it does
 * not launch a process, move bytes, use a GPU, or spend.
 */
struct SwarmCapActActionEntry {
    std::string name;
};

SwarmCapActActionEntry SwarmCapActMakeAction(const std::string& name);

/** The name must be non-empty. */
bool SwarmCapActActionUsable(const SwarmCapActActionEntry& entry);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_ENTRY_H
