// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_ACTIONS_H
#define BITCOIN_MODELNET_SWARM_CAPACT_ACTIONS_H

#include <modelnet/swarm_capact/entry.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Actions recorded by a successful Act, keyed by capability name.
 * store refuses an empty name and a name already recorded. A refused
 * store does not add a second record. There is no erase. Recording an
 * action does not launch a process.
 */
class SwarmCapActActions {
public:
    bool contains(const std::string& name) const;
    std::size_t size() const;

    /**
     * Record one action for name.
     * Refuses an unusable entry and a name already recorded. On refusal
     * the log is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmCapActActionEntry> m_names;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_ACTIONS_H
