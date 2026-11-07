// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CAPACT_GRANTS_H
#define BITCOIN_MODELNET_SWARM_CAPACT_GRANTS_H

#include <modelnet/swarm_capact/record.h>

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Capabilities stored by a successful Grant, keyed by name.
 * store refuses an empty name and a name already present. A refused
 * store leaves the first grant in place. There is no erase, and storing
 * a grant does not record an action.
 */
class SwarmCapActGrants {
public:
    bool contains(const std::string& name) const;
    std::size_t size() const;

    /**
     * Store name as a grant.
     * Refuses an unusable record and a duplicate name. On refusal the
     * set is unchanged.
     */
    bool store(const std::string& name);

private:
    std::map<std::string, SwarmCapActGrantRecord> m_names;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CAPACT_GRANTS_H
