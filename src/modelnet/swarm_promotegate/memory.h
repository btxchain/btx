// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_MEMORY_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_MEMORY_H

#include <string>

namespace modelnet {

/**
 * One remembered previous id.
 * remember replaces that id. clear drops it.
 * An empty id is not stored, so a missing memory stays missing.
 * Rollback consumes the memory once.
 */
class SwarmPromoteMemory {
public:
    bool held() const { return !m_previous.empty(); }
    const std::string& previous() const { return m_previous; }

    void remember(const std::string& id);
    void clear();

private:
    std::string m_previous;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_MEMORY_H
