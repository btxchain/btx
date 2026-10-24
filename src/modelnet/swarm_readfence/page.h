// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_PAGE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_PAGE_H

#include <string>

namespace modelnet {

/**
 * One placed page and the family it belongs to.
 * bind stores both. An empty page or an empty family is refused and
 * the previous binding stays.
 */
class SwarmReadPage {
public:
    const std::string& id() const { return m_id; }
    const std::string& family() const { return m_family; }
    bool bound() const { return !m_id.empty() && !m_family.empty(); }

    bool bind(const std::string& id, const std::string& family);

private:
    std::string m_id;
    std::string m_family;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_PAGE_H
