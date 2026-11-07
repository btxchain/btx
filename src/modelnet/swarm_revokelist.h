// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REVOKELIST_H
#define BTX_MODELNET_SWARM_REVOKELIST_H

#include <cstdint>
#include <set>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Local membership revoke list. Revoke records a member. Read records that
 * a member read a page. A revoked member reads no later page: the read is
 * refused and is not recorded. Bytes moved stay 0.
 */
class SwarmRevokeList {
public:
    bool Revoke(const std::string& member, std::string& err);
    bool Read(const std::string& member, const std::string& page, std::string& err);
    bool revoked(const std::string& member) const;
    int64_t bytes_moved() const;

private:
    std::set<std::string> m_revoked;
    std::set<std::pair<std::string, std::string>> m_reads;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REVOKELIST_H
