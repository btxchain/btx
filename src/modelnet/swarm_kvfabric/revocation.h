// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_REVOCATION_H
#define BTX_MODELNET_SWARM_KVFABRIC_REVOCATION_H

#include <modelnet/swarm_kvfabric/result.h>

#include <set>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Revoke blocks a later read. A read of a placed page is recorded only for
 * a member that has not been revoked. A refused read is not recorded.
 */
class KvFabricRevocation {
public:
    SwarmKvFabricResult Revoke(const std::string& member);
    SwarmKvFabricResult Read(const std::string& member, const std::string& page, bool page_placed);
    bool revoked(const std::string& member) const;
    bool recorded(const std::string& member, const std::string& page) const;

private:
    std::set<std::string> m_revoked;
    std::set<std::pair<std::string, std::string>> m_reads;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_REVOCATION_H
