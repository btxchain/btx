// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_MEMBERS_H
#define BITCOIN_MODELNET_SWARM_REMEDY_MEMBERS_H

#include <set>
#include <string>

namespace modelnet {

/**
 * Member revoke and read.
 * An empty member is MEMBER and is not stored.
 * A second revoke of the same member is REPLAY.
 * Read of a revoked member is NOT_READ and is not recorded.
 * A read that already happened stays recorded.
 */
class SwarmRemedyMembers {
public:
    bool Revoke(const std::string& member, std::string& err);
    bool Read(const std::string& member, std::string& err);
    bool revoked(const std::string& member) const;
    bool recorded(const std::string& member) const;

private:
    std::set<std::string> m_revoked;
    std::set<std::string> m_reads;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_MEMBERS_H
