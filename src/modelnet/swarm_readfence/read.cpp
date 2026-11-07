// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/read.h>

#include <modelnet/swarm_readfence/codes.h>

namespace modelnet {

bool SwarmReadRead::Apply(const SwarmReadRoster& roster,
                          const SwarmReadBook& book,
                          SwarmReadLedger& ledger,
                          const std::string& member,
                          const std::string& page,
                          std::string& err) const
{
    if (member.empty()) {
        err = kSwarmReadMember;
        return false;
    }
    if (page.empty()) {
        err = kSwarmReadPage;
        return false;
    }
    if (roster.revoked(member)) {
        err = kSwarmReadNotRead;
        return false;
    }
    if (!book.placed(page)) {
        err = kSwarmReadPage;
        return false;
    }
    if (!ledger.Record(member, page)) {
        err = kSwarmReadPage;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
