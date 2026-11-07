// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_READ_H
#define BITCOIN_MODELNET_SWARM_READFENCE_READ_H

#include <modelnet/swarm_readfence/book.h>
#include <modelnet/swarm_readfence/ledger.h>
#include <modelnet/swarm_readfence/roster.h>

#include <string>

namespace modelnet {

/**
 * Records a read of a placed page.
 * An empty member is MEMBER. An empty page is PAGE.
 * A revoked member is NOT_READ and the read is not recorded, including
 * when the page was never placed. A page that is not placed is PAGE.
 * A member who is not revoked records a read of a placed page.
 * A read recorded before a later revoke stays recorded.
 */
class SwarmReadRead {
public:
    bool Apply(const SwarmReadRoster& roster,
               const SwarmReadBook& book,
               SwarmReadLedger& ledger,
               const std::string& member,
               const std::string& page,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_READ_H
