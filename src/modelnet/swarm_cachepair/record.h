// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CACHEPAIR_RECORD_H
#define BITCOIN_MODELNET_SWARM_CACHEPAIR_RECORD_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * One recorded share: the page and the distinct members it had when
 * Share stored it. A later Place does not rewrite this record.
 * Nothing here moves bytes, takes a CUDA buffer, or starts a process.
 */
struct SwarmCachePairRecord {
    std::string page;
    std::vector<std::string> members;
};

SwarmCachePairRecord SwarmCachePairMakeRecord(const std::string& page, const std::vector<std::string>& members);

/**
 * A record can be stored only when the page is named and the member
 * list has at least two distinct non-empty members.
 */
bool SwarmCachePairRecordUsable(const SwarmCachePairRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CACHEPAIR_RECORD_H
