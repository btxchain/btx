// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CAS_H
#define BTX_MODELNET_SWARM_CAS_H

#include <string>

namespace modelnet {

/**
 * Local content-address plan. An invalid eviction deletes nothing. The index
 * is marked committed before an orphan is deleted. This function does not
 * hash, transfer, or trust incomplete bytes.
 */
struct SwarmCasPlan {
    bool eviction_valid{false};
    bool index_committed{false};
    bool orphan_deleted{false};
    bool bytes_trusted{false};
};

bool SwarmCommitCas(SwarmCasPlan& plan, bool want_delete_orphan, std::string& err);

/** Unverified bytes are INCOMPLETE and are not trusted. */
bool SwarmTrustIncomplete(bool digest_verified, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CAS_H
