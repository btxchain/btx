// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_RECORD_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_RECORD_H

#include <string>

namespace modelnet {

/**
 * One admitted peer and the family stored with it.
 * The family is the id from the successful Admit. Nothing here connects
 * the peer or records a seed.
 */
struct SwarmFamilyAdmitRecord {
    std::string peer;
    std::string family;
};

SwarmFamilyAdmitRecord SwarmFamilyAdmitMakeRecord(const std::string& peer, const std::string& family);

/** Both ids must be non-empty. */
bool SwarmFamilyAdmitRecordUsable(const SwarmFamilyAdmitRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_RECORD_H
