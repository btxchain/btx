// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESIDENCY_STATE_H
#define BITCOIN_MODELNET_RESIDENCY_STATE_H

#include <modelnet/piece_store.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Spec §9.2. Distinct from PieceResidency (LOCAL/CLOUD/BOTH/ABSENT). */
enum class NetworkResidency : uint8_t {
    ABSENT = 0,
    STAGING = 1,
    VERIFIED_LOCAL = 2,
    VERIFIED_REMOTE = 3,
    VERIFIED_BOTH = 4,
    REPAIRABLE = 5,
    UNAVAILABLE = 6,
};

const char* NetworkResidencyName(NetworkResidency r);
NetworkResidency FromPieceResidency(PieceResidency r);
/** An old HeadObject existence check is not VERIFIED_REMOTE. */
bool RemoteExistenceImpliesVerifiedRemote();

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESIDENCY_STATE_H
