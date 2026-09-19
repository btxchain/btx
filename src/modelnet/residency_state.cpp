// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/residency_state.h>

namespace modelnet {

const char* NetworkResidencyName(NetworkResidency r)
{
    switch (r) {
    case NetworkResidency::ABSENT: return "ABSENT";
    case NetworkResidency::STAGING: return "STAGING";
    case NetworkResidency::VERIFIED_LOCAL: return "VERIFIED_LOCAL";
    case NetworkResidency::VERIFIED_REMOTE: return "VERIFIED_REMOTE";
    case NetworkResidency::VERIFIED_BOTH: return "VERIFIED_BOTH";
    case NetworkResidency::REPAIRABLE: return "REPAIRABLE";
    case NetworkResidency::UNAVAILABLE: return "UNAVAILABLE";
    }
    return "UNAVAILABLE";
}

NetworkResidency FromPieceResidency(PieceResidency r)
{
    switch (r) {
    case PieceResidency::LOCAL: return NetworkResidency::VERIFIED_LOCAL;
    case PieceResidency::CLOUD: return NetworkResidency::VERIFIED_REMOTE;
    case PieceResidency::BOTH: return NetworkResidency::VERIFIED_BOTH;
    case PieceResidency::ABSENT: return NetworkResidency::ABSENT;
    }
    return NetworkResidency::UNAVAILABLE;
}

bool RemoteExistenceImpliesVerifiedRemote()
{
    return false;
}

} // namespace modelnet
