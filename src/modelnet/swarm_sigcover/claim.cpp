// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/claim.h>

#include <modelnet/swarm_sigcover/codes.h>

#include <string>

namespace modelnet {

bool SwarmSigCoverRefuseClaim(bool covered, bool preimage_32, const std::string& id, std::string& err)
{
    // A covered id and a 32-byte preimage description are unqualified.
    // An unknown id is the same refusal. No claim is recorded.
    static_cast<void>(covered);
    static_cast<void>(preimage_32);
    static_cast<void>(id.size());
    err = SWARM_SIGCOVER_UNQUALIFIED;
    return false;
}

} // namespace modelnet
