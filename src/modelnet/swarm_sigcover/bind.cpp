// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/bind.h>

#include <modelnet/swarm_sigcover/codes.h>
#include <modelnet/swarm_sigcover/limits.h>
#include <modelnet/swarm_sigcover/record.h>

#include <string>

namespace modelnet {

bool SwarmSigCoverRefuseBind(const SwarmSigCoverRecord* row, const std::string& key, std::string& err)
{
    // The row is const. A covered description and a stored preimage stay as they are.
    // key is not written onto any row. An empty key is the same refusal.
    const bool covered = row != nullptr && SwarmSigCoverRowCovered(*row);
    const int stored_len = row == nullptr ? kSwarmSigCoverPreimageAbsent : SwarmSigCoverRowPreimageLen(*row);
    static_cast<void>(covered);
    static_cast<void>(stored_len);
    static_cast<void>(key.size());
    err = SWARM_SIGCOVER_NOT_SIGNED;
    return false;
}

} // namespace modelnet
