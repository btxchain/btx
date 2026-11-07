// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/record.h>

#include <modelnet/swarm_sigcover/limits.h>

namespace modelnet {

bool SwarmSigCoverRowCovered(const SwarmSigCoverRecord& row)
{
    return row.outputs_covered;
}

int SwarmSigCoverRowPreimageLen(const SwarmSigCoverRecord& row)
{
    if (!row.preimage_described) {
        return kSwarmSigCoverPreimageAbsent;
    }
    return static_cast<int>(kSwarmSigCoverPreimageLen);
}

void SwarmSigCoverCommitCover(SwarmSigCoverRecord& row)
{
    // One-way. A second commit leaves the covered row covered.
    if (row.outputs_covered) {
        return;
    }
    row.outputs_covered = true;
}

void SwarmSigCoverCommitPreimage(SwarmSigCoverRecord& row)
{
    // One-way. A second commit leaves the 32-byte description in place.
    if (row.preimage_described) {
        return;
    }
    row.preimage_described = true;
}

} // namespace modelnet
