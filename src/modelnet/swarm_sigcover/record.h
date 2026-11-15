// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_RECORD_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_RECORD_H

#include <modelnet/swarm_sigcover/types.h>

namespace modelnet {

/** True when this row records a sighash description that covered outputs. */
bool SwarmSigCoverRowCovered(const SwarmSigCoverRecord& row);

/**
 * Stored preimage length.
 * 32 when a 32-byte preimage was described. -1 otherwise.
 */
int SwarmSigCoverRowPreimageLen(const SwarmSigCoverRecord& row);

/**
 * Mark the row covered.
 * A row that is already covered stays covered.
 * This function never writes outputs_covered false.
 */
void SwarmSigCoverCommitCover(SwarmSigCoverRecord& row);

/**
 * Record a 32-byte preimage description.
 * A row that already has one stays described.
 * This function never writes a length other than 32 and never clears one.
 */
void SwarmSigCoverCommitPreimage(SwarmSigCoverRecord& row);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_RECORD_H
