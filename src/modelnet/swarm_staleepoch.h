// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_STALEEPOCH_H
#define BTX_MODELNET_SWARM_STALEEPOCH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a coordinator's stored epoch and a resume epoch.
 * coordinator_id names the coordinator being noted. stored_epoch is the
 * epoch already on record. resume_epoch is the epoch offered on resume.
 * want_commit asks to treat the resume as a commit.
 *
 * This is a local note. It does not kill a process and it is not an
 * election. No hostnames or IPs are used.
 */
struct SwarmStaleEpoch {
    std::string coordinator_id;
    int64_t stored_epoch{0};
    int64_t resume_epoch{0};
    bool want_commit{false};
};

/**
 * A local stale-epoch note. committed stays false on every path: a lower
 * epoch commits nothing, and a commit request at the stored epoch is
 * still not a commit.
 */
struct SwarmStaleEpochResult {
    bool committed{false};
    std::string code;
};

/**
 * Order, first match wins: an empty coordinator_id, a stored_epoch below
 * 1, or a resume_epoch below 1 is EPOCH. A resume_epoch below
 * stored_epoch is STALE, including when want_commit is true. want_commit
 * is COMMIT_REFUSED. Otherwise the note is NOTED and err is clear.
 * committed stays false on every path. A lower epoch commits nothing. A
 * commit request at the stored epoch is still not a commit. This records
 * a local note. It does not kill a process and it is not an election. No
 * hostnames or IPs are used.
 */
SwarmStaleEpochResult SwarmNoteStaleEpoch(const SwarmStaleEpoch& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_STALEEPOCH_H
