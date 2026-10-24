// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WATCHSEQ_H
#define BTX_MODELNET_SWARM_WATCHSEQ_H

#include <string>

namespace modelnet {

/**
 * In-memory watch of the latest observed sequence.
 * The latest sequence starts at 0. A higher sequence supersedes the prior
 * one. The prior secret is not released by this record.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmWatchSeq {
public:
    /**
     * sequence below 1 is SEQUENCE and leaves latest.
     * sequence below latest is STALE and leaves latest.
     * sequence equal to latest is REPLAY and leaves latest.
     * Otherwise latest becomes sequence, err is cleared, and the call
     * returns true.
     */
    bool Observe(int sequence, std::string& err);

    /** Latest observed sequence. Starts at 0. */
    int latest() const;

    /** The prior secret is not released by this record. */
    bool secret_released() const;

private:
    int m_latest{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WATCHSEQ_H
