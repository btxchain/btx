// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchseq.h>

namespace modelnet {

bool SwarmWatchSeq::Observe(int sequence, std::string& err)
{
    if (sequence < 1) {
        err = "SEQUENCE";
        return false;
    }
    if (sequence < m_latest) {
        err = "STALE";
        return false;
    }
    if (sequence == m_latest) {
        err = "REPLAY";
        return false;
    }
    // A higher sequence supersedes the prior one. The prior secret is
    // not released by this record.
    m_latest = sequence;
    err.clear();
    return true;
}

int SwarmWatchSeq::latest() const
{
    return m_latest;
}

bool SwarmWatchSeq::secret_released() const
{
    return false;
}

} // namespace modelnet
