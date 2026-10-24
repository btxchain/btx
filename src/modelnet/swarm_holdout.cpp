// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdout.h>

namespace modelnet {

bool SwarmHoldoutBook::Open(const SwarmHoldoutOpen& round, std::string& err)
{
    if (round.suite_id.empty() || round.holdout_digest.empty()) {
        err = "HOLDOUT";
        return false;
    }
    if (round.author_sees_holdout) {
        err = "HOLDOUT_LEAKED";
        return false;
    }
    if (!round.precommitted) {
        err = "SUITE_NOT_PRECOMMITTED";
        return false;
    }
    if (m_used.count(round.holdout_digest) != 0) {
        err = "HOLDOUT_REUSED";
        return false;
    }
    if (m_open) {
        err = "REPLAY";
        return false;
    }
    m_digest = round.holdout_digest;
    m_open = true;
    m_measured = false;
    err.clear();
    return true;
}

bool SwarmHoldoutBook::Consume(std::string& err)
{
    if (!m_open) {
        err = "GATE";
        return false;
    }
    m_used.insert(m_digest);
    m_open = false;
    m_measured = false;
    err.clear();
    return true;
}

bool SwarmHoldoutBook::HasOpen() const
{
    return m_open;
}

bool SwarmHoldoutBook::Measured() const
{
    return m_measured;
}

} // namespace modelnet
