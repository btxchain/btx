// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleupdate.h>

namespace modelnet {

bool SwarmStaleUpdate::Local(uint64_t step, const std::string& hash, std::string& err)
{
    if (hash.empty()) {
        err = "HASH";
        return false;
    }
    // Only the next step is admitted. Any other step is a gap and leaves
    // the local hash where it is.
    if (step != m_step + 1) {
        err = "GAP";
        return false;
    }
    m_step = step;
    m_hash = hash;
    err.clear();
    return true;
}

bool SwarmStaleUpdate::Remote(uint64_t step, const std::string& hash, std::string& err)
{
    if (hash.empty()) {
        err = "HASH";
        return false;
    }
    // A step at or behind the local step is stale. It does not replace
    // the local hash and it is not recorded as pending.
    if (step <= m_step) {
        err = "STALE";
        return false;
    }
    m_pending = hash;
    err.clear();
    return true;
}

uint64_t SwarmStaleUpdate::step() const
{
    return m_step;
}

const std::string& SwarmStaleUpdate::hash() const
{
    return m_hash;
}

const std::string& SwarmStaleUpdate::pending() const
{
    return m_pending;
}

int64_t SwarmStaleUpdate::bytes_moved() const
{
    return 0;
}

} // namespace modelnet
