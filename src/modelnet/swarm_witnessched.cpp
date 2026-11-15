// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_witnessched.h>

namespace modelnet {

bool SwarmWitnessSched::Record(const std::string& txid, bool scheduler, bool covers_outputs, std::string& err)
{
    if (txid.empty()) {
        err = "TX";
        return false;
    }
    if (m_stored.find(txid) != m_stored.end()) {
        err = "REPLAY";
        return false;
    }
    if (scheduler) {
        m_stored.emplace(txid, false);
        err = "NOT_SIGNED";
        return false;
    }
    if (!covers_outputs) {
        m_stored.emplace(txid, false);
        err = "NOT_SIGNED";
        return false;
    }
    m_stored.emplace(txid, true);
    err.clear();
    return true;
}

bool SwarmWitnessSched::signed_ok(const std::string& txid) const
{
    const auto it = m_stored.find(txid);
    if (it == m_stored.end()) {
        return false;
    }
    return it->second;
}

} // namespace modelnet
