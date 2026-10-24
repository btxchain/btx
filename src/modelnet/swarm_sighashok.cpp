// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sighashok.h>

#include <map>
#include <string>

namespace modelnet {

bool SwarmSighashOk::Sign(const std::string& txid, bool covers_outputs, std::string& err)
{
    if (txid.empty()) {
        err = "TX";
        return false;
    }
    if (m_signed_ok.find(txid) != m_signed_ok.end()) {
        err = "REPLAY";
        return false;
    }
    // A sighash that skips outputs is recorded as unsigned and is not signed.
    if (!covers_outputs) {
        m_signed_ok.emplace(txid, false);
        err = "NOT_SIGNED";
        return false;
    }
    m_signed_ok.emplace(txid, true);
    err.clear();
    return true;
}

bool SwarmSighashOk::signed_ok(const std::string& txid) const
{
    const auto it = m_signed_ok.find(txid);
    return it != m_signed_ok.end() && it->second;
}

} // namespace modelnet
