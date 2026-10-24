// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_debitcap.h>

namespace modelnet {

bool SwarmDebitCap::Open(const std::string& channel, int64_t capacity, std::string& err)
{
    if (channel.empty()) {
        err = "CHANNEL";
        return false;
    }
    if (capacity < 1) {
        err = "CAPACITY";
        return false;
    }
    if (m_remaining.find(channel) != m_remaining.end()) {
        err = "REPLAY";
        return false;
    }
    m_remaining.emplace(channel, capacity);
    err.clear();
    return true;
}

bool SwarmDebitCap::Debit(const std::string& channel, int64_t atoms, std::string& err)
{
    const auto it = m_remaining.find(channel);
    if (it == m_remaining.end()) {
        err = "CHANNEL";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (atoms > it->second) {
        err = "SHORT";
        return false;
    }
    it->second -= atoms;
    err.clear();
    return true;
}

int64_t SwarmDebitCap::Remaining(const std::string& channel) const
{
    const auto it = m_remaining.find(channel);
    if (it == m_remaining.end()) return -1;
    return it->second;
}

} // namespace modelnet
