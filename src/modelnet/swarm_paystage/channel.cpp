// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/channel.h>

namespace modelnet {

bool SwarmPayChannel::Open(const std::string& name, int64_t capacity, std::string& err)
{
    if (name.empty()) {
        err = "CHANNEL";
        return false;
    }
    if (capacity < 1) {
        err = "CAPACITY";
        return false;
    }
    if (m_open) {
        err = "NOT_OPENED";
        return false;
    }
    m_name = name;
    m_capacity = capacity;
    m_remaining = capacity;
    m_open = true;
    err.clear();
    return true;
}

bool SwarmPayChannel::Debit(int64_t atoms, std::string& err)
{
    if (!m_open) {
        err = "CHANNEL";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (atoms > m_remaining) {
        err = "SHORT";
        return false;
    }
    m_remaining -= atoms;
    err.clear();
    return true;
}

int64_t SwarmPayChannel::Remaining(const std::string& name) const
{
    if (!m_open || name != m_name) {
        return -1;
    }
    return m_remaining;
}

const std::string& SwarmPayChannel::open_channel() const
{
    return m_name;
}

int64_t SwarmPayChannel::capacity() const
{
    return m_capacity;
}

} // namespace modelnet
