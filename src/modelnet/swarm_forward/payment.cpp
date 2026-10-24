// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/payment.h>

#include <modelnet/swarm_forward/codes.h>

namespace modelnet {

bool SwarmForwardPayment::Admit(const std::string& channel, const std::string& payment_id, std::string& err) const
{
    if (payment_id.empty()) {
        err = kSwarmForwardPayment;
        return false;
    }
    if (Seen(channel, payment_id)) {
        err = kSwarmForwardReplay;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmForwardPayment::Seen(const std::string& channel, const std::string& payment_id) const
{
    return m_seen.find(std::make_pair(channel, payment_id)) != m_seen.end();
}

void SwarmForwardPayment::Remember(const std::string& channel, const std::string& payment_id)
{
    if (payment_id.empty()) return;
    m_seen.emplace(channel, payment_id);
}

void SwarmForwardPayment::Forget(const std::string& channel, const std::string& payment_id)
{
    m_seen.erase(std::make_pair(channel, payment_id));
}

} // namespace modelnet
