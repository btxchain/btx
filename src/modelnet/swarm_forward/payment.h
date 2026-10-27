// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_PAYMENT_H
#define BITCOIN_MODELNET_SWARM_FORWARD_PAYMENT_H

#include <set>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Payment ids accepted on a channel.
 * An empty id is PAYMENT. A second forward of the same id on the same
 * channel is REPLAY. The same id may be forwarded once on another channel.
 */
class SwarmForwardPayment {
public:
    bool Admit(const std::string& channel, const std::string& payment_id, std::string& err) const;
    bool Seen(const std::string& channel, const std::string& payment_id) const;
    void Remember(const std::string& channel, const std::string& payment_id);
    void Forget(const std::string& channel, const std::string& payment_id);

private:
    std::set<std::pair<std::string, std::string>> m_seen;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_PAYMENT_H
