// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_H
#define BITCOIN_MODELNET_SWARM_FORWARD_H

#include <modelnet/swarm_forward/allow.h>
#include <modelnet/swarm_forward/channel.h>
#include <modelnet/swarm_forward/hop.h>
#include <modelnet/swarm_forward/ledger.h>
#include <modelnet/swarm_forward/liquidity.h>
#include <modelnet/swarm_forward/margin.h>
#include <modelnet/swarm_forward/payment.h>
#include <modelnet/swarm_forward/policy.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory multi-hop forward gate.
 * Open stores liquidity for one channel. An empty channel is CHANNEL.
 * Liquidity below 1 is LIQUIDITY. A second Open of the same channel is
 * REPLAY and leaves the first liquidity.
 * Forward moves amount along one hop. An unknown channel is CHANNEL.
 * An empty payment id is PAYMENT. A second forward of the same payment
 * id on the same channel is REPLAY and does not subtract again. Amount
 * below 1 is ATOMS. Amount above remaining liquidity is SHORT and the
 * liquidity stays. The outgoing expiry must be at least the incoming
 * expiry plus 160; a smaller outgoing expiry is MARGIN. SwarmForwardAllowed
 * is then called with that same margin. On refusal nothing is stored and
 * its error is returned when it sets one, otherwise MARGIN. On success
 * the amount is subtracted from the remaining liquidity.
 * A hashlock is not a qualified route. qualified() stays false.
 * broadcast() stays false. bytes_moved() stays 0. automatic_spend() is "0".
 * This gate does not broadcast.
 */
class SwarmForward {
public:
    bool Open(const std::string& channel, int64_t liquidity, std::string& err);
    /**
     * Forward one hop. outgoing_expiry is the next hop's expiry. It is
     * MARGIN when it is below incoming_expiry + 160.
     */
    bool Forward(const std::string& channel, const std::string& payment_id, int64_t amount, bool incoming_committed,
                 int incoming_expiry, int outgoing_expiry, int height, std::string& err);

    bool qualified() const { return m_policy.qualified(); }
    bool broadcast() const { return m_policy.broadcast(); }
    int64_t bytes_moved() const { return m_policy.bytes_moved(); }
    std::string automatic_spend() const { return m_policy.automatic_spend(); }

    bool opened(const std::string& channel) const { return m_channels.Known(channel); }
    int64_t remaining(const std::string& channel) const { return m_channels.Remaining(channel); }
    bool forwarded(const std::string& channel, const std::string& payment_id) const
    {
        return m_payments.Seen(channel, payment_id);
    }
    std::size_t forward_count() const { return m_ledger.size(); }
    const std::vector<SwarmForwardHop>& hops() const { return m_ledger.hops(); }

private:
    SwarmForwardChannel m_channels;
    SwarmForwardPayment m_payments;
    SwarmForwardLiquidity m_liquidity;
    SwarmForwardMargin m_margin;
    SwarmForwardAllow m_allow;
    SwarmForwardPolicy m_policy;
    SwarmForwardLedger m_ledger;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_H
