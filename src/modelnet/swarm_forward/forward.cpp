// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_forward/forward.h>

#include <modelnet/swarm_forward/codes.h>

namespace modelnet {

bool SwarmForward::Open(const std::string& channel, int64_t liquidity, std::string& err)
{
    return m_channels.Open(channel, liquidity, err);
}

bool SwarmForward::Forward(const std::string& channel, const std::string& payment_id, int64_t amount, bool incoming_committed,
                           int incoming_expiry, int outgoing_expiry, int height, std::string& err)
{
    if (!m_channels.Known(channel)) {
        err = kSwarmForwardChannel;
        return false;
    }
    if (!m_payments.Admit(channel, payment_id, err)) {
        return false;
    }
    if (!m_liquidity.Atoms(amount, err)) {
        return false;
    }
    const int64_t remaining = m_channels.Remaining(channel);
    if (!m_liquidity.Fits(remaining, amount, err)) {
        return false;
    }
    if (!m_margin.Accept(incoming_expiry, outgoing_expiry, err)) {
        return false;
    }
    if (!m_allow.Accept(incoming_committed, remaining, amount, incoming_expiry, height, err)) {
        return false;
    }

    SwarmForwardHop hop;
    hop.channel = channel;
    hop.payment_id = payment_id;
    hop.amount = amount;
    hop.incoming_committed = incoming_committed;
    hop.incoming_expiry = incoming_expiry;
    hop.outgoing_expiry = outgoing_expiry;
    hop.height = height;

    m_payments.Remember(channel, payment_id);
    if (!m_channels.Debit(channel, amount)) {
        m_payments.Forget(channel, payment_id);
        err = kSwarmForwardShort;
        return false;
    }
    m_ledger.Note(hop);
    err.clear();
    return true;
}

} // namespace modelnet
