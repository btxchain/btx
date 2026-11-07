// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channelset/channelset.h>

#include <modelnet/swarm_channelset/claim.h>
#include <modelnet/swarm_channelset/fund.h>
#include <modelnet/swarm_channelset/open.h>
#include <modelnet/swarm_channelset/payout.h>
#include <modelnet/swarm_channelset/policy.h>
#include <modelnet/swarm_channelset/refund.h>

namespace modelnet {

bool SwarmChannelSet::Open(const std::string& name, int64_t capacity, const std::vector<unsigned char>& sponsor_pubkey,
                           const std::vector<unsigned char>& worker_pubkey, std::string& err)
{
    return ChannelSetOpen(m_record, name, capacity, sponsor_pubkey, worker_pubkey, err);
}

bool SwarmChannelSet::Refund(int refund_height, std::string& err)
{
    return ChannelSetRefund(m_record, refund_height, err);
}

bool SwarmChannelSet::Fund(std::string& err)
{
    return ChannelSetFund(m_record, err);
}

bool SwarmChannelSet::Payout(int64_t cumulative, int height, int refund_height, std::string& err)
{
    return ChannelSetPayout(m_record, cumulative, height, refund_height, err);
}

bool SwarmChannelSet::ClaimAllowed(int height, int refund_height) const
{
    return ChannelSetClaimAllowed(height, refund_height);
}

const std::string& SwarmChannelSet::name() const
{
    return m_record.name;
}

int64_t SwarmChannelSet::capacity() const
{
    return m_record.tx.capacity;
}

int64_t SwarmChannelSet::cumulative() const
{
    return m_record.tx.cumulative;
}

int SwarmChannelSet::refund_height() const
{
    return m_record.tx.refund_height;
}

bool SwarmChannelSet::funded() const
{
    return m_record.tx.funded;
}

bool SwarmChannelSet::refund_built() const
{
    return m_record.refund_built;
}

int64_t SwarmChannelSet::refund_value() const
{
    if (m_record.tx.refund.vout.empty()) return 0;
    return m_record.tx.refund.vout[0].nValue;
}

std::size_t SwarmChannelSet::refund_outputs() const
{
    return m_record.tx.refund.vout.size();
}

int64_t SwarmChannelSet::payout_worker_value() const
{
    if (m_record.tx.payout.vout.empty()) return 0;
    return m_record.tx.payout.vout[0].nValue;
}

int64_t SwarmChannelSet::payout_sponsor_value() const
{
    if (m_record.tx.payout.vout.size() < 2) return 0;
    return m_record.tx.payout.vout[1].nValue;
}

std::size_t SwarmChannelSet::payout_outputs() const
{
    return m_record.tx.payout.vout.size();
}

std::string SwarmChannelSet::automatic_spend() const
{
    return ChannelSetAutomaticSpend();
}

bool SwarmChannelSet::broadcast() const
{
    return ChannelSetBroadcast();
}

bool SwarmChannelSet::mined() const
{
    return ChannelSetMined();
}

int64_t SwarmChannelSet::bytes_moved() const
{
    return ChannelSetBytesMoved();
}

bool SwarmChannelSet::multi_hop_qualified() const
{
    return ChannelSetMultiHopQualified();
}

} // namespace modelnet
