// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/paystage.h>

#include <modelnet/swarm_paystage/fiat_quote.h>
#include <modelnet/swarm_paystage/profit_split.h>
#include <modelnet/swarm_paystage/qualify.h>
#include <modelnet/swarm_paystage/spend_policy.h>

namespace modelnet {

bool SwarmPayStage::Credit(const std::string& bucket, int64_t atoms, const std::string& memo_id, std::string& err)
{
    return m_balances.Credit(bucket, atoms, memo_id, err);
}

bool SwarmPayStage::Merge(std::string& err) const
{
    return m_balances.Merge(err);
}

int64_t SwarmPayStage::Balance(const std::string& bucket) const
{
    return m_balances.Balance(bucket);
}

bool SwarmPayStage::Open(const std::string& name, int64_t capacity, std::string& err)
{
    return m_channel.Open(name, capacity, err);
}

bool SwarmPayStage::Debit(int64_t atoms, std::string& err)
{
    return m_channel.Debit(atoms, err);
}

int64_t SwarmPayStage::Remaining(const std::string& name) const
{
    return m_channel.Remaining(name);
}

const std::string& SwarmPayStage::open_channel() const
{
    return m_channel.open_channel();
}

int64_t SwarmPayStage::capacity() const
{
    return m_channel.capacity();
}

bool SwarmPayStage::Settle(const SwarmPaySettle& request, std::string& err)
{
    if (!SwarmPayAcceptSpend(request.research_key, request.scheduler, err)) {
        return false;
    }
    // A hashlock is not a qualified multi-hop network. If that ever
    // changes, abort before the book or any bucket moves.
    if (!SwarmPayRefuseQualified(m_invoices.MultiHopQualified(), err)) {
        return false;
    }
    if (request.preimage.size() != 32) {
        err = "PREIMAGE";
        return false;
    }
    if (m_balances.HasMemo(request.invoice_id)) {
        err = "REPLAY";
        return false;
    }
    if (request.atoms >= 1 && !m_balances.Fits(SWARM_PAY_BUCKET_EARNED, request.atoms)) {
        err = "ATOMS";
        return false;
    }

    int64_t settled_atoms = 0;
    if (!m_invoices.Reveal(request, settled_atoms, err)) {
        return false;
    }
    // Check again immediately before any bucket changes. The only credit
    // below is earned. Escrow, collateral, and fees are not written.
    if (!SwarmPayRefuseQualified(m_invoices.MultiHopQualified(), err)) {
        return false;
    }
    if (settled_atoms != request.atoms || settled_atoms < 1) {
        err = "ATOMS";
        return false;
    }
    return m_balances.Credit(SWARM_PAY_BUCKET_EARNED, settled_atoms, request.invoice_id, err);
}

std::string SwarmPayStage::automatic_spend() const
{
    return SwarmPayAutomaticSpend();
}

bool SwarmPayStage::Broadcast() const
{
    return SwarmPayBroadcast();
}

bool SwarmPayStage::mined() const
{
    return SwarmPayMined();
}

bool SwarmPayStage::Quote(std::string& err) const
{
    return SwarmPayFiatQuote(err);
}

bool SwarmPayStage::Split(std::string& err) const
{
    return SwarmPayProfitSplit(err);
}

bool SwarmPayStage::MultiHopQualified() const
{
    return m_invoices.MultiHopQualified();
}

} // namespace modelnet
