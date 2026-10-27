// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/workpay.h>

#include <modelnet/swarm_workpay/codes.h>
#include <modelnet/swarm_workpay/fiat_quote.h>
#include <modelnet/swarm_workpay/merge.h>
#include <modelnet/swarm_workpay/spend_policy.h>

namespace modelnet {

bool SwarmWorkPay::Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err)
{
    return m_book.Bind(receipt, job, atoms, err);
}

int64_t SwarmWorkPay::total() const
{
    return m_book.total();
}

bool SwarmWorkPay::bound(const std::string& receipt) const
{
    return m_book.bound(receipt);
}

bool SwarmWorkPay::Pay(const std::string& receipt, bool research_key, bool scheduler, std::string& err)
{
    int64_t atoms = 0;
    if (!m_book.Find(receipt, atoms)) {
        // A receipt that was not bound cannot be paid.
        err = SWARM_WORK_RECEIPT;
        return false;
    }
    if (!SwarmWorkAcceptPay(research_key, scheduler, err)) {
        return false;
    }
    return m_earned.Credit(receipt, atoms, err);
}

int64_t SwarmWorkPay::earned() const
{
    return m_earned.earned();
}

bool SwarmWorkPay::paid(const std::string& receipt) const
{
    return m_earned.paid(receipt);
}

bool SwarmWorkPay::Quote(const std::string& fiat, std::string& err) const
{
    return SwarmWorkFiatQuote(fiat, err);
}

bool SwarmWorkPay::Merge(std::string& err) const
{
    return SwarmWorkMerge(err);
}

std::string SwarmWorkPay::automatic_spend() const
{
    return SwarmWorkAutomaticSpend();
}

bool SwarmWorkPay::Broadcast() const
{
    return SwarmWorkBroadcast();
}

bool SwarmWorkPay::mined() const
{
    return SwarmWorkMined();
}

int64_t SwarmWorkPay::bytes_moved() const
{
    return SwarmWorkBytesMoved();
}

} // namespace modelnet
