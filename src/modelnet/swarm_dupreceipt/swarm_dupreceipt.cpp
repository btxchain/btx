// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dupreceipt/swarm_dupreceipt.h>

#include <modelnet/swarm_dupreceipt/bind.h>
#include <modelnet/swarm_dupreceipt/pay.h>

namespace modelnet {

bool SwarmDupReceipt::Bind(const std::string& receipt, std::string& err)
{
    return SwarmDupBind{}.Apply(m_book, receipt, err);
}

bool SwarmDupReceipt::Pay(const std::string& receipt, int64_t atoms, bool research_key, bool scheduler, std::string& err)
{
    return SwarmDupPay{}.Apply(m_book, receipt, atoms, research_key, scheduler, err);
}

bool SwarmDupReceipt::bound(const std::string& receipt) const
{
    return m_book.contains(receipt);
}

bool SwarmDupReceipt::paid(const std::string& receipt) const
{
    return m_book.paid(receipt);
}

int64_t SwarmDupReceipt::earned() const
{
    return m_book.earned();
}

int64_t SwarmDupReceipt::paid_atoms(const std::string& receipt) const
{
    return m_book.paid_atoms(receipt);
}

std::size_t SwarmDupReceipt::bound_count() const
{
    return m_book.size();
}

bool SwarmDupReceipt::broadcast() const
{
    return m_quiet.broadcast();
}

bool SwarmDupReceipt::mined() const
{
    return m_quiet.mined();
}

int64_t SwarmDupReceipt::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

std::string SwarmDupReceipt::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

} // namespace modelnet
