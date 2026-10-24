// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_H
#define BTX_MODELNET_SWARM_PAYSTAGE_H

#include <modelnet/swarm_paystage/balances.h>
#include <modelnet/swarm_paystage/channel.h>
#include <modelnet/swarm_paystage/invoice_path.h>
#include <modelnet/swarm_paystage/settle.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Payment staging. Four balances stay separate. One channel can be open.
 * An invoice settle credits earned only after a 32-byte preimage matches
 * the hashlock. automatic_spend stays "0". Nothing is broadcast or mined.
 * A fiat quote is not a balance. Profit-share is refused.
 * MultiHopQualified stays false. If it is true, Settle aborts UNQUALIFIED
 * and moves no atoms.
 */
class SwarmPayStage {
public:
    bool Credit(const std::string& bucket, int64_t atoms, const std::string& memo_id, std::string& err);
    bool Merge(std::string& err) const;
    int64_t Balance(const std::string& bucket) const;

    bool Open(const std::string& name, int64_t capacity, std::string& err);
    bool Debit(int64_t atoms, std::string& err);
    int64_t Remaining(const std::string& name) const;
    const std::string& open_channel() const;
    int64_t capacity() const;

    /**
     * Research key or scheduler is NOT_SIGNED and moves no atoms.
     * MultiHopQualified true is UNQUALIFIED and moves no atoms.
     * A preimage whose size is not 32 adds nothing.
     * A matching reveal adds the invoice atoms to earned only.
     */
    bool Settle(const SwarmPaySettle& request, std::string& err);

    /** Stays the string "0". */
    std::string automatic_spend() const;
    /** Always false. */
    bool Broadcast() const;
    /** Always false. */
    bool mined() const;

    /** Stores nothing. err is NOT_BALANCE. */
    bool Quote(std::string& err) const;
    /** Profit-share. err is REFUSED. Moves nothing. */
    bool Split(std::string& err) const;

    /** Always false. A hashlock is not a qualified multi-hop network. */
    bool MultiHopQualified() const;

private:
    SwarmPayBalances m_balances;
    SwarmPayChannel m_channel;
    SwarmPayInvoicePath m_invoices;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_H
