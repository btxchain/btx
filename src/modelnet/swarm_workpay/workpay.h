// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WORKPAY_H
#define BITCOIN_MODELNET_SWARM_WORKPAY_H

#include <modelnet/swarm_workpay/earned.h>
#include <modelnet/swarm_workpay/receipt.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Work-receipt payment. Payment is an in-memory earned counter.
 * Bind stores a receipt once. Pay adds that receipt's atoms to earned
 * once. A research key or a scheduler cannot be paid. A receipt that
 * was not bound cannot be paid.
 * automatic_spend stays "0". Nothing is broadcast or mined.
 * bytes_moved stays 0. A fiat quote is not a balance. Merge moves nothing.
 */
class SwarmWorkPay {
public:
    /**
     * Empty receipt or empty job is RECEIPT and stores nothing.
     * atoms below 1 is ATOMS and stores nothing.
     * The same receipt again is REPLAY and does not add atoms again.
     */
    bool Bind(const std::string& receipt, const std::string& job, int64_t atoms, std::string& err);

    /** Sum of atoms from the first successful bind of each receipt. */
    int64_t total() const;

    /** True when Bind stored this receipt. */
    bool bound(const std::string& receipt) const;

    /**
     * Unknown receipt is RECEIPT and adds nothing.
     * research_key or scheduler is NOT_SIGNED and adds nothing.
     * That refusal does not mark the receipt paid.
     * Otherwise the bound atoms are added to earned once.
     * A second Pay of that receipt without those flags is REPLAY and
     * does not add again.
     */
    bool Pay(const std::string& receipt, bool research_key, bool scheduler, std::string& err);

    /** Atoms added by successful pays. */
    int64_t earned() const;

    /** True when Pay has added this receipt's atoms to earned. */
    bool paid(const std::string& receipt) const;

    /** Sets err to NOT_BALANCE and stores nothing. */
    bool Quote(const std::string& fiat, std::string& err) const;

    /** Sets err to NOT_MERGED. No counter changes. */
    bool Merge(std::string& err) const;

    /** Stays the string "0". */
    std::string automatic_spend() const;

    /** Always false. Nothing is broadcast. */
    bool Broadcast() const;

    /** Always false. Nothing is mined. */
    bool mined() const;

    /** Always 0. Nothing is sent. */
    int64_t bytes_moved() const;

private:
    SwarmWorkReceiptBook m_book;
    SwarmWorkEarned m_earned;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WORKPAY_H
