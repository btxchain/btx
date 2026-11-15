// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SET01_SET01_H
#define BITCOIN_MODELNET_SET01_SET01_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

/**
 * Set01. An unsigned funding plan is not a settlement.
 * NoteUnsignedPlan returns false with ABSENT when no plan was created,
 * UNSIGNED when the plan was not submitted by a wallet, and FIELD when a
 * submitted plan has an empty txid. settled() stays false on those paths.
 * A wallet-submitted plan with a non-empty txid is stored and settled.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. This class creates no transaction and opens no RPC.
 */
class Set01 {
public:
    bool NoteUnsignedPlan(bool plan_created, bool wallet_submitted, const std::string& txid, std::string& err);

    bool settled() const { return m_settled; }
    std::string txid() const { return m_txid; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_settled{false};
    std::string m_txid;
};

} // namespace modelnet

#endif
