// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SET02_SET02_H
#define BITCOIN_MODELNET_SET02_SET02_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

/**
 * Set02. P2P-SCN-M and ASR-PAY-004.
 * A funded objective settles only when a wallet submits a non-empty txid
 * and every claimed payment mode is settled. Note returns false with FIELD
 * when modes_claimed is below 1 or the txid is empty, ABSENT when no plan
 * was created, UNSIGNED when the wallet did not submit, and MODE when
 * modes_settled is not modes_claimed. One regtest submission does not
 * settle every claimed mode. settled() stays false on those paths.
 * modes_settled() stays 0 until Note accepts an exact match.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. This class creates no transaction and opens no RPC.
 */
class Set02 {
public:
    bool Note(bool plan_created, bool wallet_submitted, const std::string& txid, int modes_claimed,
              int modes_settled, std::string& err);

    bool settled() const { return m_settled; }
    int modes_settled() const { return m_modes_settled; }
    std::string txid() const { return m_txid; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_settled{false};
    int m_modes_settled{0};
    std::string m_txid;
};

} // namespace modelnet

#endif
