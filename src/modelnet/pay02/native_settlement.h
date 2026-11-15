// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PAY02_NATIVE_SETTLEMENT_H
#define BITCOIN_MODELNET_PAY02_NATIVE_SETTLEMENT_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <optional>
#include <string>

namespace modelnet {

/** Local, rebuilt terms. Never construct these from a peer's settled boolean. */
struct NativePaymentTerms {
    std::string objective;
    COutPoint funding;
    CScript funding_script;
    CScript claim_leaf;
    CScript refund_leaf;
    CScript destination;
    CAmount principal_atoms{0};
    CAmount max_settlement_fee_atoms{0};
    uint32_t refund_height{0};
    int min_confirmations{1};
};

struct NativePaymentTransaction {
    CTransactionRef tx;
    int confirmations{0};
    uint256 block_hash;
};

/** Implemented by the local monetary chain view, never by model-peer RPC data.
 * A transaction in an orphan block must have zero or negative confirmations.
 */
class NativePaymentChainView {
public:
    virtual ~NativePaymentChainView() = default;
    virtual uint256 Tip() const = 0;
    virtual int Height() const = 0;
    virtual bool Lookup(const Txid& txid, NativePaymentTransaction& out, std::string& err) const = 0;
    virtual bool Unspent(const COutPoint& outpoint, CTxOut& out) const = 0;
};

/** Observation at a named chain tip. Reobserve after a tip change/reorganization. */
struct NativePaymentReceipt {
    std::string objective;
    std::string state{"UNKNOWN"};
    std::string branch;
    uint256 chain_tip;
    int chain_height{0};
    COutPoint funding;
    std::optional<Txid> settlement_txid;
    int funding_confirmations{0};
    int settlement_confirmations{0};
    CAmount principal_atoms{0};
    CAmount paid_atoms{0};
    CAmount fee_atoms{0};
    bool funded{false};
    bool settled{false};
};

/** Verify one native SHA-256 HTLC lot against active-chain transactions.
 * The supported settlement profile has one HTLC input and one named output;
 * unrelated inputs/outputs cannot launder a fee or a payout observation.
 * This function never signs, broadcasts, or qualifies a release.
 */
bool ObserveNativePayment(const NativePaymentChainView& chain, const NativePaymentTerms& terms,
                          const std::optional<Txid>& settlement, NativePaymentReceipt& receipt,
                          std::string& err);

} // namespace modelnet
#endif
