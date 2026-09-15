// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_MODEL_PAYMENT_H
#define BITCOIN_WALLET_MODEL_PAYMENT_H

#include <modelnet/release.h>
#include <modelnet/transfer.h>

#include <string>

namespace wallet {

/**
 * Model-plane payment policy. Does not introduce htlc_sha256_tx or
 * buildmodelhtlcclaim. Final 0.34.6 already provides:
 *   - htlc_sha256(<SHA256>, <PQ claimant>)
 *   - mr(htlc_sha256(...), refund(height, key))
 *   - buildhtlcclaim / buildhtlcrefund
 * HASH160 htlc_tx remains recovery-only.
 */
struct ModelPaymentPolicy {
    int64_t budget_atoms{0};
    bool auto_pay{false};
    bool CheckQuote(const modelnet::Quote& q, std::string& err) const;
};

} // namespace wallet

#endif // BITCOIN_WALLET_MODEL_PAYMENT_H
