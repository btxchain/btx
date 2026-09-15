// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FUNDING_H
#define BITCOIN_MODELNET_FUNDING_H

#include <modelnet/catalog.h>
#include <univalue.h>

#include <string>

namespace modelnet {

/**
 * Helper (no CWallet) implementations of prepare/sign/submit/export and
 * SHA-256 HTLC claim/refund templates. Never HASH160 htlc_tx. Never auto_pay.
 * Sign does not invent wallet keys: complete=false until the tx is already
 * signed or btxd wallet signs. Submit journals the txid; it does not verify
 * chain inclusion (paid_chain_verify stays false).
 *
 * Returns true on success. On failure err_code is set. Returns false with
 * empty err_code when method is not a funding RPC.
 */
bool DispatchFundingRpc(ModelCatalog& cat, const std::string& method, const UniValue& params,
                        UniValue& result, std::string& err_code, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_FUNDING_H
