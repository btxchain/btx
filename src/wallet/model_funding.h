// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_MODEL_FUNDING_H
#define BITCOIN_WALLET_MODEL_FUNDING_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
class CWallet;

/**
 * Frozen 0.34.6 htlc_sha256 funding round. Coordinator has no signing
 * authority: prepare never signs or broadcasts. HASH160 htlc_tx is
 * recovery-only and is never selected here.
 */
struct FrozenFundingQuote {
    std::string release_id;
    std::string key_hash_hex;
    std::string claimant_key;
    std::string refund_key;
    uint32_t refund_height{0};
    int64_t amount_atoms{0};
    int64_t fee_cap_atoms{0};
    int64_t fee_atoms{0};
    bool fee_cap_set{false};
    std::string descriptor;
    CScript output_script;
    std::string unsigned_hex;
    uint256 unsigned_txid;
};

bool RejectForbiddenHtlc(const UniValue& options, std::string& err);
bool RejectAutoPay(const UniValue& options, std::string& err);
bool ValidateFundingAmount(int64_t amount_atoms, std::string& err);
/** Canonical decimal atoms. Legacy integral JSON numbers are also accepted. */
bool ParseFundingAtoms(const UniValue& value, int64_t& atoms, std::string& err);
bool NormalizePqDescriptorKey(const std::string& in, std::string& out, std::string& err);
bool ExpandHtlcSha256Descriptor(const std::string& descriptor, CScript& script_pubkey, std::string& canonical, std::string& err);
bool BuildHtlcSha256Descriptor(FrozenFundingQuote& q, std::string& err);
bool ParseFrozenFundingQuote(const UniValue& options, FrozenFundingQuote& q, std::string& err);
void MergeHelperCampaign(const UniValue& helper, const std::string& release_id, FrozenFundingQuote& q);
bool DecodeFundingTxHex(const std::string& hex, CMutableTransaction& tx, std::string& err);
bool MatchFrozenTemplate(const FrozenFundingQuote& frozen, const CMutableTransaction& tx, std::string& err);
/**
 * Rebuild mr(htlc_sha256, refund) from key_hash, claimant, refund pubkey, and
 * refund_height. Caller output_script and unsigned_txid are ignored. Exactly
 * one output must match that script and amount_atoms. Any other output is
 * refused when change_wallet is null; otherwise it must be this wallet's change.
 */
bool MatchRebuiltHtlc(FrozenFundingQuote& q, const CMutableTransaction& tx, const CWallet* change_wallet, std::string& err);
/** Mint a wallet refund key when omitted. A supplied key must already be signable here. */
bool EnsureModelRefundKey(CWallet& wallet, FrozenFundingQuote& q, std::string& err);
UniValue FrozenQuoteToJson(const FrozenFundingQuote& q);
UniValue ExportModelRecoveryJson(const FrozenFundingQuote& q);

bool CreateUnsignedFunding(CWallet& wallet, FrozenFundingQuote& q, std::string& err);
/** Rechecks the refund key, rebuilds the HTLC, then signs. Does not trust caller script or txid. */
bool SignFrozenFunding(CWallet& wallet, const FrozenFundingQuote& quote, CMutableTransaction& mtx, bool& complete, std::string& err);
/** Rebuild exact terms and recheck input ownership, fees, and unspentness before broadcast. */
bool ValidateFrozenFundingSubmission(CWallet& wallet, FrozenFundingQuote& quote, const CMutableTransaction& tx,
                                     bool already_known, std::string& err);

/** Local wallet+chain view of a campaign HTLC. Not a remote peer claim. Never returns secrets.
 *  Matches P2MR scripts and recorded funding outpoints. A scan that finds nothing
 *  leaves confirmed_known false (it is not a known zero). */
UniValue ObserveReleaseFunding(CWallet& wallet, const std::string& key_hash_hex, uint32_t refund_height,
                               const std::string& output_script_hex = {});
UniValue ObserveReleaseFunding(const std::vector<CWallet*>& wallets, const std::string& key_hash_hex,
                               uint32_t refund_height, const std::vector<CScript>& output_scripts,
                               const std::vector<COutPoint>& funding_outpoints);

} // namespace wallet

#endif // BITCOIN_WALLET_MODEL_FUNDING_H
