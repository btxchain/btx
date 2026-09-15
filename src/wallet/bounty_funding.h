// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_BOUNTY_FUNDING_H
#define BITCOIN_WALLET_BOUNTY_FUNDING_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
class CWallet;

struct BountyEscrowPlan {
    std::string bounty_id;
    std::string round_id;
    std::string lot_id;
    std::string plan_id;
    int64_t principal_atoms{0};
    int64_t fee_reserve_atoms{0};
    int64_t fee_atoms{0};
    uint32_t award_height{0};
    uint32_t refund_height{0};
    int threshold{0};
    std::vector<std::string> council_keys;
    std::string refund_key;
    std::string descriptor;
    CScript output_script;
    std::string unsigned_hex;
    uint256 unsigned_txid;
    std::string mode; // PUBLIC_PAYOUT or STAGED_RELEASE
    std::string hashlock_hex;
    std::string claimant_key;
};

bool BuildBountyEscrowDescriptor(BountyEscrowPlan& plan, std::string& err);
bool BuildStagedHtlcDescriptor(BountyEscrowPlan& plan, std::string& err);
bool ExactTwoLeafTree(const std::string& descriptor, std::string& err);
bool PrepareBountyFunding(CWallet& wallet, BountyEscrowPlan& plan, std::string& err);
bool InspectBountyTransaction(const BountyEscrowPlan& plan, const CMutableTransaction& tx, UniValue& out, std::string& err);
bool SignBountyTransaction(CWallet& wallet, BountyEscrowPlan& plan, CMutableTransaction& tx, std::string& err);
UniValue BountyPlanToJson(const BountyEscrowPlan& plan);
bool ParseBountyPlan(const UniValue& o, BountyEscrowPlan& plan, std::string& err);

} // namespace wallet

#endif // BITCOIN_WALLET_BOUNTY_FUNDING_H
