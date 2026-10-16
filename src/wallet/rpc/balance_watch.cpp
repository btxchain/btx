// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <core_io.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <wallet/balance_watch.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
static UniValue BalanceWatchStatusToJSON(const BalanceWatchStatus& status)
{
    UniValue descriptors{UniValue::VARR};
    for (const std::string& descriptor : status.descriptors) {
        descriptors.push_back(descriptor);
    }

    UniValue fetched{UniValue::VARR};
    for (const BalanceWatchMiss& miss : status.fetched) {
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("descriptor", miss.descriptor);
        entry.pushKV("height", miss.height);
        fetched.push_back(std::move(entry));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("ready", status.ready);
    result.pushKV("chain_height", status.chain_height);
    result.pushKV("wallet_height", status.wallet_height);
    result.pushKV("blocks_behind", status.blocks_behind);
    result.pushKV("scanning", status.scanning);
    result.pushKV("shielded_foreign_watch", status.shielded_foreign_watch);
    result.pushKV("descriptors", std::move(descriptors));
    result.pushKV("fetched", std::move(fetched));
    return result;
}

RPCHelpMan getbalancewatch()
{
    return RPCHelpMan{
        "getbalancewatch",
        "Returns the status of this wallet's balance watch.\n"
        "ready is false until the wallet has processed the chain tip and is not scanning.\n"
        "A false ready value is not a balance, and this result has no amount.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "ready", "True only when the chain has a tip, the wallet has processed that height, and the wallet is not scanning"},
                {RPCResult::Type::NUM, "chain_height", "Chain tip height, or -1 when the chain has no tip"},
                {RPCResult::Type::NUM, "wallet_height", "Last block height this wallet has processed, or -1 when none has been processed"},
                {RPCResult::Type::NUM, "blocks_behind", "max(0, chain_height - wallet_height) when both heights are known, otherwise 0"},
                {RPCResult::Type::BOOL, "scanning", "True when the wallet is scanning"},
                {RPCResult::Type::BOOL, "shielded_foreign_watch", "Always false. Shielded notes this wallet cannot decrypt are not watched"},
                {RPCResult::Type::ARR, "descriptors", "This wallet's own descriptor strings",
                {
                    {RPCResult::Type::STR, "", "Descriptor string"},
                }},
                {RPCResult::Type::ARR, "fetched", "Lookups whose descriptor is not already one of this wallet's descriptors, capped at 32",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "descriptor", "Descriptor string that was looked up"},
                        {RPCResult::Type::NUM, "height", "Height of the lookup"},
                    }},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getbalancewatch", "") +
            HelpExampleRpc("getbalancewatch", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
            if (!rpc_wallet) return UniValue::VNULL;
            const CWallet& wallet = *rpc_wallet;

            wallet.BlockUntilSyncedToCurrentChain();

            return BalanceWatchStatusToJSON(GetBalanceWatchStatus(wallet, wallet.chain()));
        },
    };
}

RPCHelpMan getbalanceatheight()
{
    return RPCHelpMan{
        "getbalanceatheight",
        "Returns this wallet's transparent balance at height from transactions already stored in the wallet.\n"
        "When the watch is not ready through that height, throws RPC_WALLET_ERROR with message BTX_BALANCE_NOT_READY and no amount.\n",
        {
            {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to report the balance at."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Returned only when the balance at height is known",
            {
                {RPCResult::Type::NUM, "height", "The requested height"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Transparent balance in " + CURRENCY_UNIT + " confirmed at or below this height"},
                {RPCResult::Type::BOOL, "ready", "Always true in this result"},
            }
        },
        RPCExamples{
            HelpExampleCli("getbalanceatheight", "100") +
            HelpExampleRpc("getbalanceatheight", "100")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
            if (!rpc_wallet) return UniValue::VNULL;
            const CWallet& wallet = *rpc_wallet;

            const int height{self.Arg<int>("height")};

            wallet.BlockUntilSyncedToCurrentChain();

            const BalanceAtHeightResult result{GetBalanceAtHeight(wallet, height)};
            if (!result.ready) {
                throw JSONRPCError(RPC_WALLET_ERROR, "BTX_BALANCE_NOT_READY");
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("height", height);
            out.pushKV("amount", ValueFromAmount(result.amount));
            out.pushKV("ready", true);
            return out;
        },
    };
}
} // namespace wallet
