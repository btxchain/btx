// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/messages.h>
#include <core_io.h>
#include <key_io.h>
#include <node/types.h>
#include <rpc/util.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

using common::TransactionErrorString;
using node::TransactionError;

namespace wallet {
namespace {

std::optional<PQAlgorithm> ParsePreferredPQSigningAlgo(const UniValue& preferred_pq_algo)
{
    if (preferred_pq_algo.isNull()) {
        return std::nullopt;
    }

    const std::string value = ToLower(preferred_pq_algo.get_str());
    if (value == "ml_dsa_44" || value == "ml-dsa-44" || value == "mldsa") {
        return PQAlgorithm::ML_DSA_44;
    }
    if (value == "slh_dsa_128s" || value == "slh-dsa-128s" || value == "slhdsa") {
        return PQAlgorithm::SLH_DSA_128S;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid preferred_pq_algo. Valid values: ml_dsa_44, slh_dsa_128s");
}

void CheckDeprecatedOptionNames(const UniValue& options)
{
    if (options.exists("preferredPQAlgo")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Use preferred_pq_algo instead of preferredPQAlgo");
    }
}

} // namespace

RPCHelpMan sweeptoself()
{
    return RPCHelpMan{
        "sweeptoself",
        "Spend all available transparent UTXOs from this wallet to a newly generated wallet-controlled address.\n"
        "This RPC is intended for batched migration operations (for example, emergency PQ leaf preference transitions).\n"
        + HELP_REQUIRING_PASSPHRASE,
        {
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"preferred_pq_algo", RPCArg::Type::STR, RPCArg::DefaultHint{"wallet default"}, "Preferred post-quantum algorithm for selecting spend leaves in P2MR scripts. Valid values: \"ml_dsa_44\", \"slh_dsa_128s\"."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Minimum confirmations for selected inputs."},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum confirmations for selected inputs."},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include unsafe unconfirmed inputs."},
                    {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected inputs after creating the transaction."},
                },
            RPCArgOptions{.oneline_description = "options"}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", "The transaction id for the sweep transaction."},
                    {RPCResult::Type::STR, "destination", "The newly generated wallet address receiving swept funds."},
                    {RPCResult::Type::NUM, "inputs_swept", "Number of inputs included in the sweep."},
                    {RPCResult::Type::STR_AMOUNT, "fee", "The fee paid by the sweep transaction."},
                }
        },
        RPCExamples{
            HelpExampleCli("sweeptoself", "") +
            HelpExampleCli("-named sweeptoself", "options='{\"preferred_pq_algo\":\"slh_dsa_128s\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue options{request.params[0].isNull() ? UniValue::VOBJ : request.params[0]};
            CheckDeprecatedOptionNames(options);

            CCoinControl coin_control;
            coin_control.m_allow_other_inputs = false;
            coin_control.m_include_unsafe_inputs = options.exists("include_unsafe") ? options["include_unsafe"].get_bool() : false;

            if (options.exists("minconf")) {
                const int minconf{options["minconf"].getInt<int>()};
                if (minconf < 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid minconf (minconf cannot be negative): %d", minconf));
                }
                coin_control.m_min_depth = minconf;
            }
            if (options.exists("maxconf")) {
                const int maxconf{options["maxconf"].getInt<int>()};
                if (maxconf < coin_control.m_min_depth) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("maxconf can't be lower than minconf: %d < %d", maxconf, coin_control.m_min_depth));
                }
                coin_control.m_max_depth = maxconf;
            }
            if (options.exists("preferred_pq_algo")) {
                coin_control.m_preferred_pq_signing_algo = ParsePreferredPQSigningAlgo(options["preferred_pq_algo"]);
            }
            if (options.exists("fee_rate")) {
                coin_control.m_feerate = CFeeRate{AmountFromValue(options["fee_rate"], /*decimals=*/3)};
                // Mirror explicit fee_rate behavior from send/sendall.
                coin_control.m_signal_bip125_rbf = true;
            }

            std::vector<COutPoint> selected_inputs;
            CAmount total_input_value{0};
            {
                LOCK(pwallet->cs_wallet);
                CoinFilterParams params;
                params.min_amount = 0;
                for (const COutput& output : AvailableCoins(*pwallet, &coin_control, coin_control.m_feerate, params).All()) {
                    selected_inputs.push_back(output.outpoint);
                    coin_control.Select(output.outpoint);
                    total_input_value += output.txout.nValue;
                }
            }

            if (selected_inputs.empty() || total_input_value <= 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No spendable UTXOs available for sweep");
            }

            const auto destination_result = pwallet->GetNewDestination(OutputType::P2MR, /*label=*/"");
            if (!destination_result) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(destination_result).original);
            }

            EnsureWalletIsUnlocked(*pwallet);

            std::vector<CRecipient> recipients;
            recipients.emplace_back();
            recipients.back().dest = *destination_result;
            recipients.back().nAmount = total_input_value;
            recipients.back().fSubtractFeeFromAmount = true;

            CreatedTransactionResult tx_result_val = [&] {
                LOCK(pwallet->cs_wallet);
                auto tx_result = CreateTransaction(*pwallet, recipients, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
                if (!tx_result) {
                    throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(tx_result).original);
                }

                if (tx_result->fee > pwallet->m_default_max_tx_fee) {
                    throw JSONRPCError(RPC_WALLET_ERROR, TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
                }

                const bool lock_unspents{options.exists("lock_unspents") && options["lock_unspents"].get_bool()};
                if (lock_unspents) {
                    for (const auto& outpoint : selected_inputs) {
                        pwallet->LockCoin(outpoint);
                    }
                }
                return *tx_result;
            }();
            pwallet->CommitTransaction(tx_result_val.tx, {}, /*orderForm=*/{});

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx_result_val.tx->GetHash().GetHex());
            result.pushKV("destination", EncodeDestination(*destination_result));
            result.pushKV("inputs_swept", static_cast<int>(selected_inputs.size()));
            result.pushKV("fee", ValueFromAmount(tx_result_val.fee));
            return result;
        }
    };
}

} // namespace wallet
