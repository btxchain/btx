// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signmessage.h>
#include <key_io.h>
#include <rpc/util.h>
#include <wallet/bcp1_watchonly.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
RPCHelpMan signmessage()
{
    return RPCHelpMan{"signmessage",
        "\nSign a message with the private key of a P2MR address (BIP-322 SIMPLE).\n"
        "Legacy P2PKH/P2WPKH ECDSA compact signatures are disabled." +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The P2MR address to use for the private key."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The BIP-322 SIMPLE signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"" + EXAMPLE_ADDRESS[0] + "\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"" + EXAMPLE_ADDRESS[0] + "\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"" + EXAMPLE_ADDRESS[0] + "\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // In-process only: no FillPSBT / -signer path. BCP/1 watch-only
            // gets the same policy error as send / signrawtransactionwithwallet
            // / dump*. Leftover keys on disable_private_keys wallets must not
            // reach SignMessage either.
            bilingual_str refuse_err;
            if (RefusePrivateSign(*pwallet, refuse_err)) {
                throw JSONRPCError(RPC_WALLET_ERROR, refuse_err.original);
            }
            if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
            }

            LOCK(pwallet->cs_wallet);

            EnsureWalletIsUnlocked(*pwallet);

            std::string strAddress = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            CTxDestination dest = DecodeDestination(strAddress);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            if (!std::holds_alternative<WitnessV2P2MR>(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "BTX PQ policy: message signing requires a P2MR address; legacy P2PKH/P2WPKH ECDSA is disabled");
            }

            std::string signature;
            SigningResult err = pwallet->SignMessage(MessageSignatureFormat::SIMPLE, strMessage, dest, signature);
            if (err == SigningResult::SIGNING_FAILED) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
            } else if (err != SigningResult::OK) {
                throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
            }

            return signature;
        },
    };
}
} // namespace wallet
