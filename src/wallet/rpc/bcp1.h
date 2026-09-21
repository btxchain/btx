// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_RPC_BCP1_H
#define BITCOIN_WALLET_RPC_BCP1_H

//! BTX Custody Profile 1 (BCP/1) / BTX_EXCHANGE_PROFILE_V1 wallet RPCs.
//!
//! Coordinator registration (do not edit this comment out):
//!   1. Add `rpc/bcp1.cpp` to `bitcoin_wallet` in `src/wallet/CMakeLists.txt`.
//!   2. `#include <wallet/rpc/bcp1.h>` in `src/wallet/rpc/wallet.cpp`.
//!   3. Append each `{"wallet", &<fn>}` below to `GetWalletRPCCommands()`,
//!      or splice `GetBCP1WalletRPCCommands()`.
//!   4. `src/rpc/client.cpp` conversions (non-string params):
//!        deriveexchangeaddress        0 index, 1 options
//!        importdepositpool            0 entries, 1 options
//!        prepareexternalsign          0 package, 1 options
//!        getsigningdigests            0 package
//!        finalizeexternalsign         0 package, 1 signatures, 2 options
//!        getdepositstatus             1 vout
//!        listdepositutxos             0 options
//!        planconsolidation            0 options
//!        createconsolidationtx        1 options
//!        estimateconsolidationfee     0 options
//!        createexchangebatch          0 outputs, 1 options
//!
//! Neighbor TUs (not this exclusive pair):
//!   wallet/bcp1_package.h
//!     bcp1::Encode / Decode / FillCanonicalDigests / InsertSignature
//!     FromPSBT / FromUnsignedTx / ApplyToPSBT / TryExtractSignedTx
//!     PackageReadyToBroadcast / ParseAlgo / FormatAlgo
//!   wallet/bcp1_deposit.h
//!     GetDepositStatusUniValue / ListDepositUtxosUniValue / ListDepositUtxoFilter
//!   wallet/bcp1_watchonly.h
//!     ExchangeWatchOnlyActive / RefusePrivateSign / ImportDepositPool
//!     ExchangeWatchOnlyNodeEnabled / EvaluateBcp1Readiness / Bcp1Readiness::Ready
//!     WalletHasDepositMaterial / CommandSignerHealthReport
//!   wallet/signer_provider.h
//!     MakeCommandSigner / SignerProvider::GetPublicKey / Health
//!     DerivePublicKey → PUBLIC_CHILD_UNSUPPORTED
//!
//! Watch-only: WALLET_FLAG_DISABLE_PRIVATE_KEYS and/or -exchange-watchonly
//! refuse in-process dump/sign. prepare/finalize only attach external sigs.
//! None of these RPCs broadcast. automatic_spend_atoms is never invented.
//!
//! getexchangereadiness.ready is EvaluateBcp1Readiness(wallet, args).Ready():
//!   descriptors_ok && watchonly_ok && synced_ok && (deposits_ok || signer_ok)
//!   && !pkcs11_live && !kmip_live && !https_live
//! See wallet/bcp1_watchonly.h. PKCS#11 / KMIP / HTTPS are never live.

#include <span.h>

#include <rpc/util.h>

class CRPCCommand;

namespace wallet {
class CWallet;

RPCHelpMan getexchangereadiness();
RPCHelpMan deriveexchangeaddress();
RPCHelpMan importdepositpool();
RPCHelpMan prepareexternalsign();
RPCHelpMan getsigningdigests();
RPCHelpMan finalizeexternalsign();
RPCHelpMan getdepositstatus();
RPCHelpMan listdepositutxos();
RPCHelpMan planconsolidation();
RPCHelpMan createconsolidationtx();
RPCHelpMan estimateconsolidationfee();
RPCHelpMan createexchangebatch();

Span<const CRPCCommand> GetBCP1WalletRPCCommands();

bool IsBcp1WatchOnly(const CWallet& wallet);
bool NodeExchangeWatchOnly();

} // namespace wallet

#endif // BITCOIN_WALLET_RPC_BCP1_H
