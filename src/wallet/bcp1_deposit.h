// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_BCP1_DEPOSIT_H
#define BITCOIN_WALLET_BCP1_DEPOSIT_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <univalue.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {

/**
 * BTX Custody Profile 1 (BCP/1) deposit / UTXO helpers.
 *
 * Wallet RPC getdepositstatus / listdepositutxos should call the UniValue
 * entry points below after BlockUntilSyncedToCurrentChain() and
 * LOCK(wallet.cs_wallet). These helpers never claim irreversible finality:
 * confirmations is PoW depth on the active chain (1 = included in a connected
 * block). There is no deposit.finalized event.
 *
 * Existing ZMQ topics (do not add new notifier names; tests bind the current
 * strings) map to BCP/1 chain events as:
 *
 *   hashblock / rawblock / sequence 'C'  -> block.connected
 *   sequence 'D'                         -> block.disconnected
 *   hashtx / rawtx / sequence 'A'        -> transaction.mempool
 *   hashwallettx-mempool / rawwallettx-mempool -> transaction.mempool
 *   hashwallettx-block / rawwallettx-block     -> transaction.confirmed
 *
 * Wallet-level deposit.detected, deposit.confirmations_changed, utxo.created,
 * and utxo.spent are not ZMQ topics. Emit them with EmitDepositEvent via
 * NotificationInterface (CWallet::NotifyTransactionChanged) or -walletnotify.
 * Kernel DisconnectedBlockTransactions is validation-local and is not a
 * queryable store after a reorg; use NoteBlockDisconnected plus wallet TxState.
 */

inline constexpr std::string_view BCP1_PROFILE_ID{"BTX_EXCHANGE_PROFILE_V1"};
inline constexpr std::string_view BCP1_CHAIN_ID{"BTX"};

enum class DepositStatus {
    MEMPOOL,
    CONFIRMED,
    REORGED,
    CONFLICTED,
    SPENT,
    UNKNOWN,
};

enum class DepositEventType {
    BlockConnected,
    BlockDisconnected,
    TransactionMempool,
    TransactionConfirmed,
    TransactionReorged,
    DepositDetected,
    DepositConfirmationsChanged,
    UtxoCreated,
    UtxoSpent,
};

enum class UtxoLifecycle {
    Created,
    Spent,
    Unknown,
};

struct DepositStatusResult {
    DepositStatus status{DepositStatus::UNKNOWN};
    std::string chain{BCP1_CHAIN_ID};
    std::string network;
    uint256 txid;
    uint32_t vout{0};
    std::string address;
    CAmount amount_atoms{0};
    uint256 block_hash;
    int block_height{-1};
    int confirmations{0};
    bool in_mempool{false};
    bool is_mine{false};
    bool is_change{false};
    bool is_coinbase{false};
    bool locked{false};
    uint256 previous_block_hash;
    int previous_block_height{-1};
    uint256 spent_by;
};

struct ListDepositUtxoFilter {
    int min_confirmations{0};
    int max_confirmations{std::numeric_limits<int>::max()};
    CAmount min_amount{0};
    CAmount max_amount{MAX_MONEY};
    bool include_spent{false};
    bool include_change{false};
    bool include_immature_coinbase{false};
    bool include_conflicted{false};
    std::vector<std::string> addresses;
};

/** "BTX". */
std::string Bcp1ChainName();
/** Params().GetChainTypeString() (main, test, regtest, …). */
std::string Bcp1NetworkName();

std::string DepositStatusToString(DepositStatus status);
std::optional<DepositStatus> DepositStatusFromString(std::string_view name);
std::string DepositEventTypeToString(DepositEventType type);
std::optional<DepositEventType> DepositEventTypeFromString(std::string_view name);
std::string UtxoLifecycleToString(UtxoLifecycle state);

/** Map an existing ZMQ topic (or "sequence:C" / "sequence:D" / "sequence:A") to a BCP/1 event name. Empty if none. */
std::string_view Bcp1EventForZmqTopic(std::string_view zmq_topic);

bool IsWalletDepositOutput(const CWallet& wallet, const CTxOut& txout, bool include_change)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/**
 * Primary getdepositstatus helper. 1 confirmation = the deposit tx is in a
 * block connected to the active chain tip (depth 1). Reorg back to mempool
 * is REORGED, not MEMPOOL, when this process previously observed the confirming
 * block or NoteBlockDisconnected was called.
 */
DepositStatusResult GetDepositStatus(const CWallet& wallet, const uint256& txid, uint32_t vout)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
DepositStatusResult GetDepositStatus(const CWallet& wallet, const COutPoint& outpoint)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** RPC getdepositstatus(txid, vout) should return this object. */
UniValue GetDepositStatusUniValue(const CWallet& wallet, const uint256& txid, uint32_t vout)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

UtxoLifecycle GetUtxoLifecycle(const CWallet& wallet, const uint256& txid, uint32_t vout)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

std::vector<DepositStatusResult> ListDepositUtxos(const CWallet& wallet, const ListDepositUtxoFilter& filter = {})
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** RPC listdepositutxos should return this array. */
UniValue ListDepositUtxosUniValue(const CWallet& wallet, const ListDepositUtxoFilter& filter = {})
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

UniValue DepositStatusToUniValue(const DepositStatusResult& result, bool include_utxo_fields = false);

/** Test / NotificationInterface JSON. Never emits deposit.finalized. */
UniValue EmitDepositEvent(DepositEventType type, const DepositStatusResult& snapshot);
UniValue EmitChainEvent(DepositEventType type, const uint256& block_hash, int block_height);

std::vector<DepositEventType> EventsForDepositTransition(const std::optional<DepositStatusResult>& previous,
                                                         const DepositStatusResult& now);

/**
 * Call from tests or a future NotificationInterface adapter when a block is
 * disconnected. Marks cached (and optional explicit) txids as REORGED until
 * they are observed CONFIRMED on the active chain again.
 */
void NoteBlockDisconnected(const CWallet& wallet, const uint256& block_hash, int height);
void NoteBlockDisconnected(const CWallet& wallet, const uint256& block_hash, int height,
                          const std::vector<uint256>& txids);
void NoteBlockConnected(const CWallet& wallet, const uint256& block_hash, int height,
                        const std::vector<uint256>& txids);

void ForgetWalletDepositObservations(const CWallet& wallet);
void ResetDepositObservationCache();

/** JSON events for -walletdepositnotify. Empty when the tx has no wallet deposits. */
std::vector<UniValue> DepositNotifyEventsForTx(const CWallet& wallet, const uint256& txid, bool inserted_new)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

} // namespace wallet

#endif // BITCOIN_WALLET_BCP1_DEPOSIT_H
