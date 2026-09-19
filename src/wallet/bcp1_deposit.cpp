// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/bcp1_deposit.h>

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <key_io.h>
#include <sync.h>
#include <wallet/receive.h>
#include <wallet/transaction.h>

#include <algorithm>
#include <map>
#include <utility>

namespace wallet {
namespace {

GlobalMutex g_bcp1_deposit_cache_mutex;

struct DepositObservation {
    uint256 last_confirmed_block;
    int last_confirmed_height{-1};
    int last_confirmations{0};
    bool saw_disconnect{false};
};

struct DepositCacheKey {
    const CWallet* wallet{nullptr};
    uint256 txid;

    friend bool operator<(const DepositCacheKey& a, const DepositCacheKey& b)
    {
        if (a.wallet != b.wallet) return a.wallet < b.wallet;
        return a.txid < b.txid;
    }
};

std::map<DepositCacheKey, DepositObservation> g_deposit_obs GUARDED_BY(g_bcp1_deposit_cache_mutex);

[[nodiscard]] DepositCacheKey MakeKey(const CWallet& wallet, const uint256& txid)
{
    return DepositCacheKey{&wallet, txid};
}

void RememberConfirmed(const CWallet& wallet, const uint256& txid, const uint256& block_hash, int height, int confirmations)
    EXCLUSIVE_LOCKS_REQUIRED(g_bcp1_deposit_cache_mutex)
{
    if (block_hash.IsNull() || height < 0) return;
    DepositObservation& obs = g_deposit_obs[MakeKey(wallet, txid)];
    obs.last_confirmed_block = block_hash;
    obs.last_confirmed_height = height;
    obs.last_confirmations = confirmations;
    obs.saw_disconnect = false;
}

void RememberDisconnect(const CWallet& wallet, const uint256& txid, const uint256& block_hash, int height)
    EXCLUSIVE_LOCKS_REQUIRED(g_bcp1_deposit_cache_mutex)
{
    DepositObservation& obs = g_deposit_obs[MakeKey(wallet, txid)];
    if (obs.last_confirmed_block.IsNull() && !block_hash.IsNull()) {
        obs.last_confirmed_block = block_hash;
        obs.last_confirmed_height = height;
    }
    obs.saw_disconnect = true;
}

[[nodiscard]] bool LookupObservation(const CWallet& wallet, const uint256& txid, DepositObservation& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_bcp1_deposit_cache_mutex)
{
    const auto it = g_deposit_obs.find(MakeKey(wallet, txid));
    if (it == g_deposit_obs.end()) return false;
    out = it->second;
    return true;
}

[[nodiscard]] bool BlockIsOnActiveChain(const CWallet& wallet, const uint256& block_hash)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (block_hash.IsNull() || !wallet.HaveChain()) return false;
    bool in_active = false;
    if (!wallet.chain().findBlock(block_hash, interfaces::FoundBlock().inActiveChain(in_active))) {
        return false;
    }
    return in_active;
}

[[nodiscard]] bool CoinIsPresentInChainView(const CWallet& wallet, const COutPoint& outpoint)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!wallet.HaveChain()) return false;
    std::map<COutPoint, Coin> coins;
    coins.emplace(outpoint, Coin{});
    wallet.chain().findCoins(coins);
    return !coins.at(outpoint).IsSpent();
}

[[nodiscard]] std::optional<uint256> FindWalletSpender(const CWallet& wallet, const COutPoint& outpoint)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::optional<uint256> spent_by;
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        if (wtx.isAbandoned() || wtx.isBlockConflicted() || wtx.isMempoolConflicted()) {
            continue;
        }
        for (const CTxIn& vin : wtx.tx->vin) {
            if (vin.prevout != outpoint) continue;
            spent_by = txid;
            if (wtx.isConfirmed()) return spent_by;
        }
    }
    return spent_by;
}

void FillIdentity(DepositStatusResult& result)
{
    result.chain = Bcp1ChainName();
    result.network = Bcp1NetworkName();
}

void FillOutputFields(const CWallet& wallet, const CWalletTx& wtx, uint32_t vout, DepositStatusResult& result)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (vout >= wtx.tx->vout.size()) return;
    const CTxOut& txout = wtx.tx->vout[vout];
    result.amount_atoms = txout.nValue;
    result.is_mine = static_cast<bool>(wallet.IsMine(txout) & ISMINE_ALL);
    result.is_change = OutputIsChange(wallet, txout);
    result.is_coinbase = wtx.IsCoinBase();
    result.locked = wallet.IsLockedCoin(COutPoint{Txid::FromUint256(result.txid), vout});
    CTxDestination dest;
    if (ExtractDestination(txout.scriptPubKey, dest) && IsValidDestination(dest)) {
        result.address = EncodeDestination(dest);
    }
}

[[nodiscard]] bool AddressAllowed(const ListDepositUtxoFilter& filter, const std::string& address)
{
    if (filter.addresses.empty()) return true;
    return std::find(filter.addresses.begin(), filter.addresses.end(), address) != filter.addresses.end();
}

} // namespace

std::string Bcp1ChainName()
{
    return std::string{BCP1_CHAIN_ID};
}

std::string Bcp1NetworkName()
{
    return Params().GetChainTypeString();
}

std::string DepositStatusToString(DepositStatus status)
{
    switch (status) {
    case DepositStatus::MEMPOOL: return "MEMPOOL";
    case DepositStatus::CONFIRMED: return "CONFIRMED";
    case DepositStatus::REORGED: return "REORGED";
    case DepositStatus::CONFLICTED: return "CONFLICTED";
    case DepositStatus::SPENT: return "SPENT";
    case DepositStatus::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::optional<DepositStatus> DepositStatusFromString(std::string_view name)
{
    if (name == "MEMPOOL") return DepositStatus::MEMPOOL;
    if (name == "CONFIRMED") return DepositStatus::CONFIRMED;
    if (name == "REORGED") return DepositStatus::REORGED;
    if (name == "CONFLICTED") return DepositStatus::CONFLICTED;
    if (name == "SPENT") return DepositStatus::SPENT;
    if (name == "UNKNOWN") return DepositStatus::UNKNOWN;
    return std::nullopt;
}

std::string DepositEventTypeToString(DepositEventType type)
{
    switch (type) {
    case DepositEventType::BlockConnected: return "block.connected";
    case DepositEventType::BlockDisconnected: return "block.disconnected";
    case DepositEventType::TransactionMempool: return "transaction.mempool";
    case DepositEventType::TransactionConfirmed: return "transaction.confirmed";
    case DepositEventType::TransactionReorged: return "transaction.reorged";
    case DepositEventType::DepositDetected: return "deposit.detected";
    case DepositEventType::DepositConfirmationsChanged: return "deposit.confirmations_changed";
    case DepositEventType::UtxoCreated: return "utxo.created";
    case DepositEventType::UtxoSpent: return "utxo.spent";
    }
    return {};
}

std::optional<DepositEventType> DepositEventTypeFromString(std::string_view name)
{
    if (name == "block.connected") return DepositEventType::BlockConnected;
    if (name == "block.disconnected") return DepositEventType::BlockDisconnected;
    if (name == "transaction.mempool") return DepositEventType::TransactionMempool;
    if (name == "transaction.confirmed") return DepositEventType::TransactionConfirmed;
    if (name == "transaction.reorged") return DepositEventType::TransactionReorged;
    if (name == "deposit.detected") return DepositEventType::DepositDetected;
    if (name == "deposit.confirmations_changed") return DepositEventType::DepositConfirmationsChanged;
    if (name == "utxo.created") return DepositEventType::UtxoCreated;
    if (name == "utxo.spent") return DepositEventType::UtxoSpent;
    return std::nullopt;
}

std::string UtxoLifecycleToString(UtxoLifecycle state)
{
    switch (state) {
    case UtxoLifecycle::Created: return "CREATED";
    case UtxoLifecycle::Spent: return "SPENT";
    case UtxoLifecycle::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::string_view Bcp1EventForZmqTopic(std::string_view zmq_topic)
{
    if (zmq_topic == "hashblock" || zmq_topic == "rawblock" || zmq_topic == "sequence:C") {
        return "block.connected";
    }
    if (zmq_topic == "sequence:D") {
        return "block.disconnected";
    }
    if (zmq_topic == "hashtx" || zmq_topic == "rawtx" || zmq_topic == "sequence:A" ||
        zmq_topic == "hashwallettx-mempool" || zmq_topic == "rawwallettx-mempool") {
        return "transaction.mempool";
    }
    if (zmq_topic == "hashwallettx-block" || zmq_topic == "rawwallettx-block") {
        return "transaction.confirmed";
    }
    return {};
}

bool IsWalletDepositOutput(const CWallet& wallet, const CTxOut& txout, bool include_change)
{
    AssertLockHeld(wallet.cs_wallet);
    if (!(wallet.IsMine(txout) & ISMINE_ALL)) return false;
    if (!include_change && OutputIsChange(wallet, txout)) return false;
    return true;
}

DepositStatusResult GetDepositStatus(const CWallet& wallet, const COutPoint& outpoint)
{
    AssertLockHeld(wallet.cs_wallet);
    return GetDepositStatus(wallet, outpoint.hash.ToUint256(), outpoint.n);
}

DepositStatusResult GetDepositStatus(const CWallet& wallet, const uint256& txid, uint32_t vout)
{
    AssertLockHeld(wallet.cs_wallet);

    DepositStatusResult result;
    FillIdentity(result);
    result.txid = txid;
    result.vout = vout;

    const CWalletTx* wtx = wallet.GetWalletTx(txid);
    if (!wtx || vout >= wtx->tx->vout.size()) {
        result.status = DepositStatus::UNKNOWN;
        return result;
    }

    FillOutputFields(wallet, *wtx, vout, result);
    if (!result.is_mine) {
        result.status = DepositStatus::UNKNOWN;
        return result;
    }

    const COutPoint outpoint{Txid::FromUint256(txid), vout};
    const int depth = wallet.GetTxDepthInMainChain(*wtx);
    const bool block_conflicted = wtx->isBlockConflicted();
    const bool mempool_conflicted = wtx->isMempoolConflicted();
    const bool conflicted = block_conflicted || mempool_conflicted;
    const bool confirmed = wtx->isConfirmed() && depth >= 1;
    const bool in_mempool = !confirmed && (wtx->InMempool() || (wallet.HaveChain() && wallet.chain().isInMempool(txid)));
    result.in_mempool = in_mempool;

    if (auto* conf = wtx->state<TxStateConfirmed>()) {
        result.block_hash = conf->confirmed_block_hash;
        result.block_height = conf->confirmed_block_height;
        result.confirmations = depth;
    } else if (auto* conflict = wtx->state<TxStateBlockConflicted>()) {
        result.block_hash = conflict->conflicting_block_hash;
        result.block_height = conflict->conflicting_block_height;
        result.confirmations = depth;
    } else {
        result.confirmations = 0;
    }

    DepositObservation obs;
    bool have_obs = false;
    {
        LOCK(g_bcp1_deposit_cache_mutex);
        have_obs = LookupObservation(wallet, txid, obs);
        if (confirmed) {
            RememberConfirmed(wallet, txid, result.block_hash, result.block_height, result.confirmations);
            have_obs = LookupObservation(wallet, txid, obs);
        }
    }
    if (have_obs) {
        result.previous_block_hash = obs.last_confirmed_block;
        result.previous_block_height = obs.last_confirmed_height;
    }

    const bool saw_disconnect = have_obs && obs.saw_disconnect && !confirmed;
    const bool lost_confirming_block = have_obs && !obs.last_confirmed_block.IsNull() &&
                                        !confirmed && !BlockIsOnActiveChain(wallet, obs.last_confirmed_block);
    // Wallet records a disconnect height only on an actual blockDisconnected (or
    // a load-time reorg of the wallet's best block). Mempool eviction does not.
    const bool inactive_after_disconnect = wtx->isInactive() && !wtx->isAbandoned() &&
                                           !in_mempool && !conflicted &&
                                           wallet.GetLastReorgDisconnectedHeight() >= 0;
    const bool coinbase_disconnected = wtx->IsCoinBase() && wtx->isAbandoned() && !confirmed;
    const bool reorged = saw_disconnect || lost_confirming_block || inactive_after_disconnect || coinbase_disconnected;

    if (conflicted && !confirmed) {
        result.status = DepositStatus::CONFLICTED;
        return result;
    }

    const bool wallet_spent = wallet.IsSpent(outpoint);
    const bool parent_present = confirmed || in_mempool;
    const bool spent_in_chain_view = wallet.HaveChain() && parent_present && !CoinIsPresentInChainView(wallet, outpoint);
    if (wallet_spent || spent_in_chain_view) {
        result.status = DepositStatus::SPENT;
        if (const auto spent_by = FindWalletSpender(wallet, outpoint)) {
            result.spent_by = *spent_by;
        }
        return result;
    }

    if (confirmed) {
        result.status = DepositStatus::CONFIRMED;
        return result;
    }

    if (reorged) {
        result.status = DepositStatus::REORGED;
        result.confirmations = 0;
        if (result.block_hash.IsNull() && have_obs) {
            result.block_hash = obs.last_confirmed_block;
            result.block_height = obs.last_confirmed_height;
        }
        return result;
    }

    if (in_mempool) {
        result.status = DepositStatus::MEMPOOL;
        result.confirmations = 0;
        return result;
    }

    result.status = DepositStatus::UNKNOWN;
    return result;
}

UniValue GetDepositStatusUniValue(const CWallet& wallet, const uint256& txid, uint32_t vout)
{
    AssertLockHeld(wallet.cs_wallet);
    return DepositStatusToUniValue(GetDepositStatus(wallet, txid, vout), /*include_utxo_fields=*/false);
}

UtxoLifecycle GetUtxoLifecycle(const CWallet& wallet, const uint256& txid, uint32_t vout)
{
    AssertLockHeld(wallet.cs_wallet);
    switch (GetDepositStatus(wallet, txid, vout).status) {
    case DepositStatus::SPENT:
        return UtxoLifecycle::Spent;
    case DepositStatus::MEMPOOL:
    case DepositStatus::CONFIRMED:
    case DepositStatus::REORGED:
        return UtxoLifecycle::Created;
    case DepositStatus::CONFLICTED:
    case DepositStatus::UNKNOWN:
        return UtxoLifecycle::Unknown;
    }
    return UtxoLifecycle::Unknown;
}

std::vector<DepositStatusResult> ListDepositUtxos(const CWallet& wallet, const ListDepositUtxoFilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);

    std::vector<DepositStatusResult> out;
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        if (!filter.include_immature_coinbase && wallet.IsTxImmatureCoinBase(wtx)) {
            continue;
        }
        for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
            if (!IsWalletDepositOutput(wallet, wtx.tx->vout[n], filter.include_change)) {
                continue;
            }
            DepositStatusResult item = GetDepositStatus(wallet, txid, n);
            if (item.status == DepositStatus::UNKNOWN) continue;
            if (item.status == DepositStatus::CONFLICTED && !filter.include_conflicted) continue;
            if (item.status == DepositStatus::SPENT && !filter.include_spent) continue;
            if (item.confirmations < filter.min_confirmations) continue;
            if (item.confirmations > filter.max_confirmations) continue;
            if (item.amount_atoms < filter.min_amount) continue;
            if (item.amount_atoms > filter.max_amount) continue;
            if (!AddressAllowed(filter, item.address)) continue;
            out.push_back(std::move(item));
        }
    }
    std::sort(out.begin(), out.end(), [](const DepositStatusResult& a, const DepositStatusResult& b) {
        if (a.txid != b.txid) return a.txid < b.txid;
        return a.vout < b.vout;
    });
    return out;
}

UniValue ListDepositUtxosUniValue(const CWallet& wallet, const ListDepositUtxoFilter& filter)
{
    AssertLockHeld(wallet.cs_wallet);
    UniValue arr(UniValue::VARR);
    for (const DepositStatusResult& item : ListDepositUtxos(wallet, filter)) {
        arr.push_back(DepositStatusToUniValue(item, /*include_utxo_fields=*/true));
    }
    return arr;
}

UniValue DepositStatusToUniValue(const DepositStatusResult& result, bool include_utxo_fields)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", result.chain);
    obj.pushKV("network", result.network);
    obj.pushKV("txid", result.txid.GetHex());
    obj.pushKV("vout", static_cast<int64_t>(result.vout));
    obj.pushKV("address", result.address);
    obj.pushKV("amount_atoms", result.amount_atoms);
    obj.pushKV("block_hash", result.block_hash.IsNull() ? std::string{} : result.block_hash.GetHex());
    obj.pushKV("block_height", result.block_height);
    obj.pushKV("confirmations", result.confirmations);
    obj.pushKV("status", DepositStatusToString(result.status));
    if (include_utxo_fields) {
        obj.pushKV("in_mempool", result.in_mempool);
        obj.pushKV("is_change", result.is_change);
        obj.pushKV("is_coinbase", result.is_coinbase);
        obj.pushKV("locked", result.locked);
        if (!result.spent_by.IsNull()) {
            obj.pushKV("spent_by", result.spent_by.GetHex());
        }
        if (!result.previous_block_hash.IsNull()) {
            obj.pushKV("previous_block_hash", result.previous_block_hash.GetHex());
            obj.pushKV("previous_block_height", result.previous_block_height);
        }
    }
    return obj;
}

UniValue EmitDepositEvent(DepositEventType type, const DepositStatusResult& snapshot)
{
    UniValue obj = DepositStatusToUniValue(snapshot, /*include_utxo_fields=*/true);
    obj.pushKV("event", DepositEventTypeToString(type));
    obj.pushKV("profile", std::string{BCP1_PROFILE_ID});
    return obj;
}

UniValue EmitChainEvent(DepositEventType type, const uint256& block_hash, int block_height)
{
    DepositStatusResult snapshot;
    FillIdentity(snapshot);
    snapshot.block_hash = block_hash;
    snapshot.block_height = block_height;
    return EmitDepositEvent(type, snapshot);
}

std::vector<DepositEventType> EventsForDepositTransition(const std::optional<DepositStatusResult>& previous,
                                                         const DepositStatusResult& now)
{
    std::vector<DepositEventType> events;
    const bool now_visible = now.status == DepositStatus::MEMPOOL ||
                              now.status == DepositStatus::CONFIRMED ||
                              now.status == DepositStatus::REORGED;
    const bool now_unspent = now_visible;
    const bool was_unspent = previous && (previous->status == DepositStatus::MEMPOOL ||
                                         previous->status == DepositStatus::CONFIRMED ||
                                         previous->status == DepositStatus::REORGED);

    if (!previous && now_visible) {
        events.push_back(DepositEventType::DepositDetected);
        events.push_back(DepositEventType::UtxoCreated);
        if (now.status == DepositStatus::MEMPOOL || now.status == DepositStatus::REORGED) {
            events.push_back(DepositEventType::TransactionMempool);
        }
        if (now.status == DepositStatus::CONFIRMED) {
            events.push_back(DepositEventType::TransactionConfirmed);
        }
        if (now.status == DepositStatus::REORGED) {
            events.push_back(DepositEventType::TransactionReorged);
        }
        return events;
    }
    if (!previous && now.status == DepositStatus::SPENT) {
        events.push_back(DepositEventType::UtxoSpent);
        return events;
    }

    if (previous && previous->status != now.status) {
        if (now.status == DepositStatus::CONFIRMED) {
            events.push_back(DepositEventType::TransactionConfirmed);
        } else if (now.status == DepositStatus::REORGED) {
            events.push_back(DepositEventType::TransactionReorged);
        } else if (now.status == DepositStatus::MEMPOOL) {
            events.push_back(DepositEventType::TransactionMempool);
        } else if (now.status == DepositStatus::SPENT && was_unspent) {
            events.push_back(DepositEventType::UtxoSpent);
        }
    }

    if (previous && now_unspent && previous->confirmations != now.confirmations) {
        events.push_back(DepositEventType::DepositConfirmationsChanged);
    }
    if (was_unspent && now.status == DepositStatus::SPENT &&
        std::find(events.begin(), events.end(), DepositEventType::UtxoSpent) == events.end()) {
        events.push_back(DepositEventType::UtxoSpent);
    }
    return events;
}

void NoteBlockDisconnected(const CWallet& wallet, const uint256& block_hash, int height)
{
    NoteBlockDisconnected(wallet, block_hash, height, {});
}

void NoteBlockDisconnected(const CWallet& wallet, const uint256& block_hash, int height,
                            const std::vector<uint256>& txids)
{
    LOCK(g_bcp1_deposit_cache_mutex);
    for (auto& [key, obs] : g_deposit_obs) {
        if (key.wallet != &wallet) continue;
        if (!block_hash.IsNull() && obs.last_confirmed_block == block_hash) {
            obs.saw_disconnect = true;
        } else if (height >= 0 && obs.last_confirmed_height == height) {
            obs.saw_disconnect = true;
        }
    }
    for (const uint256& txid : txids) {
        RememberDisconnect(wallet, txid, block_hash, height);
    }
}

void NoteBlockConnected(const CWallet& wallet, const uint256& block_hash, int height,
                        const std::vector<uint256>& txids)
{
    LOCK(g_bcp1_deposit_cache_mutex);
    for (const uint256& txid : txids) {
        RememberConfirmed(wallet, txid, block_hash, height, /*confirmations=*/1);
    }
}

void ForgetWalletDepositObservations(const CWallet& wallet)
{
    LOCK(g_bcp1_deposit_cache_mutex);
    for (auto it = g_deposit_obs.begin(); it != g_deposit_obs.end();) {
        if (it->first.wallet == &wallet) {
            it = g_deposit_obs.erase(it);
        } else {
            ++it;
        }
    }
}

void ResetDepositObservationCache()
{
    LOCK(g_bcp1_deposit_cache_mutex);
    g_deposit_obs.clear();
}

std::vector<UniValue> DepositNotifyEventsForTx(const CWallet& wallet, const uint256& txid, bool inserted_new)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<UniValue> out;
    const CWalletTx* wtx = wallet.GetWalletTx(txid);
    if (!wtx || !wtx->tx) return out;
    for (uint32_t n = 0; n < wtx->tx->vout.size(); ++n) {
        if (!(wallet.IsMine(wtx->tx->vout[n]) & ISMINE_ALL)) continue;
        const DepositStatusResult now = GetDepositStatus(wallet, txid, n);
        if (now.status == DepositStatus::UNKNOWN) continue;
        std::optional<DepositStatusResult> previous;
        if (!inserted_new) {
            DepositObservation obs;
            LOCK(g_bcp1_deposit_cache_mutex);
            if (LookupObservation(wallet, txid, obs) && obs.last_confirmations > 0) {
                previous = now;
                previous->confirmations = obs.last_confirmations;
                previous->status = obs.saw_disconnect ? DepositStatus::REORGED : DepositStatus::CONFIRMED;
            }
        }
        for (const DepositEventType type : EventsForDepositTransition(previous, now)) {
            out.push_back(EmitDepositEvent(type, now));
        }
    }
    return out;
}

} // namespace wallet
