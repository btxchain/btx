// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/balance_watch.h>

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace wallet {
namespace {

//! Lookups remembered for descriptors this wallet does not already have.
static constexpr std::size_t MAX_BALANCE_WATCH_FETCHES = 32;

struct BalanceWatchFetchBook {
    Mutex mu;
    std::map<std::string, std::vector<BalanceWatchMiss>> by_wallet GUARDED_BY(mu);
};

BalanceWatchFetchBook& FetchBook()
{
    static BalanceWatchFetchBook book;
    return book;
}

std::optional<int> ConfirmedHeight(const CWalletTx& wtx)
{
    const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>();
    if (!confirmed || confirmed->confirmed_block_height < 0) return std::nullopt;
    return confirmed->confirmed_block_height;
}

//! Same maturity rule as CWallet::GetTxBlocksToMaturity, with `at_height` as the tip.
bool ImmatureCoinBaseAt(const CWalletTx& wtx, int confirmed_height, int at_height)
{
    if (!wtx.IsCoinBase()) return false;
    const int64_t depth = static_cast<int64_t>(at_height) - static_cast<int64_t>(confirmed_height) + 1;
    return depth < static_cast<int64_t>(COINBASE_MATURITY) + 1;
}

//! Public descriptor strings already installed on this wallet. Does not derive
//! or create keys. Legacy script managers contribute nothing.
std::vector<std::string> WalletOwnDescriptors(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<std::string> descriptors;
    for (ScriptPubKeyMan* spk_man : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (!desc_spk_man) continue;
        std::string descriptor;
        // priv=false is the normalized public form used by listdescriptors.
        if (!desc_spk_man->GetDescriptorString(descriptor, /*priv=*/false)) continue;
        if (descriptor.empty()) continue;
        descriptors.push_back(std::move(descriptor));
    }
    std::sort(descriptors.begin(), descriptors.end());
    descriptors.erase(std::unique(descriptors.begin(), descriptors.end()), descriptors.end());
    return descriptors;
}

bool DescriptorIsOwned(const std::vector<std::string>& owned, const std::string& descriptor)
{
    return std::binary_search(owned.begin(), owned.end(), descriptor);
}

//! Outputs confirmed at or below `height` that GetBalance would count as
//! m_mine_trusted, judged at that height instead of the live tip.
CAmount MineTrustedAtHeight(const CWallet& wallet, int height) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // GetBalance(..., avoid_reuse=true) passes ISMINE_SPENDABLE without ISMINE_USED,
    // so reused destinations are skipped only when WALLET_FLAG_AVOID_REUSE is set.
    const bool allow_used_addresses = !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    std::set<COutPoint> spent_at_height;
    for (const auto& entry : wallet.mapWallet) {
        const CWalletTx& wtx = entry.second;
        const std::optional<int> confirmed = ConfirmedHeight(wtx);
        if (!confirmed || *confirmed > height) continue;
        for (const CTxIn& txin : wtx.tx->vin) {
            if (txin.prevout.IsNull()) continue;
            spent_at_height.insert(txin.prevout);
        }
    }

    CAmount amount{0};
    for (const auto& entry : wallet.mapWallet) {
        const CWalletTx& wtx = entry.second;
        const std::optional<int> confirmed = ConfirmedHeight(wtx);
        if (!confirmed || *confirmed > height) continue;
        if (ImmatureCoinBaseAt(wtx, *confirmed, height)) continue;

        const Txid txid = wtx.GetHash();
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            const CTxOut& txout = wtx.tx->vout[i];
            // m_mine_trusted, not the watch-only bucket.
            if ((wallet.IsMine(txout) & ISMINE_SPENDABLE) == 0) continue;
            if (!allow_used_addresses && wallet.IsSpentKey(txout.scriptPubKey)) continue;
            if (spent_at_height.count(COutPoint(txid, i)) != 0) continue;
            if (!MoneyRange(txout.nValue)) {
                throw std::runtime_error(std::string(__func__) + ": value out of range");
            }
            amount += txout.nValue;
            if (!MoneyRange(amount)) {
                throw std::runtime_error(std::string(__func__) + ": value out of range");
            }
        }
    }
    return amount;
}

} // namespace

BalanceWatchStatus GetBalanceWatchStatus(const CWallet& wallet, const interfaces::Chain& chain)
{
    BalanceWatchStatus status;
    // Chain::getHeight is logically const; the interface method is not marked const.
    const std::optional<int> tip = const_cast<interfaces::Chain&>(chain).getHeight();

    {
        LOCK(wallet.cs_wallet);
        status.wallet_height = wallet.GetLastBlockProcessedHeight();
        status.scanning = wallet.IsScanning();
        status.descriptors = WalletOwnDescriptors(wallet);
    }

    if (tip.has_value()) {
        status.chain_height = *tip;
        if (status.wallet_height >= 0) {
            status.blocks_behind = std::max(0, *tip - status.wallet_height);
        }
        status.ready = status.wallet_height >= *tip && !status.scanning;
    }
    status.shielded_foreign_watch = false;

    {
        BalanceWatchFetchBook& book = FetchBook();
        LOCK(book.mu);
        const auto it = book.by_wallet.find(wallet.GetName());
        if (it != book.by_wallet.end()) {
            status.fetched = it->second;
        }
    }
    return status;
}

BalanceAtHeightResult GetBalanceAtHeight(const CWallet& wallet, int height)
{
    BalanceAtHeightResult result;
    result.shielded_omitted = true;
    if (height < 0) return result;

    LOCK(wallet.cs_wallet);
    if (wallet.IsScanning()) return result;
    if (wallet.GetLastBlockProcessedHeight() < height) return result;

    result.amount = MineTrustedAtHeight(wallet, height);
    result.ready = true;
    return result;
}

void NoteBalanceWatchFetch(const CWallet& wallet, const std::string& descriptor, int height)
{
    std::vector<std::string> owned;
    {
        LOCK(wallet.cs_wallet);
        owned = WalletOwnDescriptors(wallet);
    }
    if (DescriptorIsOwned(owned, descriptor)) return;

    BalanceWatchFetchBook& book = FetchBook();
    LOCK(book.mu);
    std::vector<BalanceWatchMiss>& misses = book.by_wallet[wallet.GetName()];
    if (misses.size() >= MAX_BALANCE_WATCH_FETCHES) {
        misses.erase(misses.begin());
    }
    misses.push_back(BalanceWatchMiss{descriptor, height});
}

} // namespace wallet
