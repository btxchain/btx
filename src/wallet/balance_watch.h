// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BALANCE_WATCH_H
#define BITCOIN_WALLET_BALANCE_WATCH_H

#include <consensus/amount.h>

#include <string>
#include <vector>

namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;

struct BalanceWatchMiss {
    std::string descriptor;
    int height{0};
};

struct BalanceWatchStatus {
    bool ready{false};
    int chain_height{-1};
    int wallet_height{-1};
    int blocks_behind{0};
    bool scanning{false};
    bool shielded_foreign_watch{false};
    std::vector<std::string> descriptors;
    std::vector<BalanceWatchMiss> fetched;
};

struct BalanceAtHeightResult {
    bool ready{false};
    CAmount amount{0};
    bool shielded_omitted{true};
};

/** Ready only when the chain has a tip H, the wallet has processed at least H,
 *  and the wallet is not scanning. descriptors are this wallet's own public
 *  descriptor strings. fetched is the capped miss list from NoteBalanceWatchFetch.
 *  shielded_foreign_watch is always false. */
BalanceWatchStatus GetBalanceWatchStatus(const CWallet& wallet, const interfaces::Chain& chain);

/** Transparent mine-trusted balance from mapWallet at `height`. Not ready when
 *  height < 0, the wallet has not processed `height`, or a scan is running.
 *  Does not walk the chain and does not add shielded value. */
BalanceAtHeightResult GetBalanceAtHeight(const CWallet& wallet, int height);

/** Record a lookup whose descriptor is not already one of this wallet's
 *  descriptor strings. At most 32 misses are kept per wallet name. */
void NoteBalanceWatchFetch(const CWallet& wallet, const std::string& descriptor, int height);

} // namespace wallet

#endif // BITCOIN_WALLET_BALANCE_WATCH_H
