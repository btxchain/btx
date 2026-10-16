// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LIGHTWATCH_H
#define BITCOIN_LIGHTWATCH_H

#include <consensus/amount.h>
#include <uint256.h>

#include <functional>
#include <string>
#include <vector>

class CBlock;
class UniValue;

/** One block downloaded because its filter matched a watched script. */
struct LightWatchFetch {
    int height{0};
    uint256 block_hash;
};

/** Status of a watch that stores only this wallet's outputs. */
struct LightWatchStatus {
    bool ready{false};
    int chain_height{-1};
    int wallet_height{-1};
    int blocks_behind{0};
    int start_height{0};
    bool shielded_foreign_watch{false};
    bool shielded_omitted{true};
    uint64_t fetched_total{0};
    std::vector<std::string> descriptors;
    std::vector<LightWatchFetch> fetched;
};

struct LightWatchAmount {
    bool ready{false};
    CAmount amount{0};
    CAmount immature{0};
};

/**
 * Lightweight watch of this wallet's public descriptors.
 *
 * The watch stores descriptor scripts, the outputs that pay them, and the
 * spends of those outputs. It does not store the chain. A block is required
 * only when its compact filter matches. Until the filter walk has reached the
 * requested height, an amount is not ready and is not reported as zero.
 * Shielded notes are omitted. Private keys are refused.
 */
class LightWatch {
public:
    static constexpr int RANGE_WINDOW = 200;
    static constexpr std::size_t MAX_FETCHED = 32;

    enum class Step {
        APPLIED,
        NEED_BLOCK,
        REJECTED,
    };

    bool AddDescriptor(const std::string& descriptor, std::string& error, bool reset_progress = true);
    void SetStartHeight(int height);

    /** Apply one filter. On NEED_BLOCK the state is unchanged and the caller
     *  must call again with the block. A filter miss advances without a block. */
    Step ApplyFilter(int height, const uint256& block_hash, const uint256& prev_hash,
                     const std::vector<unsigned char>& encoded_filter, const uint256& filter_header,
                     const CBlock* block, std::string& error);

    void RewindTo(int height);

    LightWatchStatus Status(int chain_height) const;
    LightWatchAmount BalanceAt(int height) const;

    /** Walk filters from the cursor through the node tip. `rpc` returns the
     *  unwrapped RPC result and throws on transport or RPC error. */
    bool Sync(const std::function<UniValue(const std::string& method, const std::vector<std::string>& args)>& rpc,
              std::string& error);

    bool Save(const std::string& path, std::string& error) const;
    bool Load(const std::string& path, std::string& error);

    int Cursor() const { return m_cursor; }
    int StartHeight() const { return m_start; }
    bool FilterReady() const { return m_filter_ready; }

private:
    struct Event {
        int height{0};
        uint256 txid;
        uint32_t n{0};
        CAmount value{0};
        bool coinbase{false};
        bool spend{false};
    };

    int NextHeight() const;
    void RebuildScripts();
    bool IsOpen(const uint256& txid, uint32_t n, CAmount& value, bool& coinbase) const;
    void NoteFetch(int height, const uint256& block_hash);

    int m_start{0};
    int m_cursor{-1};
    bool m_filter_ready{true};
    uint256 m_filter_header;
    bool m_anchor_set{false};
    uint256 m_anchor;
    std::vector<std::string> m_descriptors;
    std::vector<Event> m_events;
    std::vector<std::pair<int, uint256>> m_hashes;
    std::vector<LightWatchFetch> m_fetched;
    uint64_t m_fetched_total{0};

    // Rebuilt from descriptors. Not saved.
    std::vector<std::vector<unsigned char>> m_scripts;
};

#endif // BITCOIN_LIGHTWATCH_H
