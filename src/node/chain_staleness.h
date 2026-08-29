// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAIN_STALENESS_H
#define BITCOIN_NODE_CHAIN_STALENESS_H

#include <chain.h>
#include <uint256.h>

#include <algorithm>
#include <string_view>

class CBlockIndex;

namespace node {

//! Header-minus-blocks gap matching the emergency park depth (6). A connected
//! tip more than this many headers behind m_best_header is freeze-scale: the
//! node can see a longer valid header chain it has not connected. Reorgs
//! deeper than 6 are parked network-wide, so this is honest reporting, not the
//! sole double-spend barrier.
inline constexpr int CHAIN_STALE_BEHIND_HEADERS{6};

inline constexpr std::string_view CHAIN_STALE_RPC_WARNING{
    "Active chain tip is stale: this node has validated headers far ahead of connected blocks, or a heavier competing header chain it has not connected. Do not credit deposits from getblockcount or gettransaction confirmations until is_stale is false."};

struct ChainTipStaleness {
    int blocks{-1};
    int headers{-1};
    int behind_best_header{0};
    bool header_extends_tip{true};
    bool competing_heavier_header{false};
    bool is_stale{false};
    uint256 bestblockhash{};
    uint256 best_header_hash{};
};

inline uint256 BlockIndexHashOrNull(const CBlockIndex* index)
{
    return (index && index->phashBlock) ? index->GetBlockHash() : uint256{};
}

//! Compare the connected tip to the followed header. A frozen node that never
//! disconnects a block still knows when m_best_header is a much longer, or
//! strictly heavier competing, chain.
[[nodiscard]] inline ChainTipStaleness ComputeChainTipStaleness(const CBlockIndex* tip, const CBlockIndex* best_header)
{
    ChainTipStaleness out;
    if (tip) {
        out.blocks = tip->nHeight;
        out.bestblockhash = BlockIndexHashOrNull(tip);
    }
    if (best_header) {
        out.headers = best_header->nHeight;
        out.best_header_hash = BlockIndexHashOrNull(best_header);
    }
    if (tip && best_header) {
        out.behind_best_header = std::max(0, best_header->nHeight - tip->nHeight);
        out.header_extends_tip = best_header->GetAncestor(tip->nHeight) == tip;
        out.competing_heavier_header =
            best_header->nChainWork > tip->nChainWork && !out.header_extends_tip;
        out.is_stale = out.competing_heavier_header ||
                       out.behind_best_header > CHAIN_STALE_BEHIND_HEADERS;
    } else if (!tip && best_header) {
        out.behind_best_header = std::max(0, best_header->nHeight);
        out.header_extends_tip = false;
        out.competing_heavier_header = best_header->nHeight > 0;
        out.is_stale = out.behind_best_header > CHAIN_STALE_BEHIND_HEADERS ||
                       out.competing_heavier_header;
    }
    return out;
}

} // namespace node

#endif // BITCOIN_NODE_CHAIN_STALENESS_H
