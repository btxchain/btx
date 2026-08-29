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
        // V6/RB-13: a COMPETING heavier header only counts as stale when it is
        // more than a cheaply-forged header-only tower. The public-net spam
        // gate is disabled and header PoW is a self-declared digest<=target
        // check, so an attacker can index an arbitrary heavier COMPETING
        // Phase1 tower for free and flip is_stale=true to freeze a current
        // merchant's settlement (a griefing DoS). Require the competing chain
        // to carry AUTHENTICATED (ExactReplay-backed) work beyond our tip, or
        // for us to actually hold its body (HAVE_DATA -- a reorg we are
        // genuinely evaluating). A pure header-only spam tower has neither, so
        // it no longer grieves. This is NOT a CPU-oracle and does not slow the
        // GPU path. Pre-fork nAuthenticatedChainWork == nChainWork, so this is
        // behaviour-identical while the MatMul v4 fork is disabled.
        //
        // The EXTENDING behind_best_header>6 path is deliberately UNCHANGED
        // (E-3 adv5: INHERENT-TRADEOFF-FINAL). A cheap 7-header extending tower
        // can force a CURRENT merchant's is_stale=true, but that is a
        // settlement-HOLD grief (safe direction), and every candidate fix --
        // capping the unauthenticated extending lead, or gating on tip-advance
        // velocity / body corroboration -- risks UNDER-reporting an honest
        // node that is genuinely far behind, which is settle-while-behind
        // (double-spend blinding, the exact hole 77493d74/V6 closed) and worse
        // than the grief. The root cause is the public-net header-spam-gate
        // being disabled (a documented chainparams tradeoff), not fixable at
        // the staleness layer without CPU-oracling headers.
        // an honest node that is genuinely far behind (e.g. a self-qualified
        // archive catching up) must keep reporting is_stale=true so merchants
        // do not credit deposits while behind. Over-reporting there is the
        // safe direction; suppressing it would reopen the double-spend-blinding
        // hole 77493d74 closed.
        const bool competing_heavier{
            best_header->nChainWork > tip->nChainWork && !out.header_extends_tip};
        const bool competing_is_real{
            best_header->nAuthenticatedChainWork > tip->nChainWork ||
            (best_header->nStatus & BLOCK_HAVE_DATA)};
        out.competing_heavier_header = competing_heavier && competing_is_real;
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
