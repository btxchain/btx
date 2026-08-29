// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/time.h>

#include <algorithm>
#include <deque>
#include <functional>

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, nHeight, hashMerkleRoot.ToString(), GetBlockHash().ToString());
}

void CChain::SetTip(CBlockIndex& block)
{
    CBlockIndex* pindex = &block;
    if (pindex->nHeight < 0) {
        vChain.clear();
        return;
    }
    const size_t new_size = static_cast<size_t>(pindex->nHeight) + 1;
    vChain.resize(new_size);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

std::vector<uint256> LocatorEntries(const CBlockIndex* index)
{
    int step = 1;
    std::vector<uint256> have;
    if (index == nullptr) return have;

    have.reserve(32);
    while (index) {
        have.emplace_back(index->GetBlockHash());
        if (index->nHeight == 0) break;
        // Exponentially larger steps back, plus the genesis block.
        int height = std::max(index->nHeight - step, 0);
        // Use skiplist.
        index = index->GetAncestor(height);
        if (have.size() > 10) step *= 2;
    }
    return have;
}

CBlockLocator GetLocator(const CBlockIndex* index)
{
    return CBlockLocator{LocatorEntries(index)};
}

CBlockLocator CChain::GetLocator() const
{
    return ::GetLocator(Tip());
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == nullptr) {
        return nullptr;
    }
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime, int height) const
{
    std::pair<int64_t, int> blockparams = std::make_pair(nTime, height);
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), blockparams,
        [](CBlockIndex* pBlock, const std::pair<int64_t, int>& blockparams) -> bool { return pBlock->GetBlockTimeMax() < blockparams.first || pBlock->nHeight < blockparams.second; });
    return (lower == vChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    const CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            if (!pindexWalk->pprev) {
                LogError("GetAncestor: pprev is null at height %d while walking to height %d\n", heightWalk, height);
                return nullptr;
            }
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

bool IsBlockAuthenticated(const CBlockIndex& block, const Consensus::Params& params)
{
    // Below the MatMul v4 fork, v3 header work is credited immediately (matches
    // legacy nChainWork exactly). At and above the fork, a header's work is only
    // authenticated once its body arrived and the height-selected MatMul
    // authority passed (Profile-1 RC uses ExactReplay). That is precisely the
    // point at which the index reaches BLOCK_VALID_TRANSACTIONS. In trusted
    // replay mode, transaction validity is deliberately not enough by itself:
    // signer configuration is local policy and can change across restart, so
    // an explicit authority-provenance bit must still be present under the
    // current configuration.
    if (!params.IsMatMulV4Active(block.nHeight)) return true;
    if (block.nStatus & BLOCK_FAILED_MASK) return false;
    if ((block.nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) return false;
    if (params.IsMatMulTrustedReplayAttestationActive(block.nHeight) &&
        (block.nStatus & (BLOCK_EXACT_REPLAY_VERIFIED |
                          BLOCK_TRUSTED_REPLAY_ATTESTED)) == 0) {
        return false;
    }

    // Authentication is a contiguous-prefix property, not a count of
    // independently verified bodies. A child body can arrive and pass the
    // context-free/body checks before an earlier body on the same branch is
    // available (m_blocks_unlinked handles exactly that case). Crediting the
    // child immediately would create a hole in authenticated chainwork and let
    // a branch interleave cheap forged headers with isolated valid bodies.
    //
    // The parent-first load/recompute order and the descendant propagation in
    // ReceivedBlockTransactions guarantee that a verified child is promoted
    // as soon as the missing parent prefix becomes fully authenticated.
    return block.pprev == nullptr ||
           block.pprev->nAuthenticatedChainWork == block.pprev->nChainWork;
}

arith_uint256 GetBlockAuthenticatedProof(const CBlockIndex& block, const Consensus::Params& params)
{
    return IsBlockAuthenticated(block, params) ? GetBlockProof(block) : arith_uint256{};
}

void UpdateAuthenticatedChainWork(CBlockIndex& block, const Consensus::Params& params)
{
    block.nAuthenticatedChainWork =
        (block.pprev ? block.pprev->nAuthenticatedChainWork : arith_uint256{}) +
        GetBlockAuthenticatedProof(block, params);
}

arith_uint256 GetTrustAdjustedChainWork(const CBlockIndex& block, unsigned int unauth_allowance_blocks)
{
    // Invariant maintained by UpdateAuthenticatedChainWork: authenticated work
    // never exceeds claimed work (each block contributes GetBlockProof or 0).
    // Clamp the subtraction anyway (defense-in-depth): if that invariant were ever
    // broken, an unsigned arith_uint256 underflow would wrap to ~2^256 and, via the
    // std::min below, mis-rank an unauthenticated chain UPWARD. std::min pins it to 0.
    const arith_uint256 unauth{block.nChainWork - std::min(block.nChainWork, block.nAuthenticatedChainWork)};
    // Production passes a bounded allowance: a short unverified suffix may earn
    // limited preference so a lost same-height race can be chased, but a forged
    // tip's nBits cannot buy unbounded ranking before body verification.
    arith_uint256 allowance{GetBlockProof(block)};
    allowance *= unauth_allowance_blocks;
    return block.nAuthenticatedChainWork + std::min(unauth, allowance);
}

bool PreferTrustAdjustedHeader(const CBlockIndex& current, const CBlockIndex& candidate,
                               unsigned int unauth_allowance_blocks)
{
    const arith_uint256 current_adjusted =
        GetTrustAdjustedChainWork(current, unauth_allowance_blocks);
    const arith_uint256 candidate_adjusted =
        GetTrustAdjustedChainWork(candidate, unauth_allowance_blocks);
    if (current_adjusted != candidate_adjusted) {
        return current_adjusted < candidate_adjusted;
    }

    // Equal adjusted work: either both fully authenticated (legacy tie → keep
    // current), or both sit on the same allowance-capped plateau. Never let
    // unordered block-index iteration choose an arbitrary, possibly
    // millions-of-headers-deep member of that plateau as m_best_header. Prefer
    // the most authenticated and then the shallowest claimed suffix.
    const bool current_has_unauth = current.nAuthenticatedChainWork < current.nChainWork;
    const bool candidate_has_unauth = candidate.nAuthenticatedChainWork < candidate.nChainWork;
    if (!current_has_unauth && !candidate_has_unauth) return false;
    if (current.nAuthenticatedChainWork != candidate.nAuthenticatedChainWork) {
        return current.nAuthenticatedChainWork < candidate.nAuthenticatedChainWork;
    }
    const arith_uint256 current_unauth =
        current.nChainWork - std::min(current.nChainWork, current.nAuthenticatedChainWork);
    const arith_uint256 candidate_unauth =
        candidate.nChainWork - std::min(candidate.nChainWork, candidate.nAuthenticatedChainWork);
    if (current_unauth != candidate_unauth) return candidate_unauth < current_unauth;
    if (current.nHeight != candidate.nHeight) return candidate.nHeight < current.nHeight;
    return candidate.GetBlockHash() < current.GetBlockHash();
}

void PropagateAuthenticatedChainWorkDescendants(
    CBlockIndex& root,
    const Consensus::Params& params,
    const std::function<void(
        CBlockIndex&,
        const std::function<void(CBlockIndex&)>&)>& for_each_child,
    const std::function<void(CBlockIndex&)>& on_updated)
{
    std::deque<CBlockIndex*> queue;
    queue.push_back(&root);
    while (!queue.empty()) {
        CBlockIndex* parent = queue.front();
        queue.pop_front();
        for_each_child(*parent, [&](CBlockIndex& child) {
            UpdateAuthenticatedChainWork(child, params);
            if (on_updated) on_updated(child);
            queue.push_back(&child);
        });
    }
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * int64_t(r.GetLow64());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

static bool HasUsableBlockBody(const CBlockIndex* pindex, const CChain* active_chain)
{
    if (pindex == nullptr) return false;
    if (pindex->nStatus & BLOCK_HAVE_DATA) return true;
    return active_chain != nullptr && active_chain->Contains(pindex);
}

const CBlockIndex* FindLowestMissingBody(const CBlockIndex* start,
                                         const CBlockIndex* best_known,
                                         const CChain* active_chain)
{
    if (best_known == nullptr) return nullptr;
    if (start == nullptr) {
        // No known common point: treat genesis/parent of best_known's full
        // ancestry as the scan base by walking from height 0.
        start = best_known->GetAncestor(0);
    }
    // start must be an ancestor of best_known (caller re-derives via LCA).
    if (best_known->GetAncestor(start->nHeight) != start) {
        start = LastCommonAncestor(start, best_known);
    }
    if (start == best_known) return nullptr;

    for (int height = start->nHeight + 1; height <= best_known->nHeight; ++height) {
        const CBlockIndex* pindex{best_known->GetAncestor(height)};
        if (!HasUsableBlockBody(pindex, active_chain)) {
            return pindex;
        }
    }
    return nullptr;
}

LastCommonRootFirstResult ClampLastCommonToRootFirst(const CBlockIndex* last_common,
                                                     const CBlockIndex* best_known,
                                                     const CBlockIndex* tip,
                                                     const CChain* active_chain)
{
    LastCommonRootFirstResult out;
    assert(best_known != nullptr);
    assert(tip != nullptr);

    // True fork point with our tip — never start a competing-chain walk above this
    // without first proving every followed-chain body from here is present.
    const CBlockIndex* tip_lca{LastCommonAncestor(tip, best_known)};
    out.last_common = last_common != nullptr
                          ? LastCommonAncestor(last_common, best_known)
                          : tip_lca;

    // Prefer tip_lca when the stored pointer is not on the tip↔best_known fork
    // path (should already be corrected by the LCA above, but be defensive).
    if (out.last_common != tip_lca &&
        tip_lca->GetAncestor(out.last_common->nHeight) != out.last_common &&
        out.last_common->GetAncestor(tip_lca->nHeight) != tip_lca) {
        out.last_common = tip_lca;
        out.clamped = true;
        out.reason = "rederived_tip_lca";
    }

    // If last_common is below tip_lca, raise to the real fork.
    if (out.last_common->nHeight < tip_lca->nHeight) {
        out.last_common = tip_lca;
        out.clamped = true;
        out.reason = "raised_to_tip_lca";
    }

    out.lowest_missing = FindLowestMissingBody(tip_lca, best_known, active_chain);
    if (out.lowest_missing == nullptr) {
        if (!out.clamped) out.reason = "ok_no_missing";
        return out;
    }

    // Parent of the lowest hole is the latest safe common point.
    const CBlockIndex* safe{out.lowest_missing->pprev};
    assert(safe != nullptr);
    if (out.last_common->nHeight >= out.lowest_missing->nHeight) {
        out.last_common = safe;
        out.clamped = true;
        out.reason = "clamped_past_missing_root";
    }
    return out;
}

LastCommonRootFirstResult AdvanceLastCommonPastActiveTip(LastCommonRootFirstResult in,
                                                         const CBlockIndex* tip,
                                                         const CBlockIndex* best_known,
                                                         const CChain* active_chain)
{
    if (tip == nullptr || in.last_common == nullptr) return in;
    if (in.last_common->nHeight >= tip->nHeight) return in;

    // F3 dropped equal-work EncDr twins so they could not occupy inflight.
    // A strictly heavier competing fork has its missing root at or below
    // the connected tip (live 2026-08-28: hole 199304 vs tip 199312, LCA
    // 199294, claimed work of headers-only 199384 > active 199312). Snapping
    // last_common onto the active tip drops that hole; FindNextBlocks then
    // skips every competing hash with height <= tip. Keep ClampLastCommon's
    // last_common + lowest_missing so GETDATA can start at the fork root —
    // but only while the LCA is still near the tip. A deep HEADER_ONLY
    // tower (rtx6000: last_common=199312, tip=199394, Δ=82) must not pin
    // the walk 82 blocks behind bodies we already have.
    const bool heavier_competing{
        best_known != nullptr &&
        best_known->nChainWork > tip->nChainWork &&
        best_known->GetAncestor(tip->nHeight) != tip};
    if (LastCommonKeepHeavierCompetingFork(
            heavier_competing, tip->nHeight, in.last_common->nHeight)) {
        return in;
    }

    LastCommonRootFirstResult out = in;
    out.last_common = tip;
    out.clamped = true;
    out.reason = "advanced_past_active_tip";
    if (best_known == nullptr) {
        out.lowest_missing = nullptr;
        return out;
    }
    out.lowest_missing = FindLowestMissingBody(tip, best_known, active_chain);
    // FindLowestMissingBody LCAs `tip` with `best_known`, so a sibling fork
    // still yields a hole at or below the connected tip. Equal-work EncDr
    // twins are the F3 pin: drop those. Short heavier competing forks
    // already returned above; a deep withdrawn tower's competing hole
    // is also dropped so the walk starts at the connected tip.
    if (out.lowest_missing != nullptr &&
        out.lowest_missing->GetAncestor(tip->nHeight) != tip) {
        out.lowest_missing = nullptr;
    }
    return out;
}
