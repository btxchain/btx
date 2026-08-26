// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

BOOST_AUTO_TEST_SUITE(lastcommon_root_first_tests)

namespace {

struct ChainFixture {
    std::vector<std::unique_ptr<CBlockIndex>> nodes;

    CBlockIndex* Add(CBlockIndex* prev, int height)
    {
        auto idx = std::make_unique<CBlockIndex>();
        idx->nHeight = height;
        idx->pprev = prev;
        idx->nStatus = BLOCK_VALID_TREE;
        idx->nChainWork = prev ? (prev->nChainWork + 1) : 1;
        idx->BuildSkip();
        CBlockIndex* raw = idx.get();
        nodes.push_back(std::move(idx));
        return raw;
    }

    static void MarkHaveData(CBlockIndex* idx, bool have_chain_txs)
    {
        idx->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_TRANSACTIONS;
        idx->nTx = 1;
        if (have_chain_txs) {
            idx->m_chain_tx_count = (idx->pprev ? idx->pprev->m_chain_tx_count : 0) + 1;
        }
    }

    static void ClearHaveData(CBlockIndex* idx)
    {
        idx->nStatus &= ~BLOCK_HAVE_DATA;
        // Leave m_chain_tx_count set — the production desync class:
        // HaveNumChainTxs outlives BLOCK_HAVE_DATA after prune/partial loss.
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(find_lowest_missing_with_higher_bodies_present)
{
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    std::vector<CBlockIndex*> winning;
    winning.push_back(genesis);
    for (int h = 1; h <= 12; ++h) {
        winning.push_back(f.Add(winning.back(), h));
    }

    // Tip stays at fork (height 0). Six missing roots at 1..6; higher bodies
    // already on disk at 7..12 (getblockfrompeer / partial sync).
    for (int h = 7; h <= 12; ++h) {
        ChainFixture::MarkHaveData(winning[h], /*have_chain_txs=*/false);
    }

    const CBlockIndex* missing =
        FindLowestMissingBody(genesis, winning.back(), /*active_chain=*/nullptr);
    BOOST_REQUIRE(missing != nullptr);
    BOOST_CHECK_EQUAL(missing->nHeight, 1);
}

BOOST_AUTO_TEST_CASE(clamp_pulls_last_common_back_past_pruned_hole)
{
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    std::vector<CBlockIndex*> winning;
    winning.push_back(genesis);
    for (int h = 1; h <= 12; ++h) {
        CBlockIndex* idx = f.Add(winning.back(), h);
        // Simulate a prior full download: chain-tx counts set throughout.
        ChainFixture::MarkHaveData(idx, /*have_chain_txs=*/true);
        winning.push_back(idx);
    }

    // Prune the six roots — HaveNumChainTxs remains, BLOCK_HAVE_DATA cleared.
    for (int h = 1; h <= 6; ++h) {
        ChainFixture::ClearHaveData(winning[h]);
        BOOST_CHECK(winning[h]->HaveNumChainTxs());
        BOOST_CHECK(!(winning[h]->nStatus & BLOCK_HAVE_DATA));
    }

    CChain active;
    active.SetTip(*genesis);

    // Desync: LastCommon was dragged to height 12 while roots 1..6 are gone.
    const LastCommonRootFirstResult result = ClampLastCommonToRootFirst(
        /*last_common=*/winning[12],
        /*best_known=*/winning[12],
        /*tip=*/genesis,
        &active);

    BOOST_CHECK(result.clamped);
    BOOST_CHECK_EQUAL(std::string(result.reason), "clamped_past_missing_root");
    BOOST_REQUIRE(result.lowest_missing != nullptr);
    BOOST_CHECK_EQUAL(result.lowest_missing->nHeight, 1);
    BOOST_REQUIRE(result.last_common != nullptr);
    BOOST_CHECK_EQUAL(result.last_common->nHeight, 0);
    BOOST_CHECK(result.last_common == genesis);
}

BOOST_AUTO_TEST_CASE(sibling_on_active_chain_does_not_hide_followed_hole)
{
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    // Losing sibling tip at height 1 (active).
    CBlockIndex* losing = f.Add(genesis, 1);
    ChainFixture::MarkHaveData(losing, /*have_chain_txs=*/true);

    // Winning branch: missing 1..6, higher bodies present at 7..12.
    std::vector<CBlockIndex*> winning;
    winning.push_back(genesis);
    for (int h = 1; h <= 12; ++h) {
        winning.push_back(f.Add(winning.back(), h));
    }
    for (int h = 7; h <= 12; ++h) {
        ChainFixture::MarkHaveData(winning[h], /*have_chain_txs=*/false);
    }

    CChain active;
    active.SetTip(*losing);
    BOOST_CHECK(active.Contains(losing));
    BOOST_CHECK(!active.Contains(winning[1]));

    // Tempt LastCommon forward to a higher HAVE_DATA block on the followed chain.
    const LastCommonRootFirstResult result = ClampLastCommonToRootFirst(
        /*last_common=*/winning[12],
        /*best_known=*/winning[12],
        /*tip=*/losing,
        &active);

    BOOST_CHECK(result.clamped);
    BOOST_REQUIRE(result.lowest_missing != nullptr);
    BOOST_CHECK_EQUAL(result.lowest_missing->nHeight, 1);
    BOOST_CHECK_EQUAL(result.last_common->nHeight, 0);
    // Sibling Contains(losing) must not make FindLowestMissingBody skip winning[1].
    BOOST_CHECK(result.lowest_missing == winning[1]);
}

BOOST_AUTO_TEST_CASE(no_clamp_when_contiguous_from_tip_lca)
{
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    std::vector<CBlockIndex*> chain;
    chain.push_back(genesis);
    for (int h = 1; h <= 5; ++h) {
        CBlockIndex* idx = f.Add(chain.back(), h);
        if (h <= 3) {
            ChainFixture::MarkHaveData(idx, /*have_chain_txs=*/true);
        }
        chain.push_back(idx);
    }

    CChain active;
    active.SetTip(*chain[3]);

    const LastCommonRootFirstResult result = ClampLastCommonToRootFirst(
        /*last_common=*/chain[3],
        /*best_known=*/chain[5],
        /*tip=*/chain[3],
        &active);

    BOOST_CHECK(!result.clamped);
    BOOST_REQUIRE(result.lowest_missing != nullptr);
    BOOST_CHECK_EQUAL(result.lowest_missing->nHeight, 4);
    BOOST_CHECK_EQUAL(result.last_common->nHeight, 3);
}

BOOST_AUTO_TEST_CASE(have_data_unconnected_child_does_not_hide_next_hole)
{
    // Production catch-up: tip=H, last_common=H+1 with HAVE_DATA but not
    // connected, lowest_missing=H+2. Download must still see H+2 as the hole;
    // connecting H+1 is ActivateBestChain's job. A walk that then fills 16
    // successors of H+2 is the root_in_flight stall — covered in peerman.
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    std::vector<CBlockIndex*> chain;
    chain.push_back(genesis);
    for (int h = 1; h <= 5; ++h) {
        CBlockIndex* idx = f.Add(chain.back(), h);
        if (h <= 2) {
            ChainFixture::MarkHaveData(idx, /*have_chain_txs=*/true);
        }
        chain.push_back(idx);
    }

    CChain active;
    active.SetTip(*chain[1]);
    BOOST_CHECK(active.Contains(chain[1]));
    BOOST_CHECK(!active.Contains(chain[2]));
    BOOST_CHECK(chain[2]->nStatus & BLOCK_HAVE_DATA);

    const LastCommonRootFirstResult result = ClampLastCommonToRootFirst(
        /*last_common=*/chain[2],
        /*best_known=*/chain[5],
        /*tip=*/chain[1],
        &active);

    BOOST_CHECK(!result.clamped);
    BOOST_REQUIRE(result.last_common != nullptr);
    BOOST_CHECK_EQUAL(result.last_common->nHeight, 2);
    BOOST_REQUIRE(result.lowest_missing != nullptr);
    BOOST_CHECK_EQUAL(result.lowest_missing->nHeight, 3);
    BOOST_CHECK(result.last_common->nHeight > active.Height());
}

BOOST_AUTO_TEST_CASE(first_hole_survives_sibling_header_flood)
{
    // 1.4 / 4.2: a flood of HEADER_ONLY siblings at the hole height must
    // not hide the canonical lowest missing body. Restart-only recovery
    // is a test failure — ClampLastCommonToRootFirst must still name it.
    ChainFixture f;
    CBlockIndex* genesis = f.Add(nullptr, 0);
    ChainFixture::MarkHaveData(genesis, /*have_chain_txs=*/true);

    std::vector<CBlockIndex*> followed;
    followed.push_back(genesis);
    for (int h = 1; h <= 4; ++h) {
        CBlockIndex* idx = f.Add(followed.back(), h);
        if (h <= 2) {
            ChainFixture::MarkHaveData(idx, /*have_chain_txs=*/true);
        }
        followed.push_back(idx);
    }

    for (int i = 0; i < 32; ++i) {
        f.Add(followed[2], 3); // HEADER_ONLY twins of the first hole
    }

    CChain active;
    active.SetTip(*followed[2]);

    const LastCommonRootFirstResult result = ClampLastCommonToRootFirst(
        /*last_common=*/followed[2],
        /*best_known=*/followed[4],
        /*tip=*/followed[2],
        &active);

    BOOST_REQUIRE(result.lowest_missing != nullptr);
    BOOST_CHECK_EQUAL(result.lowest_missing->nHeight, 3);
    BOOST_CHECK(result.lowest_missing == followed[3]);
    BOOST_CHECK_EQUAL(result.last_common->nHeight, 2);
}

BOOST_AUTO_TEST_SUITE_END()
