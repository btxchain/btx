// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/string.h>
#include <validation.h>

#include <cstdlib>

using util::ToString;

/* Equality between doubles is imprecise. Comparison should be done
 * with a small threshold of tolerance, rather than exact equality.
 */
static bool DoubleEquals(double a, double b, double epsilon)
{
    return std::abs(a - b) < epsilon;
}

static CBlockIndex* CreateBlockIndexWithNbits(uint32_t nbits)
{
    CBlockIndex* block_index = new CBlockIndex();
    block_index->nHeight = 46367;
    block_index->nTime = 1269211443;
    block_index->nBits = nbits;
    return block_index;
}

static void RejectDifficultyMismatch(double difficulty, double expected_difficulty) {
     BOOST_CHECK_MESSAGE(
        DoubleEquals(difficulty, expected_difficulty, 0.00001),
        "Difficulty was " + ToString(difficulty)
            + " but was expected to be " + ToString(expected_difficulty));
}

/* Given a BlockIndex with the provided nbits,
 * verify that the expected difficulty results.
 */
static void TestDifficulty(uint32_t nbits, double expected_difficulty)
{
    CBlockIndex* block_index = CreateBlockIndexWithNbits(nbits);
    double difficulty = GetDifficulty(*block_index);
    delete block_index;

    RejectDifficultyMismatch(difficulty, expected_difficulty);
}

BOOST_FIXTURE_TEST_SUITE(blockchain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(get_difficulty_for_very_low_target)
{
    TestDifficulty(0x1f111111, 0.000001);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_low_target)
{
    TestDifficulty(0x1ef88f6f, 0.000016);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_mid_target)
{
    TestDifficulty(0x1df88f6f, 0.004023);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_high_target)
{
    TestDifficulty(0x1cf88f6f, 1.029916);
}

BOOST_AUTO_TEST_CASE(get_difficulty_for_very_high_target)
{
    TestDifficulty(0x12345678, 5913134931067755359633408.0);
}

//! Prune chain from height down to genesis block and check that
//! GetPruneHeight returns the correct value
static void CheckGetPruneHeight(node::BlockManager& blockman, CChain& chain, int height) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);

    // Emulate pruning all blocks from `height` down to the genesis block
    // by unsetting the `BLOCK_HAVE_DATA` flag from `nStatus`
    for (CBlockIndex* it{chain[height]}; it != nullptr && it->nHeight > 0; it = it->pprev) {
        it->nStatus &= ~BLOCK_HAVE_DATA;
    }

    const auto prune_height{GetPruneHeight(blockman, chain)};
    BOOST_REQUIRE(prune_height.has_value());
    BOOST_CHECK_EQUAL(*prune_height, height);
}

BOOST_FIXTURE_TEST_CASE(get_prune_height, TestChain100Setup)
{
    LOCK(::cs_main);
    auto& chain = m_node.chainman->ActiveChain();
    auto& blockman = m_node.chainman->m_blockman;

    // Fresh chain of 100 blocks without any pruned blocks, so std::nullopt should be returned
    BOOST_CHECK(!GetPruneHeight(blockman, chain).has_value());

    // Start pruning
    CheckGetPruneHeight(blockman, chain, 1);
    CheckGetPruneHeight(blockman, chain, 99);
    CheckGetPruneHeight(blockman, chain, 100);
}

BOOST_AUTO_TEST_CASE(num_chain_tx_max)
{
    CBlockIndex block_index{};
    block_index.m_chain_tx_count = std::numeric_limits<uint64_t>::max();
    BOOST_CHECK_EQUAL(block_index.m_chain_tx_count, std::numeric_limits<uint64_t>::max());
}

BOOST_FIXTURE_TEST_CASE(invalidate_block_marks_only_descendants_failed_child, TestChain100Setup)
{
    Chainstate& chainstate{Assert(m_node.chainman)->ActiveChainstate()};
    CBlockIndex* original_tip;
    CBlockIndex* invalidate_at;
    {
        LOCK(::cs_main);
        original_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(original_tip != nullptr);
        invalidate_at = chainstate.m_chain[original_tip->nHeight - 10];
        BOOST_REQUIRE(invalidate_at != nullptr);
    }

    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, invalidate_at));

    LOCK(::cs_main);
    BOOST_CHECK(invalidate_at->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK_EQUAL(invalidate_at->nStatus & BLOCK_FAILED_CHILD, 0U);

    for (CBlockIndex* ancestor{invalidate_at->pprev}; ancestor; ancestor = ancestor->pprev) {
        BOOST_CHECK(ancestor->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK_EQUAL(ancestor->nStatus & BLOCK_FAILED_MASK, 0U);
    }

    for (CBlockIndex* descendant{original_tip}; descendant != invalidate_at; descendant = descendant->pprev) {
        BOOST_REQUIRE(descendant != nullptr);
        BOOST_CHECK_EQUAL(descendant->nStatus & BLOCK_FAILED_VALID, 0U);
        BOOST_CHECK(descendant->nStatus & BLOCK_FAILED_CHILD);
    }

    chainstate.ResetBlockFailureFlags(invalidate_at);
    BOOST_CHECK_EQUAL(invalidate_at->nStatus & BLOCK_FAILED_MASK, 0U);
    for (CBlockIndex* descendant{original_tip}; descendant != invalidate_at; descendant = descendant->pprev) {
        BOOST_CHECK_EQUAL(descendant->nStatus & BLOCK_FAILED_MASK, 0U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
