// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Consensus coverage for the BTX content-elimination hard fork
// (doc/btx-inscription-elimination-plan.md). These cases exercise the two
// coinbase-only block rules that the Python functional test
// (test/functional/feature_content_elimination.py) cannot reach, because they
// require a hand-crafted coinbase and the regtest MatMul proof-of-work cannot
// be solved outside the node:
//
//   - Pillar 5: a coinbase scriptSig larger than 40 bytes is rejected
//     bad-cb-scriptsig-content.
//   - Pillar 1 (coinbase arm): a coinbase OP_RETURN output other than the
//     witness commitment is rejected bad-cb-opreturn.
//
// The non-coinbase OP_RETURN rule (bad-txns-opreturn-forbidden) and the P2MR
// non-financial witness leaf rule (bad-txns-nonfinancial-witness) are covered
// by the functional test.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <key.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

//! Activate the content-elimination rules at height 101, i.e. the first block
//! mined on top of the 100-block TestChain100Setup chain.
constexpr int CONTENT_ELIMINATION_HEIGHT{101};

TestOpts ContentEliminationOpts()
{
    TestOpts opts;
    opts.extra_args = {"-regtestcontenteliminationheight=101"};
    return opts;
}

struct ContentEliminationSetup : public TestChain100Setup {
    ContentEliminationSetup()
        : TestChain100Setup(ChainType::REGTEST, ContentEliminationOpts()) {}

    //! Coinbase output script matching the one the base fixture mines with.
    CScript CoinbaseScript() const
    {
        return GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    }

    int NextHeight() const
    {
        return WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Height()) + 1;
    }

    //! Recompute the witness commitment + merkle root after a coinbase mutation
    //! and re-mine a valid consensus header.
    void Reseal(CBlock& block)
    {
        node::RegenerateCommitments(block, *Assert(m_node.chainman));
        const int height{NextHeight()};
        BOOST_REQUIRE(MineHeaderForConsensus(block, static_cast<uint32_t>(height),
                                             m_node.chainman->GetConsensus()));
    }

    //! Run full block validity against the current tip and return the reject
    //! reason (empty string means the block is valid).
    std::string RejectReason(const CBlock& block)
    {
        LOCK(::cs_main);
        BlockValidationState state;
        Chainstate& chainstate{m_node.chainman->ActiveChainstate()};
        const bool ok{TestBlockValidity(state, Params(), chainstate, block,
                                        chainstate.m_chain.Tip())};
        if (ok) return {};
        return state.GetRejectReason();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(content_elimination_tests, ContentEliminationSetup)

// Sanity: the rules are active at the first post-100 block, yet an ordinary
// block (coinbase carrying only the witness commitment) still validates.
BOOST_AUTO_TEST_CASE(active_baseline_block_is_valid)
{
    BOOST_REQUIRE(m_node.chainman->GetConsensus().IsContentEliminationActive(CONTENT_ELIMINATION_HEIGHT));

    CBlock block{CreateBlock({}, CoinbaseScript(),
                             m_node.chainman->ActiveChainstate(), /*use_mempool=*/false)};
    BOOST_CHECK_EQUAL(RejectReason(block), "");
}

// Pillar 5: a coinbase scriptSig above the 40-byte content bound is rejected.
// The BIP34 height push is preserved as the prefix so the block fails on the
// content rule, not on BIP34.
BOOST_AUTO_TEST_CASE(coinbase_scriptsig_over_bound_is_rejected)
{
    CBlock block{CreateBlock({}, CoinbaseScript(),
                             m_node.chainman->ActiveChainstate(), /*use_mempool=*/false)};

    CMutableTransaction coinbase{*block.vtx[0]};
    // Height push (BIP34) + a 50-byte extranonce blob => well over 40 bytes.
    coinbase.vin[0].scriptSig = CScript() << NextHeight()
                                          << std::vector<unsigned char>(50, 0x00);
    BOOST_REQUIRE_GT(coinbase.vin[0].scriptSig.size(), 40U);
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    Reseal(block);

    BOOST_CHECK_EQUAL(RejectReason(block), "bad-cb-scriptsig-content");
}

// Pillar 1 (coinbase arm): a coinbase OP_RETURN output that is not the witness
// commitment is rejected.
BOOST_AUTO_TEST_CASE(coinbase_extra_opreturn_is_rejected)
{
    CBlock block{CreateBlock({}, CoinbaseScript(),
                             m_node.chainman->ActiveChainstate(), /*use_mempool=*/false)};

    CMutableTransaction coinbase{*block.vtx[0]};
    // A small extra data OP_RETURN (under the 83-byte size cap, so it clears
    // CheckReducedDataOutputLimits and is caught by the content rule). Reseal
    // re-appends the witness commitment after this output, so the commitment
    // stays the only permitted coinbase OP_RETURN.
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef});
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    Reseal(block);

    BOOST_CHECK_EQUAL(RejectReason(block), "bad-cb-opreturn");
}

BOOST_AUTO_TEST_SUITE_END()
