// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <script/interpreter.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

void AssertGenesisCoinbaseIsP2MR(const CChainParams& params)
{
    const CBlock& genesis = params.GenesisBlock();
    BOOST_REQUIRE(!genesis.vtx.empty());
    BOOST_REQUIRE(!genesis.vtx[0]->vout.empty());

    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    BOOST_REQUIRE(genesis.vtx[0]->vout[0].scriptPubKey.IsWitnessProgram(witness_version, witness_program));
    BOOST_CHECK_EQUAL(witness_version, 2);
    BOOST_CHECK_EQUAL(witness_program.size(), WITNESS_V2_P2MR_SIZE);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_genesis_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(genesis_coinbase_is_p2mr)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    AssertGenesisCoinbaseIsP2MR(*params);
}

BOOST_AUTO_TEST_CASE(genesis_block_valid)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const CBlock& genesis = params->GenesisBlock();

    BlockValidationState state;
    BOOST_CHECK(CheckBlock(genesis, state, params->GetConsensus(), /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true));
    BOOST_CHECK_EQUAL(genesis.nTime, 1773878400U);
    BOOST_CHECK_EQUAL(strprintf("%08x", genesis.nBits), "20147ae1");
}

BOOST_AUTO_TEST_CASE(genesis_coinbase_amount_correct)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN);
    const CBlock& genesis = params->GenesisBlock();

    BOOST_REQUIRE(!genesis.vtx.empty());
    BOOST_REQUIRE(!genesis.vtx[0]->vout.empty());
    BOOST_CHECK_EQUAL(genesis.vtx[0]->vout[0].nValue, params->GetConsensus().nInitialSubsidy);
}

BOOST_AUTO_TEST_CASE(regtest_genesis_is_p2mr)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::REGTEST);
    AssertGenesisCoinbaseIsP2MR(*params);
}

BOOST_AUTO_TEST_SUITE_END()
