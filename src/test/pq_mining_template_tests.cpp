// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <interfaces/mining.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

namespace {

class P2MRMainTemplateSetup : public TestingSetup
{
public:
    P2MRMainTemplateSetup()
        : TestingSetup{ChainType::MAIN, TestOpts{.setup_net = false}}
    {
        m_node.mining = interfaces::MakeMining(m_node);
    }

    interfaces::Mining& Mining() { return *Assert(m_node.mining); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_mining_template_tests, P2MRMainTemplateSetup)

BOOST_AUTO_TEST_CASE(default_coinbase_output_is_p2mr_on_enforcing_chains)
{
    const auto& consensus = Assert(m_node.chainman)->GetConsensus();
    BOOST_REQUIRE(consensus.fReducedDataLimits);
    BOOST_REQUIRE(consensus.fEnforceP2MROnlyOutputs);

    auto tmpl = Mining().createNewBlock();
    BOOST_REQUIRE(tmpl);

    const CBlock& block = tmpl->getBlock();
    BOOST_REQUIRE(!block.vtx.empty());
    BOOST_REQUIRE(!block.vtx.at(0)->vout.empty());

    const CScript& spk = block.vtx.at(0)->vout.at(0).scriptPubKey;
    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    BOOST_REQUIRE(spk.IsWitnessProgram(witness_version, witness_program));
    BOOST_CHECK_EQUAL(witness_version, 2);
    BOOST_CHECK_EQUAL(witness_program.size(), 32U);
}

BOOST_AUTO_TEST_CASE(rejects_non_p2mr_coinbase_output_on_enforcing_chains)
{
    const auto& consensus = Assert(m_node.chainman)->GetConsensus();
    BOOST_REQUIRE(consensus.fReducedDataLimits);
    BOOST_REQUIRE(consensus.fEnforceP2MROnlyOutputs);

    node::BlockCreateOptions options;
    options.coinbase_output_script = CScript{} << OP_TRUE;

    BOOST_CHECK_EXCEPTION(Mining().createNewBlock(options), std::runtime_error,
                          HasReason("coinbase output must be witness v2 P2MR"));
}

BOOST_AUTO_TEST_CASE(allows_op_return_coinbase_output_on_enforcing_chains)
{
    const auto& consensus = Assert(m_node.chainman)->GetConsensus();
    BOOST_REQUIRE(consensus.fReducedDataLimits);
    BOOST_REQUIRE(consensus.fEnforceP2MROnlyOutputs);

    node::BlockCreateOptions options;
    options.coinbase_output_script = CScript{} << OP_RETURN << std::vector<unsigned char>{0x01, 0x02};

    BOOST_REQUIRE(Mining().createNewBlock(options));
}

BOOST_AUTO_TEST_SUITE_END()
