// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_thirdleaf.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_thirdleaf_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tx_id_yields_tx)
{
    modelnet::SwarmThirdLeaf tx;
    tx.tx_id.clear();
    tx.want_build = false;
    std::string err;
    const modelnet::SwarmThirdLeafResult result = modelnet::SwarmNoteThirdLeaf(tx, err);
    BOOST_CHECK_EQUAL(result.code, "TX");
    BOOST_CHECK_EQUAL(err, "TX");
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_CASE(want_build_true_yields_held)
{
    modelnet::SwarmThirdLeaf tx;
    tx.tx_id = "noted";
    tx.want_build = true;
    std::string err;
    const modelnet::SwarmThirdLeafResult result = modelnet::SwarmNoteThirdLeaf(tx, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_CASE(want_build_false_yields_noted_with_err_empty)
{
    modelnet::SwarmThirdLeaf tx;
    tx.tx_id = "noted";
    tx.want_build = false;
    std::string err = "stale";
    const modelnet::SwarmThirdLeafResult result = modelnet::SwarmNoteThirdLeaf(tx, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.built);
}

BOOST_AUTO_TEST_SUITE_END()
