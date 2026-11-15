// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_integerkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_integerkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pair_id_is_pair)
{
    modelnet::SwarmIntegerKeep pair;
    pair.pair_id.clear();
    pair.pairs = 9;
    pair.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmIntegerKeepResult result = modelnet::SwarmKeepIntegerPairs(pair, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.pairs, 8);
    BOOST_CHECK_EQUAL(result.code, "PAIR");
    BOOST_CHECK_EQUAL(err, "PAIR");
}

BOOST_AUTO_TEST_CASE(nine_pairs_is_range)
{
    modelnet::SwarmIntegerKeep pair;
    pair.pair_id = "pair-1";
    pair.pairs = 9;
    pair.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmIntegerKeepResult result = modelnet::SwarmKeepIntegerPairs(pair, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.pairs, 8);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
}

BOOST_AUTO_TEST_CASE(want_add_with_eight_pairs_is_held)
{
    modelnet::SwarmIntegerKeep pair;
    pair.pair_id = "pair-1";
    pair.pairs = 8;
    pair.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmIntegerKeepResult result = modelnet::SwarmKeepIntegerPairs(pair, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.pairs, 8);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(eight_pairs_without_add_is_noted)
{
    modelnet::SwarmIntegerKeep pair;
    pair.pair_id = "pair-1";
    pair.pairs = 8;
    pair.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmIntegerKeepResult result = modelnet::SwarmKeepIntegerPairs(pair, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.pairs, 8);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
