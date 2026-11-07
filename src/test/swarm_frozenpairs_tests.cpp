// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_frozenpairs.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_frozenpairs_tests, BasicTestingSetup)

static modelnet::SwarmFrozenPairs NotedPairs()
{
    modelnet::SwarmFrozenPairs note;
    note.model_id = "model-1";
    note.pair_count = 8;
    note.want_unfreeze = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_model_id_is_pairs)
{
    modelnet::SwarmFrozenPairs note = NotedPairs();
    note.model_id.clear();
    note.want_unfreeze = true;
    std::string err = "prior";
    const modelnet::SwarmFrozenPairsResult result = modelnet::SwarmNoteFrozenPairs(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "PAIRS");
    BOOST_CHECK_EQUAL(err, "PAIRS");
}

BOOST_AUTO_TEST_CASE(negative_pair_count_is_pairs)
{
    modelnet::SwarmFrozenPairs note = NotedPairs();
    note.pair_count = -1;
    note.want_unfreeze = true;
    std::string err = "prior";
    const modelnet::SwarmFrozenPairsResult result = modelnet::SwarmNoteFrozenPairs(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "PAIRS");
    BOOST_CHECK_EQUAL(err, "PAIRS");
}

BOOST_AUTO_TEST_CASE(want_unfreeze_with_eight_pairs_is_frozen)
{
    modelnet::SwarmFrozenPairs note = NotedPairs();
    note.pair_count = 8;
    note.want_unfreeze = true;
    std::string err = "prior";
    const modelnet::SwarmFrozenPairsResult result = modelnet::SwarmNoteFrozenPairs(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(note.pair_count, 8);
}

BOOST_AUTO_TEST_CASE(seven_pairs_is_frozen)
{
    modelnet::SwarmFrozenPairs note = NotedPairs();
    note.pair_count = 7;
    note.want_unfreeze = false;
    std::string err = "prior";
    const modelnet::SwarmFrozenPairsResult result = modelnet::SwarmNoteFrozenPairs(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(eight_pairs_without_unfreeze_is_noted)
{
    modelnet::SwarmFrozenPairs note = NotedPairs();
    note.pair_count = 8;
    note.want_unfreeze = false;
    std::string err = "prior";
    const modelnet::SwarmFrozenPairsResult result = modelnet::SwarmNoteFrozenPairs(note, err);
    BOOST_CHECK(!result.changed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(note.model_id, "model-1");
    BOOST_CHECK_EQUAL(note.pair_count, 8);
}

BOOST_AUTO_TEST_SUITE_END()
