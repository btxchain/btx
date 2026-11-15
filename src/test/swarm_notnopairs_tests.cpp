// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopairs.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopairs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_model_id_is_model)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPairs note;
    note.pair_count = 7;
    note.want_unfreeze = true;
    const modelnet::SwarmNotNoPairsResult result = modelnet::SwarmNoteNotNoPairs(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "MODEL");
    BOOST_CHECK_EQUAL(err, "MODEL");
}

BOOST_AUTO_TEST_CASE(pair_count_other_than_eight_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPairs note;
    note.model_id = "model-1";
    note.pair_count = 7;
    note.want_unfreeze = false;
    const modelnet::SwarmNotNoPairsResult result = modelnet::SwarmNoteNotNoPairs(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(want_unfreeze_at_eight_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPairs note;
    note.model_id = "model-1";
    note.pair_count = 8;
    note.want_unfreeze = true;
    const modelnet::SwarmNotNoPairsResult result = modelnet::SwarmNoteNotNoPairs(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(plain_eight_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoPairs note;
    note.model_id = "model-1";
    note.pair_count = 8;
    note.want_unfreeze = false;
    const modelnet::SwarmNotNoPairsResult result = modelnet::SwarmNoteNotNoPairs(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.applied, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
