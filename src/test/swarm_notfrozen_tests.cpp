// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfrozen.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfrozen_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pair_id_is_pair)
{
    std::string err = "prior";
    modelnet::SwarmNotFrozen note;
    note.pair_count = 8;
    note.want_unfreeze = true;
    const modelnet::SwarmNotFrozenResult result = modelnet::SwarmNoteNotFrozen(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.code, "PAIR");
    BOOST_CHECK_EQUAL(err, "PAIR");
}

BOOST_AUTO_TEST_CASE(pair_count_seven_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotFrozen note;
    note.pair_id = "pairs-a";
    note.pair_count = 7;
    note.want_unfreeze = false;
    const modelnet::SwarmNotFrozenResult result = modelnet::SwarmNoteNotFrozen(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(want_unfreeze_with_eight_pairs_is_frozen)
{
    std::string err = "prior";
    modelnet::SwarmNotFrozen note;
    note.pair_id = "pairs-a";
    note.pair_count = 8;
    note.want_unfreeze = true;
    const modelnet::SwarmNotFrozenResult result = modelnet::SwarmNoteNotFrozen(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.code, "FROZEN");
    BOOST_CHECK_EQUAL(err, "FROZEN");
}

BOOST_AUTO_TEST_CASE(plain_note_with_eight_pairs_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotFrozen note;
    note.pair_id = "pairs-a";
    note.pair_count = 8;
    note.want_unfreeze = false;
    const modelnet::SwarmNotFrozenResult result = modelnet::SwarmNoteNotFrozen(note, err);
    BOOST_CHECK(!result.unfrozen);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
