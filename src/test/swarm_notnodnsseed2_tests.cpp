// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodnsseed2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodnsseed2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_seed_id_is_seed)
{
    modelnet::SwarmNotNoDnsSeed2 note;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsSeed2Result result = modelnet::SwarmNoteNotNoDnsSeed2(note, err);
    BOOST_CHECK_EQUAL(result.added, false);
    BOOST_CHECK_EQUAL(result.code, "SEED");
    BOOST_CHECK_EQUAL(err, "SEED");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    modelnet::SwarmNotNoDnsSeed2 note;
    note.seed_id = "seed-1";
    note.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsSeed2Result result = modelnet::SwarmNoteNotNoDnsSeed2(note, err);
    BOOST_CHECK_EQUAL(result.added, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoDnsSeed2 note;
    note.seed_id = "seed-1";
    note.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsSeed2Result result = modelnet::SwarmNoteNotNoDnsSeed2(note, err);
    BOOST_CHECK_EQUAL(result.added, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
