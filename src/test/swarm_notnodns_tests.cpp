// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodns.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnodns_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_seed_id_is_seed)
{
    modelnet::SwarmNotNoDns note;
    note.want_fill = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsResult result = modelnet::SwarmNoteNotNoDns(note, err);
    BOOST_CHECK(!result.filled);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "SEED");
    BOOST_CHECK_EQUAL(err, "SEED");
}

BOOST_AUTO_TEST_CASE(want_fill_is_empty)
{
    modelnet::SwarmNotNoDns note;
    note.seed_id = "seed-1";
    note.want_fill = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsResult result = modelnet::SwarmNoteNotNoDns(note, err);
    BOOST_CHECK(!result.filled);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoDns note;
    note.seed_id = "seed-1";
    note.want_fill = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoDnsResult result = modelnet::SwarmNoteNotNoDns(note, err);
    BOOST_CHECK(!result.filled);
    BOOST_CHECK_EQUAL(result.seeds, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
