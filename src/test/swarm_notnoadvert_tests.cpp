// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoadvert.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoadvert_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAdvert note;
    note.caller_rate = true;
    note.want_advertise = true;
    const modelnet::SwarmNotNoAdvertResult result = modelnet::SwarmNoteNotNoAdvert(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(caller_rate_without_advertise_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAdvert note;
    note.engine_id = "engine-1";
    note.caller_rate = true;
    note.want_advertise = false;
    const modelnet::SwarmNotNoAdvertResult result = modelnet::SwarmNoteNotNoAdvert(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAdvert note;
    note.engine_id = "engine-1";
    note.caller_rate = false;
    note.want_advertise = true;
    const modelnet::SwarmNotNoAdvertResult result = modelnet::SwarmNoteNotNoAdvert(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoAdvert note;
    note.engine_id = "engine-1";
    note.caller_rate = false;
    note.want_advertise = false;
    const modelnet::SwarmNotNoAdvertResult result = modelnet::SwarmNoteNotNoAdvert(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
