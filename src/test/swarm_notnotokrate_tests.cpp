// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotokrate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnotokrate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_engine_id_is_engine)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTokRate note;
    note.caller_rate = true;
    note.want_advertise = true;
    const modelnet::SwarmNotNoTokRateResult result = modelnet::SwarmNoteNotNoTokRate(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
}

BOOST_AUTO_TEST_CASE(caller_rate_without_advertise_is_not_advertised)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTokRate note;
    note.engine_id = "engine-1";
    note.caller_rate = true;
    note.want_advertise = false;
    const modelnet::SwarmNotNoTokRateResult result = modelnet::SwarmNoteNotNoTokRate(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADVERTISED");
    BOOST_CHECK_EQUAL(err, "NOT_ADVERTISED");
}

BOOST_AUTO_TEST_CASE(want_advertise_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTokRate note;
    note.engine_id = "engine-1";
    note.caller_rate = false;
    note.want_advertise = true;
    const modelnet::SwarmNotNoTokRateResult result = modelnet::SwarmNoteNotNoTokRate(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoTokRate note;
    note.engine_id = "engine-1";
    note.caller_rate = false;
    note.want_advertise = false;
    const modelnet::SwarmNotNoTokRateResult result = modelnet::SwarmNoteNotNoTokRate(note, err);
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
