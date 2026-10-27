// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobodycap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnobodycap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_body_id)
{
    modelnet::SwarmNotNoBodyCap2 note;
    note.body_id.clear();
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyCap2Result result = modelnet::SwarmNoteNotNoBodyCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "BODY");
    BOOST_CHECK_EQUAL(err, "BODY");
}

BOOST_AUTO_TEST_CASE(want_raise)
{
    modelnet::SwarmNotNoBodyCap2 note;
    note.body_id = "body-1";
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyCap2Result result = modelnet::SwarmNoteNotNoBodyCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoBodyCap2 note;
    note.body_id = "body-1";
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoBodyCap2Result result = modelnet::SwarmNoteNotNoBodyCap2(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(33554432));
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
