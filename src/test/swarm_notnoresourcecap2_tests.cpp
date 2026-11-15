// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoresourcecap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoresourcecap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sandbox_id)
{
    modelnet::SwarmNotNoResourceCap2 note;
    std::string err = "stale";
    const modelnet::SwarmNotNoResourceCap2Result result = modelnet::SwarmNoteNotNoResourceCap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "SANDBOX");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(err, "SANDBOX");
}

BOOST_AUTO_TEST_CASE(over_cap_true_want_raise_false)
{
    modelnet::SwarmNotNoResourceCap2 note;
    note.sandbox_id = "sandbox-1";
    note.over_cap = true;
    note.want_raise = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoResourceCap2Result result = modelnet::SwarmNoteNotNoResourceCap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_raise_true_over_cap_false)
{
    modelnet::SwarmNotNoResourceCap2 note;
    note.sandbox_id = "sandbox-1";
    note.over_cap = false;
    note.want_raise = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoResourceCap2Result result = modelnet::SwarmNoteNotNoResourceCap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(neither_over_cap_nor_want_raise)
{
    modelnet::SwarmNotNoResourceCap2 note;
    note.sandbox_id = "sandbox-1";
    note.over_cap = false;
    note.want_raise = false;
    std::string err = "stale";
    const modelnet::SwarmNotNoResourceCap2Result result = modelnet::SwarmNoteNotNoResourceCap2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.raised);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
