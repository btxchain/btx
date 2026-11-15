// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosandboxcap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosandboxcap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sandbox_id_is_sandbox)
{
    modelnet::SwarmNotNoSandboxCap2 note;
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSandboxCap2Result result = modelnet::SwarmNoteNotNoSandboxCap2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.code, "SANDBOX");
    BOOST_CHECK_EQUAL(err, "SANDBOX");
}

BOOST_AUTO_TEST_CASE(want_raise_is_capped)
{
    modelnet::SwarmNotNoSandboxCap2 note;
    note.sandbox_id = "sandbox-1";
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSandboxCap2Result result = modelnet::SwarmNoteNotNoSandboxCap2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSandboxCap2 note;
    note.sandbox_id = "sandbox-1";
    note.want_raise = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSandboxCap2Result result = modelnet::SwarmNoteNotNoSandboxCap2(note, err);
    BOOST_CHECK_EQUAL(result.raised, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
