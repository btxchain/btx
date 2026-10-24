// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoforward2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoforward2_tests, BasicTestingSetup)

static modelnet::SwarmNotNoForward2 NotedNote()
{
    modelnet::SwarmNotNoForward2 note;
    note.hop_id = "hop-1";
    note.forwarder = false;
    note.want_charge = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoForward2 note = NotedNote();
    note.hop_id.clear();
    note.forwarder = true;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoForward2Result result = modelnet::SwarmNoteNotNoForward2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HOP");
    BOOST_CHECK_EQUAL(err, "HOP");
}

BOOST_AUTO_TEST_CASE(forwarder)
{
    modelnet::SwarmNotNoForward2 note = NotedNote();
    note.forwarder = true;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoForward2Result result = modelnet::SwarmNoteNotNoForward2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(want_charge)
{
    modelnet::SwarmNotNoForward2 note = NotedNote();
    note.hop_id = "hop-2";
    note.forwarder = false;
    note.want_charge = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoForward2Result result = modelnet::SwarmNoteNotNoForward2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_hop)
{
    modelnet::SwarmNotNoForward2 note = NotedNote();
    note.hop_id = "hop-2";
    note.forwarder = false;
    note.want_charge = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoForward2Result result = modelnet::SwarmNoteNotNoForward2(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
