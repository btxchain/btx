// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorv2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorv2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_rendezvous_id_is_rv)
{
    modelnet::SwarmNotNoRv2 note;
    note.rendezvous_id.clear();
    note.public_rv = true;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRv2Result result = modelnet::SwarmNoteNotNoRv2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RV");
    BOOST_CHECK_EQUAL(err, "RV");
}

BOOST_AUTO_TEST_CASE(public_rv_is_not_opened)
{
    modelnet::SwarmNotNoRv2 note;
    note.rendezvous_id = "rv-1";
    note.public_rv = true;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRv2Result result = modelnet::SwarmNoteNotNoRv2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOT_OPENED");
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmNotNoRv2 note;
    note.rendezvous_id = "rv-1";
    note.public_rv = false;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRv2Result result = modelnet::SwarmNoteNotNoRv2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRv2 note;
    note.rendezvous_id = "rv-1";
    note.public_rv = false;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRv2Result result = modelnet::SwarmNoteNotNoRv2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
