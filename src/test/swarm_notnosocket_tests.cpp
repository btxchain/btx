// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosocket.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosocket_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_rendezvous_id_is_rendezvous)
{
    modelnet::SwarmNotNoSocket note;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSocketResult result = modelnet::SwarmNoteNotNoSocket(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "RENDEZVOUS");
    BOOST_CHECK_EQUAL(err, "RENDEZVOUS");
}

BOOST_AUTO_TEST_CASE(want_open_is_no_socket)
{
    modelnet::SwarmNotNoSocket note;
    note.rendezvous_id = "rendezvous-1";
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSocketResult result = modelnet::SwarmNoteNotNoSocket(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NO_SOCKET");
    BOOST_CHECK_EQUAL(err, "NO_SOCKET");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSocket note;
    note.rendezvous_id = "rendezvous-1";
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSocketResult result = modelnet::SwarmNoteNotNoSocket(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
