// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosealed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosealed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_piece_id_is_piece)
{
    modelnet::SwarmNotNoSealed note;
    note.sealed = true;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealedResult result = modelnet::SwarmNoteNotNoSealed(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "PIECE");
    BOOST_CHECK_EQUAL(err, "PIECE");
}

BOOST_AUTO_TEST_CASE(sealed_is_realm_sealed)
{
    modelnet::SwarmNotNoSealed note;
    note.piece_id = "piece-1";
    note.sealed = true;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealedResult result = modelnet::SwarmNoteNotNoSealed(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "REALM_SEALED");
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
}

BOOST_AUTO_TEST_CASE(want_open_is_held)
{
    modelnet::SwarmNotNoSealed note;
    note.piece_id = "piece-1";
    note.sealed = false;
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealedResult result = modelnet::SwarmNoteNotNoSealed(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoSealed note;
    note.piece_id = "piece-1";
    note.sealed = false;
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoSealedResult result = modelnet::SwarmNoteNotNoSealed(note, err);
    BOOST_CHECK_EQUAL(result.opened, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
