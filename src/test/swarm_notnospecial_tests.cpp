// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnospecial.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnospecial_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_store_id_is_store)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpecial note;
    note.want_replace = true;
    const modelnet::SwarmNotNoSpecialResult result = modelnet::SwarmNoteNotNoSpecial(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "STORE");
    BOOST_CHECK_EQUAL(err, "STORE");
}

BOOST_AUTO_TEST_CASE(want_replace_is_kept)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpecial note;
    note.store_id = "store-1";
    note.want_replace = true;
    const modelnet::SwarmNotNoSpecialResult result = modelnet::SwarmNoteNotNoSpecial(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "KEPT");
    BOOST_CHECK_EQUAL(err, "KEPT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSpecial note;
    note.store_id = "store-1";
    note.want_replace = false;
    const modelnet::SwarmNotNoSpecialResult result = modelnet::SwarmNoteNotNoSpecial(note, err);
    BOOST_CHECK(!result.replaced);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
