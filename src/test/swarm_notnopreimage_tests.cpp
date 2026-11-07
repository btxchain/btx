// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopreimage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnopreimage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_preimage_id_is_preimage)
{
    modelnet::SwarmNotNoPreimage note;
    note.preimage_id.clear();
    note.length = 31;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPreimageResult result = modelnet::SwarmNoteNotNoPreimage(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(wrong_length_is_refused)
{
    modelnet::SwarmNotNoPreimage note;
    note.preimage_id = "preimage-1";
    note.length = 31;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPreimageResult result = modelnet::SwarmNoteNotNoPreimage(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(want_claim_is_refused)
{
    modelnet::SwarmNotNoPreimage note;
    note.preimage_id = "preimage-1";
    note.length = 32;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoPreimageResult result = modelnet::SwarmNoteNotNoPreimage(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "REFUSED");
    BOOST_CHECK_EQUAL(err, "REFUSED");
}

BOOST_AUTO_TEST_CASE(exact_length_plain_is_noted)
{
    modelnet::SwarmNotNoPreimage note;
    note.preimage_id = "preimage-1";
    note.length = 32;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoPreimageResult result = modelnet::SwarmNoteNotNoPreimage(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
