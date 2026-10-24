// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflat16k.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoflat16k_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id)
{
    modelnet::SwarmNotNoFlat16k note;
    note.manifest_id.clear();
    note.count = 16385;
    note.want_flatten = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16kResult result = modelnet::SwarmNoteNotNoFlat16k(note, err);
    BOOST_CHECK(!result.flattened);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(count_16385)
{
    modelnet::SwarmNotNoFlat16k note;
    note.manifest_id = "manifest-1";
    note.count = 16385;
    note.want_flatten = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16kResult result = modelnet::SwarmNoteNotNoFlat16k(note, err);
    BOOST_CHECK(!result.flattened);
    BOOST_CHECK_EQUAL(result.code, "NOT_FLAT");
    BOOST_CHECK_EQUAL(err, "NOT_FLAT");
}

BOOST_AUTO_TEST_CASE(want_flatten_count_16384)
{
    modelnet::SwarmNotNoFlat16k note;
    note.manifest_id = "manifest-1";
    note.count = 16384;
    note.want_flatten = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16kResult result = modelnet::SwarmNoteNotNoFlat16k(note, err);
    BOOST_CHECK(!result.flattened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(quiet_note_count_16384)
{
    modelnet::SwarmNotNoFlat16k note;
    BOOST_CHECK(!note.want_flatten);
    note.manifest_id = "manifest-1";
    note.count = 16384;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16kResult result = modelnet::SwarmNoteNotNoFlat16k(note, err);
    BOOST_CHECK(!result.flattened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
