// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflatcap2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoflatcap2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_manifest_id)
{
    modelnet::SwarmNotNoFlatCap2 note;
    note.manifest_id.clear();
    note.entries = 16385;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlatCap2Result result = modelnet::SwarmNoteNotNoFlatCap2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(entries_above_16384)
{
    modelnet::SwarmNotNoFlatCap2 note;
    note.manifest_id = "manifest-1";
    note.entries = 16385;
    note.want_store = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlatCap2Result result = modelnet::SwarmNoteNotNoFlatCap2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_store_at_16384)
{
    modelnet::SwarmNotNoFlatCap2 note;
    note.manifest_id = "manifest-1";
    note.entries = 16384;
    note.want_store = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlatCap2Result result = modelnet::SwarmNoteNotNoFlatCap2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(plain_note_at_16384)
{
    modelnet::SwarmNotNoFlatCap2 note;
    BOOST_CHECK(!note.want_store);
    note.manifest_id = "manifest-1";
    note.entries = 16384;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlatCap2Result result = modelnet::SwarmNoteNotNoFlatCap2(note, err);
    BOOST_CHECK(!result.stored);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
