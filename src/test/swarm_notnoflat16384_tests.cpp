// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoflat16384.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoflat16384_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_manifest_id)
{
    modelnet::SwarmNotNoFlat16384 note;
    note.manifest_id.clear();
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16384Result result = modelnet::SwarmNoteNotNoFlat16384(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(want_raise)
{
    modelnet::SwarmNotNoFlat16384 note;
    note.manifest_id = "manifest-1";
    note.want_raise = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16384Result result = modelnet::SwarmNoteNotNoFlat16384(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoFlat16384 note;
    BOOST_CHECK(!note.want_raise);
    note.manifest_id = "manifest-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoFlat16384Result result = modelnet::SwarmNoteNotNoFlat16384(note, err);
    BOOST_CHECK(!result.raised);
    BOOST_CHECK_EQUAL(result.bytes, 16384);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
