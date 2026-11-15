// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomanifest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomanifest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_manifest_id)
{
    modelnet::SwarmNotNoManifest note;
    note.manifest_id.clear();
    note.over_cap = true;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoManifestResult result = modelnet::SwarmNoteNotNoManifest(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(over_cap)
{
    modelnet::SwarmNotNoManifest note;
    note.manifest_id = "manifest-1";
    note.over_cap = true;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoManifestResult result = modelnet::SwarmNoteNotNoManifest(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(want_accept)
{
    modelnet::SwarmNotNoManifest note;
    note.manifest_id = "manifest-1";
    note.over_cap = false;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoManifestResult result = modelnet::SwarmNoteNotNoManifest(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CAPPED");
    BOOST_CHECK_EQUAL(err, "CAPPED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoManifest note;
    note.manifest_id = "manifest-1";
    note.over_cap = false;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoManifestResult result = modelnet::SwarmNoteNotNoManifest(note, err);
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
