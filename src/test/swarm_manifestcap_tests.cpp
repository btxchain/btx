// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifestcap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_manifestcap_tests, BasicTestingSetup)

static modelnet::SwarmManifestCap NotedManifest()
{
    modelnet::SwarmManifestCap note;
    note.manifest_id = "manifest-flat";
    note.piece_count = 64;
    note.want_accept = false;
    return note;
}

static void ExpectAcceptedStaysFalse(const modelnet::SwarmManifestCapResult& result)
{
    BOOST_CHECK(!result.accepted);
}

BOOST_AUTO_TEST_CASE(empty_manifest_id_is_manifest)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.manifest_id.clear();
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(negative_piece_count_is_manifest)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = -1;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(empty_manifest_id_wins_over_cap_and_want_accept)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.manifest_id.clear();
    note.piece_count = 16385;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(negative_piece_count_wins_over_want_accept)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = -1;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST");
    BOOST_CHECK_EQUAL(err, "MANIFEST");
}

BOOST_AUTO_TEST_CASE(one_piece_over_the_cap_is_manifest_cap)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = 16385;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST_CAP");
    BOOST_CHECK_EQUAL(err, "MANIFEST_CAP");
}

BOOST_AUTO_TEST_CASE(manifest_cap_wins_when_want_accept_is_true)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = 16385;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "MANIFEST_CAP");
    BOOST_CHECK_EQUAL(err, "MANIFEST_CAP");
}

BOOST_AUTO_TEST_CASE(want_accept_is_held)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_with_want_accept_is_held)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = 16384;
    note.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(small_manifest_is_noted)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(exact_cap_without_want_accept_is_noted)
{
    modelnet::SwarmManifestCap note = NotedManifest();
    note.piece_count = 16384;
    note.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmManifestCapResult result = modelnet::SwarmNoteManifestCap(note, err);
    ExpectAcceptedStaysFalse(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
