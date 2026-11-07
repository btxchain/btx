// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_graph.h>
#include <modelnet/swarm_manifest.h>
#include <modelnet/swarm_piece.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_manifest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_manifest_is_usable_only_when_every_piece_verifies)
{
    std::string err;
    modelnet::SwarmArtifactManifest manifest;
    BOOST_CHECK(!modelnet::SwarmSplitManifest({}, manifest, err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK(!manifest.usable);

    const std::vector<unsigned char> small{1, 2, 3, 4, 5};
    BOOST_REQUIRE(modelnet::SwarmSplitManifest(small, manifest, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.usable);
    BOOST_CHECK_EQUAL(manifest.artifact_id, modelnet::SwarmPieceDigest(small));
    BOOST_CHECK_EQUAL(manifest.length, 5U);
    BOOST_REQUIRE_EQUAL(manifest.pieces.size(), 1U);
    BOOST_CHECK_EQUAL(manifest.pieces[0].id, modelnet::SwarmPieceDigest(small));
    BOOST_CHECK_EQUAL(manifest.pieces[0].offset, 0U);
    BOOST_CHECK_EQUAL(manifest.pieces[0].length, 5U);
    BOOST_CHECK(manifest.pieces[0].verified);

    std::vector<unsigned char> wide(modelnet::SWARM_PIECE_BYTES + 1, 7);
    BOOST_REQUIRE(modelnet::SwarmSplitManifest(wide, manifest, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.usable);
    BOOST_CHECK_EQUAL(manifest.artifact_id, modelnet::SwarmPieceDigest(wide));
    BOOST_CHECK_EQUAL(manifest.length, wide.size());
    BOOST_REQUIRE_EQUAL(manifest.pieces.size(), 2U);
    const std::vector<unsigned char> first(wide.begin(), wide.begin() + static_cast<std::ptrdiff_t>(modelnet::SWARM_PIECE_BYTES));
    const std::vector<unsigned char> last(wide.end() - 1, wide.end());
    BOOST_CHECK_EQUAL(manifest.pieces[0].id, modelnet::SwarmPieceDigest(first));
    BOOST_CHECK_EQUAL(manifest.pieces[0].offset, 0U);
    BOOST_CHECK_EQUAL(manifest.pieces[0].length, modelnet::SWARM_PIECE_BYTES);
    BOOST_CHECK(manifest.pieces[0].verified);
    BOOST_CHECK_EQUAL(manifest.pieces[1].id, modelnet::SwarmPieceDigest(last));
    BOOST_CHECK_EQUAL(manifest.pieces[1].offset, modelnet::SWARM_PIECE_BYTES);
    BOOST_CHECK_EQUAL(manifest.pieces[1].length, 1U);
    BOOST_CHECK(manifest.pieces[1].verified);
    BOOST_CHECK_EQUAL(manifest.pieces[0].length + manifest.pieces[1].length, wide.size());

    BOOST_CHECK(!modelnet::SwarmResumeManifest(manifest, {manifest.pieces[0].id}, err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!manifest.usable);
    BOOST_CHECK(manifest.pieces[0].verified);
    BOOST_CHECK(!manifest.pieces[1].verified);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_graph_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_child_prefetch_without_an_engine_moves_no_bytes)
{
    std::string err;
    const modelnet::SwarmWorkHint absent = modelnet::SwarmPlanWorkGraph(true, true, true, true, false, err);
    BOOST_CHECK(absent.retain_parent);
    BOOST_CHECK(absent.prefetch_child);
    BOOST_CHECK(absent.demote_inactive);
    BOOST_CHECK(absent.prefer_ancestor);
    BOOST_CHECK(!absent.bytes_moved);
    BOOST_CHECK_EQUAL(absent.code, "ENGINE_ABSENT");

    const modelnet::SwarmWorkHint local = modelnet::SwarmPlanWorkGraph(false, true, false, false, true, err);
    BOOST_CHECK(!local.bytes_moved);
    BOOST_CHECK_EQUAL(local.code, "LOCAL");

    modelnet::SwarmPrefixBytes base;
    base.prefix = "abc";
    base.suffix = "de";
    modelnet::SwarmPrefixBytes out;
    BOOST_REQUIRE(modelnet::SwarmAppendCausal(base, "f", out, err));
    BOOST_CHECK_EQUAL(out.prefix, "abc");
    BOOST_CHECK_EQUAL(out.suffix, "def");
    BOOST_CHECK_EQUAL(base.prefix, "abc");

    modelnet::SwarmParticipation row;
    BOOST_REQUIRE(modelnet::SwarmNoteParticipant(row, true, true, true, true, err));
    BOOST_CHECK(row.passive);
    BOOST_CHECK(row.disappeared);
    BOOST_CHECK(row.follows_older);
    BOOST_CHECK(row.community_continues);
    BOOST_REQUIRE(modelnet::SwarmNoteParticipant(row, false, true, false, false, err));
    BOOST_CHECK(!row.community_continues);
}

BOOST_AUTO_TEST_SUITE_END()
