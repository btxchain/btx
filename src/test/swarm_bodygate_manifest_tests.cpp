// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/swarm_bodygate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>

BOOST_FIXTURE_TEST_SUITE(swarm_bodygate_manifest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(manifest_caps_are_the_fixed_limits)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE_EQUAL(gate.piece_bytes(), int64_t{4194304});
    BOOST_REQUIRE_EQUAL(gate.body_cap(), int64_t{33554432});
    BOOST_REQUIRE_EQUAL(gate.manifest_cap(), int64_t{16384});
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_CASE(manifest_16385_is_flat_and_leaves_the_count)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.SetManifestEntries(gate.manifest_cap()));
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{16384});
    BOOST_REQUIRE_EQUAL(gate.code(), "OK");
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.SetManifestEntries(16385));
    BOOST_CHECK_EQUAL(gate.code(), "FLAT");
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{16384});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.SetManifestEntries(gate.manifest_cap() + 2));
    BOOST_CHECK_EQUAL(gate.code(), "FLAT");
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{16384});
}

BOOST_AUTO_TEST_CASE(negative_manifest_is_not_stored)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.SetManifestEntries(3));
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{3});

    BOOST_CHECK(!gate.SetManifestEntries(-1));
    BOOST_CHECK_EQUAL(gate.code(), "FLAT");
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{3});

    BOOST_CHECK(!gate.SetManifestEntries(int64_t{-100}));
    BOOST_CHECK_EQUAL(gate.code(), "FLAT");
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{3});
    BOOST_CHECK_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_REQUIRE(gate.SetManifestEntries(0));
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{0});
    BOOST_REQUIRE_EQUAL(gate.code(), "OK");
}

BOOST_AUTO_TEST_CASE(manifest_flat_does_not_drop_a_joined_body)
{
    modelnet::SwarmBodyGate gate;
    BOOST_REQUIRE(gate.AddPiece(0, int64_t{8}, true));
    BOOST_REQUIRE(gate.Join());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{8});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_REQUIRE(gate.SetManifestEntries(2));
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{8});
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{2});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});

    BOOST_CHECK(!gate.SetManifestEntries(16385));
    BOOST_CHECK_EQUAL(gate.code(), "FLAT");
    BOOST_REQUIRE(gate.joined());
    BOOST_REQUIRE_EQUAL(gate.bytes(), int64_t{8});
    BOOST_REQUIRE_EQUAL(gate.manifest_entries(), int64_t{2});
    BOOST_REQUIRE_EQUAL(gate.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_SUITE_END()
