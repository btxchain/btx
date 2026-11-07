// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvfabric_control_tests, BasicTestingSetup)

static void ExpectNoMove(const modelnet::SwarmKvFabric& fabric, const modelnet::SwarmKvFabricResult& result)
{
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.bytes, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(result.advertised, false);
    BOOST_CHECK_EQUAL(result.qualified, false);
    BOOST_CHECK_EQUAL(result.published, false);
    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
}

BOOST_AUTO_TEST_CASE(control_plane_records_without_moving_bytes)
{
    modelnet::SwarmKvFabric fabric;

    const modelnet::SwarmKvFabricResult early = fabric.Prefetch("page-1");
    BOOST_CHECK_EQUAL(early.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    BOOST_CHECK(!fabric.process_started());
    ExpectNoMove(fabric, early);

    const modelnet::SwarmKvFabricResult absent = fabric.Probe("vllm", false);
    BOOST_CHECK_EQUAL(absent.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(fabric.engine_installed(), false);
    ExpectNoMove(fabric, absent);

    const modelnet::SwarmKvFabricResult still = fabric.Prefetch("page-1");
    BOOST_CHECK_EQUAL(still.code, "ENGINE_ABSENT");
    BOOST_CHECK(!fabric.prefetched("page-1"));
    ExpectNoMove(fabric, still);

    const modelnet::SwarmKvFabricResult installed = fabric.Probe("vllm", true);
    BOOST_REQUIRE_EQUAL(installed.code, "INSTALLED");
    BOOST_CHECK_EQUAL(fabric.advertised(), false);
    BOOST_CHECK_EQUAL(fabric.qualified(), false);
    BOOST_CHECK_EQUAL(fabric.process_started(), false);
    ExpectNoMove(fabric, installed);

    const modelnet::SwarmKvFabricResult empty_place = fabric.Place("", "fam-a");
    BOOST_CHECK_EQUAL(empty_place.code, "PAGE");
    BOOST_CHECK(!fabric.placed(""));
    ExpectNoMove(fabric, empty_place);

    const modelnet::SwarmKvFabricResult placed = fabric.Place("page-1", "fam-a");
    BOOST_REQUIRE_EQUAL(placed.code, "PLACED");
    BOOST_CHECK(fabric.placed("page-1"));
    BOOST_CHECK(!fabric.holds_family());
    ExpectNoMove(fabric, placed);

    const modelnet::SwarmKvFabricResult same = fabric.Share("page-1", "fam-a", "fam-a", true);
    BOOST_CHECK_EQUAL(same.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, same);

    const modelnet::SwarmKvFabricResult incompatible = fabric.Share("page-1", "fam-a", "fam-b", false);
    BOOST_CHECK_EQUAL(incompatible.code, "NOT_COMPAT");
    BOOST_CHECK(!fabric.shared("page-1"));
    ExpectNoMove(fabric, incompatible);

    const modelnet::SwarmKvFabricResult shared = fabric.Share("page-1", "fam-a", "fam-b", true);
    BOOST_REQUIRE_EQUAL(shared.code, "SHARED");
    BOOST_CHECK(fabric.shared("page-1"));
    ExpectNoMove(fabric, shared);

    const modelnet::SwarmKvFabricResult prefetched = fabric.Prefetch("page-1");
    BOOST_REQUIRE_EQUAL(prefetched.code, "PREFETCH");
    BOOST_CHECK(fabric.prefetched("page-1"));
    BOOST_CHECK(!fabric.cuda_buffer());
    ExpectNoMove(fabric, prefetched);

    const modelnet::SwarmKvFabricResult read = fabric.Read("member-b", "page-1");
    BOOST_REQUIRE_EQUAL(read.code, "READ");
    BOOST_CHECK(fabric.read_recorded("member-b", "page-1"));
    ExpectNoMove(fabric, read);

    const modelnet::SwarmKvFabricResult revoked = fabric.Revoke("member-a");
    BOOST_REQUIRE_EQUAL(revoked.code, "REVOKED");
    ExpectNoMove(fabric, revoked);

    const modelnet::SwarmKvFabricResult blocked = fabric.Read("member-a", "page-1");
    BOOST_CHECK_EQUAL(blocked.code, "NOT_READ");
    BOOST_CHECK(!fabric.read_recorded("member-a", "page-1"));
    ExpectNoMove(fabric, blocked);

    const modelnet::SwarmKvFabricResult truncated = fabric.Accept(0);
    BOOST_CHECK_EQUAL(truncated.code, "TRUNCATED");
    BOOST_CHECK(!fabric.cache_accepted());
    BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(0));
    BOOST_CHECK(!fabric.body_retained());
    ExpectNoMove(fabric, truncated);

    const modelnet::SwarmKvFabricResult accepted = fabric.Accept(33554432);
    BOOST_REQUIRE_EQUAL(accepted.code, "ACCEPTED");
    BOOST_CHECK(fabric.cache_accepted());
    BOOST_CHECK_EQUAL(fabric.admitted_size(), static_cast<int64_t>(33554432));
    BOOST_CHECK(!fabric.body_retained());
    ExpectNoMove(fabric, accepted);

    const modelnet::SwarmKvFabricResult held = fabric.Publish(1);
    BOOST_CHECK_EQUAL(held.code, "HELD");
    BOOST_CHECK_EQUAL(fabric.published(), false);
    BOOST_CHECK_EQUAL(fabric.rate_stored(), false);
    ExpectNoMove(fabric, held);

    BOOST_CHECK_EQUAL(fabric.bytes_moved(), false);
    BOOST_CHECK_EQUAL(fabric.advertised(), false);
    BOOST_CHECK_EQUAL(fabric.qualified(), false);
    BOOST_CHECK_EQUAL(fabric.process_started(), false);
    BOOST_CHECK(!fabric.cuda_buffer());
}

BOOST_AUTO_TEST_SUITE_END()
