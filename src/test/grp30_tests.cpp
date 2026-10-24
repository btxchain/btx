// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp30/grp30.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp30& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.compute_proof());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp30_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(req_NIF_KV_002)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-002", err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK(!eng.expired_stored());
    BOOST_CHECK(eng.open_held());
    BOOST_CHECK_EQUAL(eng.open_accepted(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.complete());
    BOOST_CHECK(!eng.compute_proof());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-KV-002", err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK(!eng.expired_stored());
    BOOST_CHECK(eng.open_held());
    BOOST_CHECK_EQUAL(eng.open_accepted(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.complete());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_KV_007)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-KV-007", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.compute_proof());
    BOOST_CHECK(!eng.complete());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NIF-KV-007", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!eng.compute_proof());
    BOOST_CHECK(!eng.qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_NIF_QA_001)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("NIF-QA-001", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.hardware_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("NIF-QA-001", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.component_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.native_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.hardware_count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.release_count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.release_count(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_GRD_003)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-GRD-003", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.gradient_pending(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Apply("DT-GRD-003", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.gradient_pending(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_006)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-006", err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!eng.incompatible_stored());
    BOOST_CHECK_EQUAL(eng.full_trajectories(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.replenished());
    BOOST_CHECK(!eng.Apply("DT-RLP-006", err));
    BOOST_CHECK_EQUAL(err, "ROUTE");
    BOOST_CHECK(!eng.incompatible_stored());
    BOOST_CHECK_EQUAL(eng.full_trajectories(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_RLP_007)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-RLP-007", err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!eng.replenished());
    BOOST_CHECK_EQUAL(eng.full_trajectories(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.short_trajectories(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Apply("DT-RLP-007", err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK(!eng.replenished());
    BOOST_CHECK_EQUAL(eng.full_trajectories(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.short_trajectories(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_DT_WAN_006)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("DT-WAN-006", err));
    BOOST_CHECK_EQUAL(err, "CHANGE");
    BOOST_CHECK(eng.delay_has_base());
    BOOST_CHECK_EQUAL(eng.delay_head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.delay_pending(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.Apply("DT-WAN-006", err));
    BOOST_CHECK_EQUAL(err, "CHANGE");
    BOOST_CHECK_EQUAL(eng.delay_head(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.delay_pending(), static_cast<int64_t>(4));
    BOOST_CHECK(eng.delay_has_base());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(req_unknown_id)
{
    modelnet::Grp30 eng;
    std::string err;
    BOOST_CHECK(!eng.Apply("", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.expired_stored());
    BOOST_CHECK(!eng.open_held());
    BOOST_CHECK(!eng.complete());
    BOOST_CHECK(!eng.compute_proof());
    BOOST_CHECK_EQUAL(eng.component_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.gradient_pending(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.full_trajectories(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.delay_head(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Apply("NO-SUCH", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.complete());
    BOOST_CHECK(!eng.compute_proof());
    BOOST_CHECK(!eng.release_qualified());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
