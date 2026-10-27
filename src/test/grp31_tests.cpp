// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp31/grp31.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Idle(modelnet::Grp31& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp31_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(transfer_four_bytes)
{
    modelnet::Grp31 eng;
    std::string err = "prior";
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Transfer({}, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    const std::vector<unsigned char> body{1, 2, 3, 4};
    BOOST_CHECK(eng.Transfer(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(4));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(remote_rdma_adds_nothing)
{
    modelnet::Grp31 eng;
    std::string err = "prior";
    const std::vector<unsigned char> body{1, 2, 3, 4};
    BOOST_CHECK(eng.Transfer(body, err));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(4));
    const int64_t before = eng.bytes_moved();
    BOOST_CHECK(!eng.Remote("rdma", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.bytes_moved() - before, static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(4));
    BOOST_CHECK(!eng.Remote("nixl", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), before);
    BOOST_CHECK(!eng.Remote("mooncake", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(4));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(exchange_four_bytes)
{
    modelnet::Grp31 eng;
    std::string err = "prior";
    const std::vector<unsigned char> body{1, 2, 3, 4};
    BOOST_CHECK(eng.Transfer(body, err));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(4));
    const std::vector<unsigned char> payload{5, 6, 7, 8};
    BOOST_CHECK(eng.Exchange(payload, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(8));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(wan_is_no_route)
{
    modelnet::Grp31 eng;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Wan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(scan_is_not_scan)
{
    modelnet::Grp31 eng;
    std::string err = "prior";
    BOOST_CHECK(!eng.Scan("prefix", err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
