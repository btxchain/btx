// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/pay_regtest/pay_regtest.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::PayRegtest& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.network_opened());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.network_opened());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pay_regtest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(same_pool_is_economy)
{
    modelnet::PayRegtest eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Open("channel-1", "pool-a", "pool-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::PAY_REGTEST_ECONOMY);
    BOOST_CHECK_EQUAL(err, "ECONOMY");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.network_opened());
    BOOST_CHECK(!eng.Open("channel-1", "pool-a", "pool-a", err));
    BOOST_CHECK_EQUAL(err, "ECONOMY");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(pay_keeps_held)
{
    modelnet::PayRegtest eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_CHECK(!eng.Pay("pool-a", "job-a", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.network_opened());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(settle_unqualified_moves_no_atoms)
{
    modelnet::PayRegtest eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_CHECK(!eng.Pay("pool-a", "job-a", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!eng.Settle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.network_opened());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
