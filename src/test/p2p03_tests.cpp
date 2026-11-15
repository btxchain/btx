// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/p2p03/p2p03.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectStillUnqualified(const modelnet::P2p03& family)
{
    BOOST_CHECK(!family.gpu_passed());
    BOOST_CHECK(!family.windows_passed());
    BOOST_CHECK(!family.release_qualified());
    BOOST_CHECK(!family.hardware_qualified());
    BOOST_CHECK(!family.passed());
    BOOST_CHECK_EQUAL(family.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(family.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2p03_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(field_before_scheduler_or_gpus)
{
    modelnet::P2p03 family;
    std::string err = "stale";

    BOOST_CHECK(!family.JoinFamily(0, false, 0, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(!family.JoinFamily(-1, false, 1, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(!family.JoinFamily(0, true, 2, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(family.joined(), 0);
    ExpectStillUnqualified(family);
}

BOOST_AUTO_TEST_CASE(scheduler_refused_and_unshared)
{
    modelnet::P2p03 first;
    modelnet::P2p03 second;
    modelnet::P2p03 third;
    std::string err = "stale";

    BOOST_CHECK(!first.JoinFamily(3, true, 0, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(first.joined(), 0);
    BOOST_CHECK_EQUAL(second.joined(), 0);
    BOOST_CHECK_EQUAL(third.joined(), 0);

    BOOST_CHECK(!first.JoinFamily(3, true, 2, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(first.joined(), 0);

    BOOST_CHECK(second.JoinFamily(3, false, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(second.joined(), 3);
    BOOST_CHECK_EQUAL(first.joined(), 0);
    BOOST_CHECK_EQUAL(third.joined(), 0);
    BOOST_CHECK_EQUAL(second.physical_hosts(), static_cast<int64_t>(1));
    ExpectStillUnqualified(first);
    ExpectStillUnqualified(second);
    ExpectStillUnqualified(third);
}

BOOST_AUTO_TEST_CASE(two_gpus_stay_unqualified)
{
    modelnet::P2p03 family;
    std::string err = "stale";

    BOOST_CHECK(!family.JoinFamily(3, false, 2, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(!family.JoinFamily(5, false, 4, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(!family.JoinFamily(2, false, 2, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(family.joined(), 0);
    ExpectStillUnqualified(family);
}

BOOST_AUTO_TEST_CASE(local_count_is_not_three_physical_hosts)
{
    modelnet::P2p03 family;
    std::string err = "stale";

    BOOST_CHECK(!family.JoinFamily(2, false, 0, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(!family.JoinFamily(1, false, 1, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(family.joined(), 0);

    BOOST_CHECK(family.JoinFamily(3, false, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(family.joined(), 3);
    BOOST_CHECK_EQUAL(family.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(family.JoinFamily(3, false, 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(family.joined(), 3);

    BOOST_CHECK(family.JoinFamily(5, false, 0, err));
    BOOST_CHECK_EQUAL(family.joined(), 5);
    BOOST_CHECK_EQUAL(family.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(!family.JoinFamily(4, true, 0, err));
    BOOST_CHECK_EQUAL(err, "SCHEDULER");
    BOOST_CHECK_EQUAL(family.joined(), 5);
    BOOST_CHECK_EQUAL(family.physical_hosts(), static_cast<int64_t>(1));
    ExpectStillUnqualified(family);
}

BOOST_AUTO_TEST_SUITE_END()
