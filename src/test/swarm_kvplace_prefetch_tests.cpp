// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/swarm_kvplace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectStill(const modelnet::SwarmKvPlace& place)
{
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_prefetch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_fingerprint_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_CHECK(!place.Prefetch("fp-missing", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    BOOST_CHECK(err != "PREFIX_MISMATCH");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(empty_fingerprint_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Prefetch("", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(family_only_fingerprint_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.Prefetch("fp-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(a_never_offered_fingerprint_is_not_an_absent_engine)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(!place.Prefix("fp-other", 4, "", true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");

    BOOST_CHECK(!place.Prefetch("fp-other", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    BOOST_CHECK(err != "PREFIX_MISMATCH");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(kv_fingerprint_is_engine_absent_and_moves_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(place.in_kv("fp-a"));
    BOOST_CHECK(place.in_cohort("fp-a"));
    BOOST_CHECK(!place.Prefetch("fp-a", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

BOOST_AUTO_TEST_CASE(prefetch_ignores_a_stored_prefix)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_REQUIRE(place.Prefix("fp-a", 6, "parent-a", true, err));
    BOOST_CHECK(!place.Prefetch("fp-a", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.measured_benchmark());
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
