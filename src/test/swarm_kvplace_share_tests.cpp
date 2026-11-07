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

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_share_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(different_kv_fingerprints_are_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_REQUIRE(place.Offer("fp-b", "full", "ckpt-b", "recipe-b", err));
    BOOST_CHECK(place.in_kv("fp-a"));
    BOOST_CHECK(place.in_kv("fp-b"));
    BOOST_CHECK(!place.Share("fp-a", "fp-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(the_same_fingerprint_outside_kv_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.Share("fp-a", "fp-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(an_unknown_fingerprint_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Share("fp-missing", "fp-missing", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(!place.Share("", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(one_side_outside_kv_is_not_compat)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_REQUIRE(place.Offer("fp-b", "4bit", "", "", err));
    BOOST_CHECK(!place.Share("fp-a", "fp-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(place.in_kv("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-b"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(the_same_kv_fingerprint_shares)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(place.in_kv("fp-a"));
    BOOST_CHECK(place.in_cohort("fp-a"));
    BOOST_CHECK(place.Share("fp-a", "fp-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(place.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!place.launched());
    BOOST_CHECK(!place.gpu());
    BOOST_CHECK(!place.measured_benchmark());
}

BOOST_AUTO_TEST_CASE(sharing_again_stays_true_and_a_refusal_does_not_block_it)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(!place.Share("fp-a", "fp-other", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(place.Share("fp-a", "fp-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.Share("fp-a", "fp-a", err));
    BOOST_CHECK(err.empty());
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
