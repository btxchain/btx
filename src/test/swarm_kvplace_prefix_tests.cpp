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

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_prefix_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(length_below_one_is_prefix)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));

    BOOST_CHECK(!place.Prefix("fp-a", 0, "", true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK(!place.Prefix("fp-a", -1, "parent-a", true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(length_below_one_wins_over_a_mismatch)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Prefix("fp-missing", 0, "parent-a", false, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK(err != "PREFIX_MISMATCH");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(unknown_fingerprint_is_prefix_mismatch_not_engine_absent)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));

    BOOST_CHECK(!place.Prefix("fp-other", 4, "", true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_family("fp-other"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(mismatch_wins_over_a_causal_gap)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Prefix("fp-missing", 3, "parent-a", false, err));
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
    BOOST_CHECK(err != "CAUSAL_GAP");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(named_parent_that_is_not_known_is_a_causal_gap)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(!place.Prefix("fp-a", 8, "parent-a", false, err));
    BOOST_CHECK_EQUAL(err, "CAUSAL_GAP");
    BOOST_CHECK(err != "ENGINE_ABSENT");
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(empty_parent_is_stored_when_parent_known_is_false)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(place.Prefix("fp-a", 1, "", false, err));
    BOOST_CHECK(err.empty());
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(known_parent_is_stored)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_REQUIRE(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(place.Prefix("fp-a", 16, "parent-a", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_kv("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(a_causal_gap_does_not_block_a_later_prefix)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(!place.Prefix("fp-a", 2, "parent-a", false, err));
    BOOST_CHECK_EQUAL(err, "CAUSAL_GAP");
    BOOST_CHECK(place.Prefix("fp-a", 2, "parent-a", true, err));
    BOOST_CHECK(err.empty());
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(a_short_length_does_not_block_a_later_prefix)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(!place.Prefix("fp-a", 0, "", true, err));
    BOOST_CHECK_EQUAL(err, "PREFIX");
    BOOST_CHECK(place.Prefix("fp-a", 4, "", true, err));
    BOOST_CHECK(err.empty());
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(prefix_does_not_require_kv_membership)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_REQUIRE(place.Offer("fp-a", "4bit", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(place.Prefix("fp-a", 2, "", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!place.in_kv("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
