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

BOOST_FIXTURE_TEST_SUITE(swarm_kvplace_offer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_fingerprint_stores_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_CHECK(!place.Offer("", "4bit", "ckpt", "recipe", err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(!place.in_family(""));
    BOOST_CHECK(!place.in_kv(""));
    BOOST_CHECK(!place.in_cohort(""));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(empty_fingerprint_wins_over_a_bad_quantization)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Offer("", "nope", "", "", err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(!place.in_family(""));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(four_bit_is_family_only)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_CHECK(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.in_cohort("fp-a"));
    BOOST_CHECK(!place.in_family("fp-b"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(four_bit_stays_family_only_with_checkpoint_and_recipe)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-a", "4bit", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.in_cohort("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(full_with_checkpoint_and_recipe_is_family_kv_and_cohort)
{
    modelnet::SwarmKvPlace place;
    std::string err = "prior";
    BOOST_CHECK(place.Offer("fp-full", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_family("fp-full"));
    BOOST_CHECK(place.in_kv("fp-full"));
    BOOST_CHECK(place.in_cohort("fp-full"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(other_quantization_stores_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-keep", "4bit", "", "", err));
    BOOST_CHECK(!place.Offer("fp-other", "8bit", "ckpt-a", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_family("fp-other"));
    BOOST_CHECK(!place.in_kv("fp-other"));
    BOOST_CHECK(!place.in_cohort("fp-other"));
    BOOST_CHECK(place.in_family("fp-keep"));

    BOOST_CHECK(!place.Offer("fp-empty-q", "", "ckpt-a", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_family("fp-empty-q"));

    BOOST_CHECK(!place.Offer("fp-case", "Full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.Offer("fp-case2", "4BIT", "", "", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_family("fp-case"));
    BOOST_CHECK(!place.in_family("fp-case2"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(full_without_checkpoint_or_recipe_stores_nothing)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Offer("fp-a", "full", "", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.in_cohort("fp-a"));

    BOOST_CHECK(!place.Offer("fp-a", "full", "ckpt-a", "", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_family("fp-a"));

    BOOST_CHECK(!place.Offer("fp-a", "full", "", "", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!place.in_kv("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(second_offer_of_the_same_fingerprint_keeps_the_first)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(!place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(!place.in_cohort("fp-a"));

    BOOST_CHECK(!place.Offer("fp-a", "nope", "", "", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(replay_of_a_cohort_offer_does_not_drop_kv)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-full", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(!place.Offer("fp-full", "4bit", "ckpt-b", "recipe-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(place.in_family("fp-full"));
    BOOST_CHECK(place.in_kv("fp-full"));
    BOOST_CHECK(place.in_cohort("fp-full"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(a_refused_profile_does_not_block_a_later_offer)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(!place.Offer("fp-a", "8bit", "", "", err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(place.Offer("fp-a", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(place.in_kv("fp-a"));
    BOOST_CHECK(place.in_cohort("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(a_second_fingerprint_is_stored_beside_the_first)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(place.Offer("fp-b", "full", "ckpt-b", "recipe-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    BOOST_CHECK(place.in_family("fp-b"));
    BOOST_CHECK(place.in_kv("fp-b"));
    BOOST_CHECK(place.in_cohort("fp-b"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_CASE(empty_fingerprint_does_not_drop_a_stored_offer)
{
    modelnet::SwarmKvPlace place;
    std::string err;
    BOOST_CHECK(place.Offer("fp-a", "4bit", "", "", err));
    BOOST_CHECK(!place.Offer("", "full", "ckpt-a", "recipe-a", err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK(place.in_family("fp-a"));
    BOOST_CHECK(!place.in_kv("fp-a"));
    ExpectStill(place);
}

BOOST_AUTO_TEST_SUITE_END()
