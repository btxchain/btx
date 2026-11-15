// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/swarm_kvmove.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectCold(const modelnet::SwarmKvMove& mover)
{
    BOOST_CHECK(!mover.launched());
    BOOST_CHECK(!mover.gpu());
}

const std::vector<unsigned char> kBodyA{0x10, 0x20, 0x30, 0x40};
const std::vector<unsigned char> kBodyB{0x01, 0x02, 0x03};

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvmove_put_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_slot_is_page_and_stores_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    BOOST_CHECK(!mover.Put("", "fp-a", "full", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!mover.in_family(""));
    BOOST_CHECK(!mover.in_kv(""));
    BOOST_CHECK_EQUAL(mover.body_size(""), static_cast<std::size_t>(0));
    BOOST_CHECK(mover.body("").empty());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(empty_fingerprint_is_page_and_stores_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    BOOST_CHECK(!mover.Put("slot-a", "", "full", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!mover.in_family("slot-a"));
    BOOST_CHECK(!mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a").empty());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(empty_identity_wins_over_a_bad_quantization)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    BOOST_CHECK(!mover.Put("", "fp-a", "nope", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!mover.Put("slot-a", "", "8bit", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!mover.in_family("slot-a"));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(full_stores_the_body_and_marks_kv)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    BOOST_CHECK(mover.Put("slot-a", "fp-a", "full", kBodyA, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.in_family("slot-a"));
    BOOST_CHECK(mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a") == kBodyA);
    BOOST_CHECK_EQUAL(mover.body_size("slot-a"), kBodyA.size());
    BOOST_CHECK(!mover.in_family("slot-b"));
    BOOST_CHECK(!mover.in_kv("slot-b"));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(four_bit_is_family_only_and_drops_the_body)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    BOOST_CHECK(mover.Put("slot-a", "fp-a", "4bit", kBodyA, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.in_family("slot-a"));
    BOOST_CHECK(!mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a").empty());
    BOOST_CHECK_EQUAL(mover.body_size("slot-a"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(other_quantization_stores_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    BOOST_CHECK(mover.Put("slot-keep", "fp-keep", "4bit", kBodyA, err));

    BOOST_CHECK(!mover.Put("slot-other", "fp-other", "8bit", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_family("slot-other"));
    BOOST_CHECK(!mover.in_kv("slot-other"));

    BOOST_CHECK(!mover.Put("slot-empty-q", "fp-empty", "", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_family("slot-empty-q"));

    BOOST_CHECK(!mover.Put("slot-case", "fp-case", "Full", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.Put("slot-case2", "fp-case2", "4BIT", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_family("slot-case"));
    BOOST_CHECK(!mover.in_family("slot-case2"));
    BOOST_CHECK(mover.in_family("slot-keep"));
    BOOST_CHECK(!mover.in_kv("slot-keep"));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(full_with_an_empty_body_is_quantization)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    BOOST_CHECK(!mover.Put("slot-a", "fp-a", "full", {}, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_family("slot-a"));
    BOOST_CHECK(!mover.in_kv("slot-a"));
    BOOST_CHECK_EQUAL(mover.body_size("slot-a"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(a_refused_put_does_not_occupy_the_slot)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    BOOST_CHECK(!mover.Put("slot-a", "fp-a", "8bit", kBodyA, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(mover.Put("slot-a", "fp-a", "full", kBodyA, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a") == kBodyA);
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(second_put_is_replay_and_keeps_the_first_body)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    BOOST_CHECK(mover.Put("slot-a", "fp-a", "full", kBodyA, err));
    BOOST_CHECK(!mover.Put("slot-a", "fp-b", "full", kBodyB, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(mover.in_family("slot-a"));
    BOOST_CHECK(mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a") == kBodyA);
    BOOST_CHECK_EQUAL(mover.body_size("slot-a"), kBodyA.size());

    BOOST_CHECK(!mover.Put("slot-a", "fp-a", "nope", kBodyB, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(mover.body("slot-a") == kBodyA);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(replay_of_a_family_slot_does_not_upgrade_it_to_kv)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    BOOST_CHECK(mover.Put("slot-a", "fp-a", "4bit", kBodyA, err));
    BOOST_CHECK(!mover.Put("slot-a", "fp-a", "full", kBodyB, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(mover.in_family("slot-a"));
    BOOST_CHECK(!mover.in_kv("slot-a"));
    BOOST_CHECK(mover.body("slot-a").empty());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_SUITE_END()
