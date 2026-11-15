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

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvmove_quant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_four_bit_slot_is_not_in_kv)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> offered{1, 2, 3, 4, 5, 6};
    BOOST_CHECK(mover.Put("slot-q", "fp-q", "4bit", offered, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.in_family("slot-q"));
    BOOST_CHECK(!mover.in_kv("slot-q"));
    BOOST_CHECK(mover.body("slot-q").empty());
    BOOST_CHECK_EQUAL(mover.body_size("slot-q"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(a_memory_move_from_four_bit_is_not_compat)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> offered{1, 2, 3, 4};
    const std::vector<unsigned char> dst_body{9, 9, 9};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "4bit", offered, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_CHECK(!mover.in_kv("src"));
    BOOST_CHECK(mover.in_kv("dst"));

    BOOST_CHECK(!mover.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!mover.in_kv("src"));
    BOOST_CHECK(mover.in_family("src"));
    BOOST_CHECK(mover.body("src").empty());
    BOOST_CHECK(mover.body("dst") == dst_body);
    BOOST_CHECK_EQUAL(mover.body_size("dst"), dst_body.size());
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(four_bit_to_four_bit_is_not_compat)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> offered{0x10, 0x20, 0x30};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "4bit", offered, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "4bit", {}, err));
    BOOST_CHECK(!mover.in_kv("src"));
    BOOST_CHECK(!mover.in_kv("dst"));

    BOOST_CHECK(!mover.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(!mover.in_kv("src"));
    BOOST_CHECK(!mover.in_kv("dst"));
    BOOST_CHECK(mover.body("dst").empty());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(full_needs_a_body_and_other_profiles_store_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> body{0x10, 0x11};

    BOOST_CHECK(!mover.Put("empty-full", "fp-a", "full", {}, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_family("empty-full"));
    BOOST_CHECK(!mover.in_kv("empty-full"));

    BOOST_CHECK(!mover.Put("int8", "fp-b", "int8", body, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
    BOOST_CHECK(!mover.in_kv("int8"));

    BOOST_CHECK(!mover.Put("blank", "fp-c", "", body, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");

    BOOST_CHECK(mover.Put("kept", "fp-d", "4bit", body, err));
    BOOST_CHECK(mover.in_family("kept"));
    BOOST_CHECK(!mover.in_kv("kept"));
    BOOST_CHECK_EQUAL(mover.body_size("kept"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_SUITE_END()
