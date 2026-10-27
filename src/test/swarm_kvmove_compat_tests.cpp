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

BOOST_FIXTURE_TEST_SUITE(swarm_kvmove_compat_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fingerprint_mismatch_is_not_compat_and_copies_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30};
    const std::vector<unsigned char> dst_body{0x01, 0x02, 0x03, 0x04};
    BOOST_REQUIRE(mover.Put("src", "fp-a", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-b", "full", dst_body, err));
    BOOST_CHECK(mover.in_kv("src"));
    BOOST_CHECK(mover.in_kv("dst"));

    BOOST_CHECK(!mover.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(mover.body("dst") == dst_body);
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK_EQUAL(mover.body_size("dst"), dst_body.size());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(moving_onto_a_four_bit_dst_does_not_make_it_in_kv)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30, 0x40};
    const std::vector<unsigned char> discarded{0xaa, 0xbb, 0xcc};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "4bit", discarded, err));
    BOOST_CHECK(mover.in_kv("src"));
    BOOST_CHECK(mover.in_family("dst"));
    BOOST_CHECK(!mover.in_kv("dst"));
    BOOST_CHECK(mover.body("dst").empty());

    BOOST_CHECK(!mover.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(!mover.in_kv("dst"));
    BOOST_CHECK(mover.in_family("dst"));
    BOOST_CHECK(mover.body("dst").empty());
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(unknown_src_or_dst_is_page)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> body{0x10, 0x20};
    BOOST_REQUIRE(mover.Put("src", "fp-a", "full", body, err));

    BOOST_CHECK(!mover.Move("src", "missing", "memory", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(mover.body("src") == body);

    BOOST_CHECK(!mover.Move("missing", "src", "memory", err));
    BOOST_CHECK_EQUAL(err, "PAGE");

    BOOST_CHECK(!mover.Move("missing", "also-missing", "nixl", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(!mover.in_family("missing"));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(a_refused_slot_is_still_unknown)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> body{0x10, 0x20, 0x30};
    BOOST_REQUIRE(mover.Put("src", "fp-a", "full", body, err));
    BOOST_CHECK(!mover.Put("dst", "fp-a", "8bit", body, err));
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");

    BOOST_CHECK(!mover.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(mover.body("src") == body);
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(any_other_engine_name_is_engine_and_copies_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30};
    const std::vector<unsigned char> dst_body{0x01, 0x02};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));

    const char* names[] = {"", "cuda", "Memory", "NIXL", "vllm", "memory "};
    for (const char* engine : names) {
        BOOST_CHECK(!mover.Move("src", "dst", engine, err));
        BOOST_CHECK_EQUAL(err, "ENGINE");
        BOOST_CHECK(mover.body("dst") == dst_body);
        BOOST_CHECK(mover.body("src") == src_body);
        BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    }
    BOOST_CHECK_EQUAL(mover.body_size("dst"), dst_body.size());
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(not_compat_does_not_block_a_later_matching_memory_move)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30, 0x40};
    const std::vector<unsigned char> other_body{0x01};
    const std::vector<unsigned char> dst_body{0xaa, 0xbb};
    BOOST_REQUIRE(mover.Put("src", "fp-a", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("other", "fp-b", "full", other_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-a", "full", dst_body, err));

    BOOST_CHECK(!mover.Move("src", "other", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(mover.body("other") == other_body);

    BOOST_CHECK(mover.Move("src", "dst", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.body("dst") == src_body);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(src_body.size()));
    BOOST_CHECK_EQUAL(mover.body_size("other"), static_cast<std::size_t>(1));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_SUITE_END()
