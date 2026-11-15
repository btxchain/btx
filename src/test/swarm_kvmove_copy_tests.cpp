// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/swarm_kvmove.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_FIXTURE_TEST_SUITE(swarm_kvmove_copy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(memory_engine_copies_src_bytes_onto_dst)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{0x00, 0x11, 0x00, 0xff, 0x7f};
    const std::vector<unsigned char> dst_body{0x01, 0x02};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK(mover.body("dst") == dst_body);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));

    BOOST_CHECK(mover.Move("src", "dst", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.body("dst") == src_body);
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK_EQUAL(mover.body_size("dst"), src_body.size());
    BOOST_CHECK_EQUAL(mover.body_size("src"), src_body.size());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(src_body.size()));
    BOOST_CHECK(mover.in_kv("src"));
    BOOST_CHECK(mover.in_kv("dst"));
    BOOST_CHECK(mover.in_family("dst"));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(a_second_memory_move_adds_the_src_size_again)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30, 0x40};
    const std::vector<unsigned char> dst_body{0xaa};
    const std::vector<unsigned char> other_body{0x01, 0x02, 0x03};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_REQUIRE(mover.Put("other", "fp-same", "full", other_body, err));

    BOOST_CHECK(mover.Move("src", "dst", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(src_body.size()));

    BOOST_CHECK(mover.Move("src", "other", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.body("other") == src_body);
    BOOST_CHECK(mover.body("dst") == src_body);
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(src_body.size() * 2));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(memory_move_onto_the_same_slot_counts_the_body)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> src_body{0x50, 0x60, 0x70};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_CHECK(mover.Move("src", "src", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(mover.body("src") == src_body);
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(src_body.size()));
    BOOST_CHECK(mover.in_kv("src"));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_SUITE_END()
