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

const char* kRemoteEngines[] = {
    "nixl",
    "mooncake",
    "rdma",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvmove_remote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(nixl_mooncake_and_rdma_are_engine_absent_and_copy_nothing)
{
    modelnet::SwarmKvMove mover;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{1, 2, 3, 4, 5};
    const std::vector<unsigned char> dst_body{9, 8, 7};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));

    for (const char* engine : kRemoteEngines) {
        const std::int64_t before = mover.bytes_moved();
        BOOST_CHECK(!mover.Move("src", "dst", engine, err));
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(mover.bytes_moved(), before);
        BOOST_CHECK(mover.body("dst") == dst_body);
        BOOST_CHECK(mover.body("src") == src_body);
        BOOST_CHECK_EQUAL(mover.body_size("dst"), dst_body.size());
    }
    BOOST_CHECK_EQUAL(mover.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectCold(mover);
}

BOOST_AUTO_TEST_CASE(remote_after_a_memory_copy_leaves_bytes_moved_unchanged)
{
    modelnet::SwarmKvMove mover;
    std::string err;
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30, 0x40};
    const std::vector<unsigned char> dst_body{0xaa, 0xbb};
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_REQUIRE(mover.Move("src", "dst", "memory", err));
    BOOST_CHECK(mover.body("dst") == src_body);
    const std::int64_t moved = mover.bytes_moved();
    BOOST_CHECK_EQUAL(moved, static_cast<std::int64_t>(src_body.size()));

    for (const char* engine : kRemoteEngines) {
        BOOST_CHECK(!mover.Move("src", "dst", engine, err));
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(mover.bytes_moved(), moved);
        BOOST_CHECK(mover.body("dst") == src_body);
        BOOST_CHECK(mover.body("src") == src_body);
    }
    ExpectCold(mover);
}

BOOST_AUTO_TEST_SUITE_END()
