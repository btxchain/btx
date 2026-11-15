// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/swarm_kvmove.h>
#include <modelnet/swarm_kvremote/swarm_kvremote.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmKvRemote& remote)
{
    BOOST_CHECK(!remote.launched());
    BOOST_CHECK(!remote.gpu());
    BOOST_CHECK(!remote.broadcast());
    BOOST_CHECK_EQUAL(remote.automatic_spend(), "0");
}

const char* kRemoteEngines[] = {
    "nixl",
    "mooncake",
    "rdma",
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvremote_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(memory_transfer_copies_src_body_and_page_bytes_equal_body_size)
{
    modelnet::SwarmKvRemote remote;
    std::string err = "prior";
    const std::vector<unsigned char> body{0x10, 0x20, 0x30, 0x40, 0x50};
    BOOST_CHECK(remote.Transfer("src", "dst", body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(remote.body("dst") == remote.body("src"));
    BOOST_CHECK(remote.body("src") == body);
    BOOST_CHECK(remote.body("dst") == body);
    BOOST_CHECK_EQUAL(remote.body_size("dst"), static_cast<std::size_t>(body.size()));
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(body.size()));
    BOOST_CHECK_EQUAL(remote.bytes_moved(), remote.page_bytes());
    BOOST_CHECK(remote.in_kv("src"));
    BOOST_CHECK(remote.in_kv("dst"));
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_CASE(memory_move_matches_swarm_kvmove_bytes)
{
    modelnet::SwarmKvRemote remote;
    modelnet::SwarmKvMove mover;
    std::string remote_err = "prior";
    std::string move_err = "prior";
    const std::vector<unsigned char> src_body{0x00, 0x11, 0x00, 0xff, 0x7f};
    const std::vector<unsigned char> dst_body{0x01, 0x02};
    BOOST_REQUIRE(remote.Put("src", "fp-same", "full", src_body, remote_err));
    BOOST_REQUIRE(mover.Put("src", "fp-same", "full", src_body, move_err));
    BOOST_REQUIRE(remote.Put("dst", "fp-same", "full", dst_body, remote_err));
    BOOST_REQUIRE(mover.Put("dst", "fp-same", "full", dst_body, move_err));

    BOOST_CHECK(remote.Move("src", "dst", "memory", remote_err));
    BOOST_CHECK(mover.Move("src", "dst", "memory", move_err));
    BOOST_CHECK(remote_err.empty());
    BOOST_CHECK(remote.body("dst") == remote.body("src"));
    BOOST_CHECK(remote.body("src") == src_body);
    BOOST_CHECK(remote.body("dst") == mover.body("dst"));
    BOOST_CHECK_EQUAL(remote.bytes_moved(), mover.bytes_moved());
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(src_body.size()));
    BOOST_CHECK_EQUAL(remote.page_bytes(), remote.bytes_moved());
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_CASE(nixl_after_transfer_leaves_page_bytes_unchanged)
{
    modelnet::SwarmKvRemote remote;
    std::string err;
    const std::vector<unsigned char> body{0x10, 0x20, 0x30, 0x40};
    BOOST_REQUIRE(remote.Transfer("src", "dst", body, err));
    const std::int64_t pages = remote.page_bytes();
    BOOST_CHECK_EQUAL(pages, static_cast<std::int64_t>(body.size()));
    BOOST_CHECK(remote.body("dst") == remote.body("src"));

    BOOST_CHECK(!remote.Remote("src", "dst", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(remote.page_bytes(), pages);
    BOOST_CHECK_EQUAL(remote.bytes_moved(), pages);
    BOOST_CHECK(remote.body("dst") == body);
    BOOST_CHECK(remote.body("src") == body);
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_CASE(nixl_mooncake_and_rdma_call_move_and_add_no_bytes)
{
    modelnet::SwarmKvRemote remote;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{1, 2, 3, 4, 5};
    const std::vector<unsigned char> dst_body{9, 8, 7};
    BOOST_REQUIRE(remote.Put("src", "fp-same", "full", src_body, err));
    BOOST_REQUIRE(remote.Put("dst", "fp-same", "full", dst_body, err));
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(0));

    for (const char* engine : kRemoteEngines) {
        const std::int64_t before = remote.page_bytes();
        BOOST_CHECK(!remote.Move("src", "dst", engine, err));
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(remote.page_bytes(), before);
        BOOST_CHECK_EQUAL(remote.bytes_moved(), before);
        BOOST_CHECK(remote.body("dst") == dst_body);
        BOOST_CHECK(remote.body("src") == src_body);
    }
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(0));
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_CASE(different_fingerprints_are_not_compat_and_copy_nothing)
{
    modelnet::SwarmKvRemote remote;
    std::string err = "prior";
    const std::vector<unsigned char> src_body{0x10, 0x20, 0x30};
    const std::vector<unsigned char> dst_body{0x01, 0x02, 0x03, 0x04};
    BOOST_REQUIRE(remote.Put("src", "fp-a", "full", src_body, err));
    BOOST_REQUIRE(remote.Put("dst", "fp-b", "full", dst_body, err));
    BOOST_CHECK(remote.in_kv("src"));
    BOOST_CHECK(remote.in_kv("dst"));

    BOOST_CHECK(!remote.Move("src", "dst", "memory", err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(remote.body("dst") == dst_body);
    BOOST_CHECK(remote.body("src") == src_body);
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(0));
    BOOST_CHECK_EQUAL(remote.bytes_moved(), static_cast<std::int64_t>(0));
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_CASE(full_is_resident_and_four_bit_is_family_only)
{
    modelnet::SwarmKvRemote remote;
    std::string err = "prior";
    const std::vector<unsigned char> resident{0x10, 0x20, 0x30, 0x40};
    const std::vector<unsigned char> offered{1, 2, 3, 4, 5, 6};
    BOOST_CHECK(remote.Put("slot-full", "fp-full", "full", resident, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(remote.in_family("slot-full"));
    BOOST_CHECK(remote.in_kv("slot-full"));
    BOOST_CHECK(remote.body("slot-full") == resident);

    BOOST_CHECK(remote.Put("slot-q", "fp-q", "4bit", offered, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(remote.in_family("slot-q"));
    BOOST_CHECK(!remote.in_kv("slot-q"));
    BOOST_CHECK(remote.body("slot-q").empty());
    BOOST_CHECK_EQUAL(remote.body_size("slot-q"), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(remote.page_bytes(), static_cast<std::int64_t>(0));
    ExpectQuiet(remote);
}

BOOST_AUTO_TEST_SUITE_END()
