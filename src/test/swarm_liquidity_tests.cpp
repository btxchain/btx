// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_liquidity.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_liquidity_tests, BasicTestingSetup)

namespace {

struct ScratchDir {
    fs::path path;
    ScratchDir()
    {
        path = fs::temp_directory_path();
        path /= fs::u8path("btx-swarm-liquidity-" + std::to_string(::getpid()));
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~ScratchDir() { fs::remove_all(path); }
};

} // namespace

BOOST_AUTO_TEST_CASE(shared_capacity_reservations_persist)
{
    modelnet::SwarmLiquidityBook book;
    std::string err;

    BOOST_REQUIRE(book.Open(1000, err));
    BOOST_REQUIRE(book.Reserve("p1", "p1", 400, err));
    BOOST_REQUIRE(book.Reserve("p2", "p2", 400, err));
    BOOST_CHECK_EQUAL(book.Reserved(), 800);
    BOOST_CHECK_EQUAL(book.Available(), 200);
    BOOST_CHECK(!book.Reserve("p3", "p3", 300, err));
    BOOST_CHECK_EQUAL(err, "DOUBLE_RESERVE");
    BOOST_CHECK_EQUAL(book.Available(), 200);
    BOOST_CHECK_EQUAL(book.Reserved(), 800);

    BOOST_REQUIRE(book.Reserve("p1", "p1", 400, err));
    BOOST_CHECK_EQUAL(book.Reserved(), 800);

    BOOST_CHECK(!book.Reserve("p1", "p1", 250, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Reserved(), 800);
    BOOST_CHECK_EQUAL(book.Available(), 200);
    BOOST_CHECK(!book.Reserve("p1", "other", 400, err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    BOOST_CHECK_EQUAL(book.Reserved(), 800);

    BOOST_REQUIRE(book.Release("p1", err));
    BOOST_CHECK_EQUAL(book.Available(), 600);
    BOOST_CHECK_EQUAL(book.Reserved(), 400);

    BOOST_REQUIRE(book.Freeze(err));
    BOOST_CHECK(!book.Reserve("p4", "p4", 100, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(book.Reserved(), 400);
    BOOST_CHECK_EQUAL(book.Available(), 600);

    const ScratchDir scratch;
    BOOST_REQUIRE(book.Persist(scratch.path, err));
    const fs::path saved = scratch.path / "swarm" / "liquidity.json";
    std::ifstream in(saved);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue root;
    BOOST_REQUIRE(root.read(raw));
    BOOST_CHECK(root.exists("capacity"));
    BOOST_CHECK(root.exists("frozen"));
    BOOST_CHECK(root.exists("reservations"));
    BOOST_CHECK(!root.exists("spend"));
    BOOST_CHECK(!root.exists("automatic_spend"));
    BOOST_CHECK(!root.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(root["capacity"].getInt<int64_t>(), 1000);
    BOOST_CHECK(root["frozen"].get_bool());
    BOOST_REQUIRE(root["reservations"].isArray());
    BOOST_CHECK_EQUAL(root["reservations"].size(), 1U);
    BOOST_CHECK_EQUAL(root["reservations"][0]["reservation_id"].get_str(), "p2");
    BOOST_CHECK_EQUAL(root["reservations"][0]["pool_id"].get_str(), "p2");
    BOOST_CHECK_EQUAL(root["reservations"][0]["atoms"].getInt<int64_t>(), 400);

    modelnet::SwarmLiquidityBook restored;
    BOOST_REQUIRE(restored.Load(scratch.path, err));
    BOOST_CHECK_EQUAL(restored.Reserved(), 400);
    BOOST_CHECK_EQUAL(restored.Available(), 600);
    BOOST_CHECK(!restored.Reserve("p5", "p5", 50, err));
    BOOST_CHECK_EQUAL(err, "FROZEN");
    BOOST_CHECK_EQUAL(restored.Reserved(), 400);
    BOOST_CHECK_EQUAL(restored.Available(), 600);
}

BOOST_AUTO_TEST_SUITE_END()
