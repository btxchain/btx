// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvwire/swarm_kvwire.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmKvWire& wire)
{
    BOOST_CHECK(!wire.launched());
    BOOST_CHECK(!wire.gpu());
    BOOST_CHECK(!wire.broadcast());
    BOOST_CHECK(!wire.connected());
    BOOST_CHECK_EQUAL(wire.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(wire.engine(), "local");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_kvwire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(transfer_receives_the_body_and_nixl_keeps_ten_bytes)
{
    modelnet::SwarmKvWire wire;
    std::string err = "prior";
    const std::vector<unsigned char> body{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    BOOST_CHECK(wire.Transfer(body, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(wire.received() == body);
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<std::int64_t>(10));
    ExpectQuiet(wire);

    const std::vector<unsigned char> kept = wire.received();
    BOOST_CHECK(!wire.Remote("nixl", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<std::int64_t>(10));
    BOOST_CHECK(wire.received() == kept);
    BOOST_CHECK(wire.received() == body);
    ExpectQuiet(wire);
}

BOOST_AUTO_TEST_CASE(mooncake_and_rdma_add_nothing_from_a_fresh_object)
{
    const char* engines[] = {"mooncake", "rdma"};
    for (const char* engine : engines) {
        modelnet::SwarmKvWire wire;
        std::string err = "prior";
        BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<std::int64_t>(0));
        BOOST_CHECK(wire.received().empty());
        BOOST_CHECK(!wire.Remote(engine, err));
        BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
        BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<std::int64_t>(0));
        BOOST_CHECK(wire.received().empty());
        ExpectQuiet(wire);
    }
}

BOOST_AUTO_TEST_CASE(empty_body_is_page_and_moves_nothing)
{
    modelnet::SwarmKvWire wire;
    std::string err = "prior";
    const std::vector<unsigned char> empty;
    BOOST_CHECK(!wire.Transfer(empty, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(wire.bytes_moved(), static_cast<std::int64_t>(0));
    BOOST_CHECK(wire.received().empty());
    ExpectQuiet(wire);
}

BOOST_AUTO_TEST_SUITE_END()
