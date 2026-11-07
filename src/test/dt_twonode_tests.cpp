// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_twonode/dt_twonode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(dt_twonode_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_host_two_ranks_exchange_and_gpu_stays_absent_here)
{
    modelnet::DtTwoNode nodes;
    std::string err;
    const std::vector<unsigned char> from_a{'a', 'l', 'p', 'h', 'a'};
    const std::vector<unsigned char> from_b{'b', 'r', 'a', 'v', 'o'};
    BOOST_CHECK(nodes.Exchange(from_a, from_b, err));
    BOOST_CHECK(nodes.rank_a_received() == from_b);
    BOOST_CHECK(nodes.rank_b_received() == from_a);
    BOOST_CHECK_EQUAL(nodes.bytes_moved(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(nodes.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(nodes.ranks(), 2);
    BOOST_CHECK(!nodes.GpuRank(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!nodes.gpu());
    BOOST_CHECK(!nodes.launched());
    BOOST_CHECK_EQUAL(nodes.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
