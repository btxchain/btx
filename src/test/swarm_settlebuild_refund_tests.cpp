// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_settlebuild_refund_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(refund_leaf_parses_back_to_the_same_timeout)
{
    modelnet::SwarmSettleBuild book;
    std::string err = "prior";
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x33);
    BOOST_REQUIRE(book.BuildRefund(160, pubkey, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.has_refund());
    BOOST_CHECK(!book.qualified());

    int64_t parsed_timeout{0};
    PQAlgorithm parsed_algo{PQAlgorithm::ML_DSA_44};
    std::vector<unsigned char> parsed_key;
    BOOST_CHECK(ParseP2MRRefundLeaf(book.refund_script(), parsed_timeout, parsed_algo, parsed_key));
    BOOST_CHECK_EQUAL(parsed_timeout, static_cast<int64_t>(160));
    BOOST_CHECK(parsed_key == pubkey);
    BOOST_CHECK(parsed_algo == PQAlgorithm::ML_DSA_44);
}

BOOST_AUTO_TEST_CASE(timeout_below_one_stores_nothing)
{
    modelnet::SwarmSettleBuild book;
    std::string err;
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x33);
    BOOST_CHECK(!book.BuildRefund(0, pubkey, err));
    BOOST_CHECK_EQUAL(err, "TIMEOUT");
    BOOST_CHECK(!book.has_refund());
}

BOOST_AUTO_TEST_SUITE_END()
