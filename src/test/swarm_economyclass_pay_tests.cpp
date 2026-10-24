// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_economyclass_pay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(work_payment_is_held_and_leaves_do_not_settle)
{
    modelnet::SwarmEconomyClass book;
    std::string err;
    BOOST_REQUIRE(book.Open("channel-1", "pool-a", "pool-b", err));

    BOOST_CHECK(!book.PayWork("pool-b", "job-b", "worker-b", err));
    BOOST_CHECK_EQUAL(err, "FUNDING");
    BOOST_CHECK_EQUAL(book.earned_balance(), static_cast<int64_t>(0));

    BOOST_CHECK(!book.PayWork("pool-a", "job-a", "worker-a", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(book.earned_balance(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");

    BOOST_CHECK(!book.Quote("pool-a", "1.00", err));
    BOOST_CHECK_EQUAL(err, "NOT_BALANCE");
    BOOST_CHECK_EQUAL(book.earned_balance(), static_cast<int64_t>(1));

    std::vector<unsigned char> hash(32, 0x22);
    std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x11);
    BOOST_REQUIRE(book.BuildLeaves(hash, pubkey, 160, err));
    BOOST_CHECK(!book.claim_script().empty());
    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm parsed_algo{PQAlgorithm::ML_DSA_44};
    BOOST_REQUIRE(ParseP2MRHTLCSha256Leaf(book.claim_script(), parsed_hash, parsed_algo, parsed_key));
    BOOST_CHECK(parsed_hash == hash);
    BOOST_CHECK(parsed_key == pubkey);
    BOOST_CHECK(P2MRClaimLeafPinsPreimageLength(book.claim_script()));
    BOOST_CHECK(!book.Settle(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
