// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_settlebuild_settle_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(settle_stays_unqualified_after_a_claim_leaf)
{
    modelnet::SwarmSettleBuild book;
    std::string err;
    const std::vector<unsigned char> hash(32, 0x44);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x55);
    BOOST_REQUIRE(book.BuildClaim(hash, pubkey, err));
    BOOST_CHECK(!book.Settle(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK(book.has_claim());
}

BOOST_AUTO_TEST_SUITE_END()
