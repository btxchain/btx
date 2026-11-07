// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_settlebuild_preimage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hash_of_31_bytes_stores_nothing)
{
    modelnet::SwarmSettleBuild book;
    std::string err;
    const std::vector<unsigned char> hash(31, 0x22);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x11);
    BOOST_CHECK(!book.BuildClaim(hash, pubkey, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.has_claim());
    BOOST_CHECK(book.claim_script().empty());
}

BOOST_AUTO_TEST_CASE(short_pubkey_stores_nothing)
{
    modelnet::SwarmSettleBuild book;
    std::string err;
    const std::vector<unsigned char> hash(32, 0x22);
    const std::vector<unsigned char> pubkey(32, 0x11);
    BOOST_CHECK(!book.BuildClaim(hash, pubkey, err));
    BOOST_CHECK_EQUAL(err, "KEY");
    BOOST_CHECK(!book.has_claim());
}

BOOST_AUTO_TEST_SUITE_END()
