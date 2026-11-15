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

BOOST_FIXTURE_TEST_SUITE(swarm_settlebuild_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_leaf_parses_back_to_the_same_hash)
{
    modelnet::SwarmSettleBuild book;
    std::string err = "prior";
    const std::vector<unsigned char> hash(32, 0x22);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x11);
    BOOST_REQUIRE(book.BuildClaim(hash, pubkey, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.has_claim());
    BOOST_CHECK(!book.qualified());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));

    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm parsed_algo{PQAlgorithm::ML_DSA_44};
    BOOST_CHECK(ParseP2MRHTLCSha256Leaf(book.claim_script(), parsed_hash, parsed_algo, parsed_key));
    BOOST_CHECK(parsed_hash == hash);
    BOOST_CHECK(parsed_key == pubkey);
    BOOST_CHECK(parsed_algo == PQAlgorithm::ML_DSA_44);
    BOOST_CHECK(P2MRClaimLeafPinsPreimageLength(book.claim_script()));
}

BOOST_AUTO_TEST_SUITE_END()
