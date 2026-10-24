// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/digest.h>
#include <modelnet/swarm_hashlock/hashlock.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_hashlock_claim_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(std::size_t n, unsigned char fill)
{
    return std::vector<unsigned char>(n, fill);
}

std::vector<unsigned char> PaymentHash(const std::vector<unsigned char>& preimage)
{
    const uint256 digest = modelnet::SwarmHashlockSha256(preimage);
    return std::vector<unsigned char>(digest.begin(), digest.end());
}

void RequireSilent(const modelnet::SwarmHashlock& plane)
{
    BOOST_REQUIRE(!plane.qualified());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

} // namespace

BOOST_AUTO_TEST_CASE(qualified_stays_false)
{
    modelnet::SwarmHashlock plane;
    RequireSilent(plane);
    BOOST_REQUIRE(!plane.qualified());
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(unknown_id_is_invoice)
{
    modelnet::SwarmHashlock plane;
    const std::vector<unsigned char> preimage = Bytes(32, 0x5a);
    std::string err = "prior";
    BOOST_REQUIRE(!plane.Claim("missing", preimage, err));
    BOOST_REQUIRE_EQUAL(err, "INVOICE");
    BOOST_REQUIRE(!plane.claimed("missing"));
    BOOST_REQUIRE_EQUAL(plane.claims("missing"), 0);
    RequireSilent(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("", Bytes(31, 0x5a), err));
    BOOST_REQUIRE_EQUAL(err, "INVOICE");
    BOOST_REQUIRE(!plane.offered(""));
    RequireSilent(plane);
}

BOOST_AUTO_TEST_CASE(preimage_whose_size_is_not_32_claims_nothing)
{
    modelnet::SwarmHashlock plane;
    const std::vector<unsigned char> preimage = Bytes(32, 0x5a);
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("id-1", PaymentHash(preimage), err));
    BOOST_REQUIRE(err.empty());

    for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{31}, std::size_t{33}}) {
        err = "prior";
        BOOST_REQUIRE(!plane.Claim("id-1", Bytes(n, 0x5a), err));
        BOOST_REQUIRE_EQUAL(err, "PREIMAGE");
        BOOST_REQUIRE(!plane.claimed("id-1"));
        BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 0);
        BOOST_REQUIRE(plane.offered("id-1"));
        RequireSilent(plane);
    }

    BOOST_REQUIRE(plane.Claim("id-1", preimage, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);
    RequireSilent(plane);
}

BOOST_AUTO_TEST_CASE(hash_mismatch_is_hashlock_and_marks_nothing)
{
    modelnet::SwarmHashlock plane;
    const std::vector<unsigned char> preimage = Bytes(32, 0x5a);
    const std::vector<unsigned char> wrong = Bytes(32, 0x5b);
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("id-1", PaymentHash(preimage), err));

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("id-1", wrong, err));
    BOOST_REQUIRE_EQUAL(err, "HASHLOCK");
    BOOST_REQUIRE(!plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 0);
    BOOST_REQUIRE(plane.offered("id-1"));
    RequireSilent(plane);

    std::vector<unsigned char> stored;
    BOOST_REQUIRE(plane.stored_hash("id-1", stored));
    BOOST_REQUIRE(stored == PaymentHash(preimage));

    BOOST_REQUIRE(plane.Claim("id-1", preimage, err));
    BOOST_REQUIRE(plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);
    RequireSilent(plane);
}

BOOST_AUTO_TEST_CASE(matching_32_byte_claim_then_replay)
{
    const std::vector<unsigned char> preimage = Bytes(32, 0x5a);
    const uint256 single = modelnet::SwarmHashlockSha256(preimage);
    uint256 tree;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(tree.begin());
    BOOST_REQUIRE(single == tree);
    BOOST_REQUIRE(single != Hash(preimage));
    BOOST_REQUIRE_EQUAL(preimage.size(), 32U);

    modelnet::SwarmHashlock plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.Offer("id-1", PaymentHash(preimage), err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.claimed("id-1"));
    RequireSilent(plane);

    BOOST_REQUIRE(plane.Claim("id-1", preimage, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);
    RequireSilent(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("id-1", Bytes(32, 0x5b), err));
    BOOST_REQUIRE_EQUAL(err, "HASHLOCK");
    BOOST_REQUIRE(plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);

    err = "prior";
    BOOST_REQUIRE(!plane.Claim("id-1", preimage, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.claimed("id-1"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);
    RequireSilent(plane);

    const std::vector<unsigned char> other = Bytes(32, 0x6c);
    BOOST_REQUIRE(plane.Offer("id-2", PaymentHash(other), err));
    BOOST_REQUIRE(plane.Claim("id-2", other, err));
    BOOST_REQUIRE(plane.claimed("id-2"));
    BOOST_REQUIRE_EQUAL(plane.claims("id-1"), 1);
    BOOST_REQUIRE_EQUAL(plane.claims("id-2"), 1);
    BOOST_REQUIRE(!plane.qualified());
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
