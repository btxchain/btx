// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/swarm_sigcover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sigcover_claim_tests, BasicTestingSetup)

static void ExpectFrozen(const modelnet::SwarmSigCover& book)
{
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(unknown_id_is_unqualified)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.Claim("missing", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.Claim("", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.covered("missing"));
    BOOST_CHECK_EQUAL(book.preimage_len("missing"), -1);
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.secp_penalty());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(covered_id_with_preimage_is_still_unqualified)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("claim-a", true, err));
    BOOST_CHECK(book.Preimage("claim-a", 32, err));
    BOOST_CHECK(book.covered("claim-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("claim-a"), 32);
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.Claim("claim-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK(!book.signed_ok());
    BOOST_CHECK_EQUAL(book.automatic_spend(), "0");
    BOOST_CHECK(book.covered("claim-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("claim-a"), 32);

    BOOST_CHECK(!book.Claim("claim-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.secp_penalty());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(cover_alone_and_preimage_alone_stay_unqualified)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("claim-b", true, err));
    BOOST_CHECK(!book.Claim("claim-b", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(book.covered("claim-b"));
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.secp_penalty());

    BOOST_CHECK(book.Preimage("claim-c", 32, err));
    BOOST_CHECK(!book.Claim("claim-c", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!book.covered("claim-c"));
    BOOST_CHECK_EQUAL(book.preimage_len("claim-c"), 32);
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.secp_penalty());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(penalty_is_not_penalty_and_stores_nothing)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("claim-a", true, err));
    BOOST_CHECK(book.Preimage("claim-a", 32, err));

    BOOST_CHECK(!book.Penalty("claim-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_PENALTY");
    BOOST_CHECK(!book.secp_penalty());
    BOOST_CHECK(book.covered("claim-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("claim-a"), 32);
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.broadcast());
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.Penalty("", err));
    BOOST_CHECK_EQUAL(err, "NOT_PENALTY");
    BOOST_CHECK(!book.Penalty("missing", err));
    BOOST_CHECK_EQUAL(err, "NOT_PENALTY");
    BOOST_CHECK(!book.covered("missing"));
    BOOST_CHECK(!book.covered(""));
    BOOST_CHECK(book.covered("claim-a"));
    ExpectFrozen(book);

    BOOST_CHECK(!book.Claim("claim-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!book.secp_penalty());
}

BOOST_AUTO_TEST_SUITE_END()
