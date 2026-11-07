// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/swarm_sigcover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sigcover_skip_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(later_false_is_not_signed_and_covered_stays_true)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("skip-a", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.covered("skip-a"));
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.Cover("skip-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("skip-a"));
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);

    BOOST_CHECK(!book.Cover("skip-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("skip-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("skip-a"), -1);
}

BOOST_AUTO_TEST_CASE(later_false_leaves_a_stored_preimage)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("skip-a", true, err));
    BOOST_CHECK(book.Preimage("skip-a", 32, err));
    BOOST_CHECK_EQUAL(book.preimage_len("skip-a"), 32);
    BOOST_CHECK(!book.Cover("skip-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("skip-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("skip-a"), 32);
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(skip_one_id_leaves_another_covered)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("skip-a", true, err));
    BOOST_CHECK(book.Cover("skip-b", true, err));
    BOOST_CHECK(!book.Cover("skip-a", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("skip-a"));
    BOOST_CHECK(book.covered("skip-b"));
    BOOST_CHECK(!book.Cover("missing", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!book.covered("missing"));
    BOOST_CHECK(book.covered("skip-a"));
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_SUITE_END()
