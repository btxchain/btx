// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/swarm_sigcover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sigcover_preimage_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(empty_id_is_sighash_and_stores_nothing)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.Preimage("", 32, err));
    BOOST_CHECK_EQUAL(err, "SIGHASH");
    BOOST_CHECK_EQUAL(book.preimage_len(""), -1);
    BOOST_CHECK(!book.Preimage("", 31, err));
    BOOST_CHECK_EQUAL(err, "SIGHASH");
    BOOST_CHECK_EQUAL(book.preimage_len(""), -1);
    BOOST_CHECK(!book.covered(""));
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(length_31_stores_nothing_and_length_32_stores_32)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.Preimage("pre-a", 31, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), -1);
    BOOST_CHECK(!book.covered("pre-a"));
    ExpectFrozen(book);

    BOOST_CHECK(book.Preimage("pre-a", 32, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);
    BOOST_CHECK(!book.covered("pre-a"));
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);

    BOOST_CHECK(!book.Claim("pre-a", err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);
    BOOST_CHECK_EQUAL(book.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(other_lengths_store_nothing)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.Preimage("pre-b", 0, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.Preimage("pre-b", 33, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.Preimage("pre-b", -1, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(book.preimage_len("pre-b"), -1);
    BOOST_CHECK(book.Preimage("pre-b", 32, err));
    BOOST_CHECK_EQUAL(book.preimage_len("pre-b"), 32);
}

BOOST_AUTO_TEST_CASE(second_length_32_is_replay_and_later_31_keeps_32)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("pre-a", true, err));
    BOOST_CHECK(book.Preimage("pre-a", 32, err));
    BOOST_CHECK(book.covered("pre-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);

    BOOST_CHECK(!book.Preimage("pre-a", 32, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);
    BOOST_CHECK(book.covered("pre-a"));
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.Preimage("pre-a", 31, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);
    BOOST_CHECK(book.covered("pre-a"));
    ExpectFrozen(book);

    BOOST_CHECK(book.Preimage("pre-c", 32, err));
    BOOST_CHECK_EQUAL(book.preimage_len("pre-c"), 32);
    BOOST_CHECK_EQUAL(book.preimage_len("pre-a"), 32);
    BOOST_CHECK(!book.covered("pre-c"));
}

BOOST_AUTO_TEST_SUITE_END()
