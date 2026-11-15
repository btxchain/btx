// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/swarm_sigcover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sigcover_key_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(empty_id_is_sighash)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.BindKey("", "channel-key", err));
    BOOST_CHECK_EQUAL(err, "SIGHASH");
    BOOST_CHECK(!book.BindKey("", "", err));
    BOOST_CHECK_EQUAL(err, "SIGHASH");
    BOOST_CHECK(!book.covered(""));
    BOOST_CHECK_EQUAL(book.preimage_len(""), -1);
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(any_key_is_not_signed_and_stores_nothing)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(!book.BindKey("key-a", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!book.covered("key-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("key-a"), -1);
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.BindKey("key-a", "channel-key", err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!book.covered("key-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("key-a"), -1);
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);
}

BOOST_AUTO_TEST_CASE(existing_covered_record_stays_covered)
{
    modelnet::SwarmSigCover book;
    std::string err = "prior";
    BOOST_CHECK(book.Cover("key-a", true, err));
    BOOST_CHECK(book.Preimage("key-a", 32, err));
    BOOST_CHECK(book.covered("key-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("key-a"), 32);

    BOOST_CHECK(!book.BindKey("key-a", "channel-key", err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("key-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("key-a"), 32);
    BOOST_CHECK(!book.signed_ok());

    BOOST_CHECK(!book.BindKey("key-a", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(book.covered("key-a"));
    BOOST_CHECK_EQUAL(book.preimage_len("key-a"), 32);
    BOOST_CHECK(!book.signed_ok());
    ExpectFrozen(book);

    BOOST_CHECK(book.covered("key-a"));
    BOOST_CHECK(!book.Cover("key-a", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.covered("key-a"));
}

BOOST_AUTO_TEST_SUITE_END()
