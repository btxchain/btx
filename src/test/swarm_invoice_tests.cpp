// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_invoice.h>
#include <crypto/sha256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_invoice_tests, BasicTestingSetup)

namespace {

uint256 HashPreimage(const std::vector<unsigned char>& preimage)
{
    uint256 hash;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.begin());
    return hash;
}

} // namespace

BOOST_AUTO_TEST_CASE(create_reserve_reveal_stays_unqualified)
{
    modelnet::SwarmInvoiceBook book;
    std::string err;
    const std::vector<unsigned char> preimage(32, 0x42);
    const std::vector<unsigned char> other(32, 0x43);
    const std::vector<unsigned char> short_preimage(31, 0x42);
    const uint256 hashlock = HashPreimage(preimage);

    BOOST_CHECK(!book.MultiHopQualified());

    BOOST_REQUIRE(book.Open(err));
    BOOST_CHECK(!book.Open(err));
    BOOST_CHECK_EQUAL(err, "REOPEN");

    BOOST_CHECK(!book.Create("", "ben", "objective", 10, hashlock, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK(!book.Create("inv", "", "objective", 10, hashlock, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK(!book.Create("inv", "ben", "", 10, hashlock, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK(!book.Create("inv", "ben", "objective", 0, hashlock, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");

    BOOST_REQUIRE(book.Create("inv", "ben", "objective", 10, hashlock, err));
    BOOST_CHECK(!book.Create("inv", "other", "other-objective", 99, HashPreimage(other), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!book.Reserve("missing", "liq-1", err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK(!book.Reserve("inv", "", err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");

    BOOST_REQUIRE(book.Reserve("inv", "liq-1", err));
    BOOST_REQUIRE(book.Reserve("inv", "liq-1", err));

    BOOST_REQUIRE(book.Create("inv-2", "ben-2", "objective-2", 5, hashlock, err));
    BOOST_CHECK(!book.Reserve("inv-2", "liq-1", err));
    BOOST_CHECK_EQUAL(err, "DOUBLE_RESERVE");
    BOOST_REQUIRE(book.Reserve("inv-2", "liq-2", err));

    BOOST_CHECK(!book.Reveal("inv", short_preimage, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK(!book.Reveal("inv", other, err));
    BOOST_CHECK_EQUAL(err, "HASHLOCK");

    BOOST_REQUIRE(book.Reveal("inv", preimage, err));
    BOOST_CHECK(!book.Reveal("inv", preimage, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!book.MultiHopQualified());
}

BOOST_AUTO_TEST_SUITE_END()
