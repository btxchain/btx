// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_pay/nif_pay.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_pay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reserve_earns_once_and_settle_stays_unqualified)
{
    modelnet::NifPay pay;
    std::string err;

    BOOST_CHECK(!pay.Reserve("job", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(pay.reserved_atoms(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(0));

    BOOST_CHECK(pay.Reserve("job", static_cast<int64_t>(10), err));
    BOOST_CHECK(pay.Reserve("other", static_cast<int64_t>(3), err));
    BOOST_CHECK(!pay.Reserve("job", static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(pay.reserved_atoms(), static_cast<int64_t>(13));

    BOOST_CHECK(!pay.Accept("missing", true, err));
    BOOST_CHECK_EQUAL(err, "ATTEMPT");
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(0));

    BOOST_CHECK(pay.Accept("job", true, err));
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(pay.reserved_atoms(), static_cast<int64_t>(13));

    BOOST_CHECK(!pay.Accept("job", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(pay.reserved_atoms(), static_cast<int64_t>(13));

    BOOST_CHECK(!pay.Accept("other", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_ACCEPTED");
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(pay.reserved_atoms(), static_cast<int64_t>(13));

    BOOST_CHECK(!pay.Accept("other", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(10));

    BOOST_CHECK(!pay.Open("", "pool", err));
    BOOST_CHECK_EQUAL(err, "ECONOMY");

    const int64_t earned_before_work = pay.earned_atoms();
    BOOST_CHECK(!pay.PayWork("pool", "work", "worker", err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(pay.earned_atoms(), earned_before_work);

    BOOST_CHECK(!pay.Settle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!pay.settlement_qualified());
    BOOST_CHECK(!pay.broadcast());
    BOOST_CHECK(!pay.launched());
    BOOST_CHECK(!pay.gpu());
    BOOST_CHECK_EQUAL(pay.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(pay.earned_atoms(), static_cast<int64_t>(10));
}

BOOST_AUTO_TEST_SUITE_END()
