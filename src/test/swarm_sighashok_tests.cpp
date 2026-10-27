// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sighashok.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_sighashok_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_txid_is_tx)
{
    modelnet::SwarmSighashOk gate;
    std::string err = "stale";

    BOOST_CHECK(!gate.Sign("", true, err));
    BOOST_CHECK_EQUAL(err, "TX");
    BOOST_CHECK(!gate.signed_ok(""));

    BOOST_CHECK(!gate.Sign("", false, err));
    BOOST_CHECK_EQUAL(err, "TX");
    BOOST_CHECK(!gate.signed_ok(""));
}

BOOST_AUTO_TEST_CASE(skipped_outputs_are_refused)
{
    modelnet::SwarmSighashOk gate;
    std::string err = "stale";

    BOOST_CHECK(!gate.signed_ok("tx-skip"));
    BOOST_CHECK(!gate.Sign("tx-skip", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK(!gate.signed_ok("tx-skip"));
    BOOST_CHECK(!gate.signed_ok("tx-other"));

    BOOST_CHECK(!gate.Sign("tx-skip", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!gate.signed_ok("tx-skip"));

    BOOST_CHECK(!gate.Sign("tx-skip", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!gate.signed_ok("tx-skip"));
}

BOOST_AUTO_TEST_CASE(covering_sighash_records_signed_ok)
{
    modelnet::SwarmSighashOk gate;
    std::string err = "stale";

    BOOST_CHECK(!gate.signed_ok("tx-cover"));
    BOOST_REQUIRE(gate.Sign("tx-cover", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.signed_ok("tx-cover"));
    BOOST_CHECK(!gate.signed_ok("tx-other"));

    BOOST_CHECK(!gate.Sign("tx-cover", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(gate.signed_ok("tx-cover"));

    BOOST_CHECK(!gate.Sign("tx-cover", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(gate.signed_ok("tx-cover"));

    BOOST_REQUIRE(gate.Sign("tx-other", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(gate.signed_ok("tx-cover"));
    BOOST_CHECK(gate.signed_ok("tx-other"));
}

BOOST_AUTO_TEST_SUITE_END()
