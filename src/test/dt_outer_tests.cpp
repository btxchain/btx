// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_outer/dt_outer.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_outer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_fields_and_failed_journal_store_nothing)
{
    modelnet::DtOuter outer;
    std::string err = "prior";

    BOOST_CHECK(outer.epoch().empty());
    BOOST_CHECK(outer.optimizer_state().empty());
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(outer.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!outer.permanent_leader());
    BOOST_CHECK(!outer.diloco_complete());
    BOOST_CHECK_EQUAL(outer.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(outer.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!outer.launched());
    BOOST_CHECK(!outer.gpu());
    BOOST_CHECK(!outer.broadcast());
    BOOST_CHECK(!outer.qualified());
    BOOST_CHECK_EQUAL(outer.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(outer.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(!outer.Commit("", "adam", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "EPOCH");
    BOOST_CHECK_EQUAL(err, modelnet::DT_OUTER_EPOCH);
    BOOST_CHECK(outer.epoch().empty());
    BOOST_CHECK(outer.optimizer_state().empty());
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(0));

    BOOST_CHECK(!outer.Commit("e1", "", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, "OPT");
    BOOST_CHECK_EQUAL(err, modelnet::DT_OUTER_OPT);
    BOOST_CHECK(outer.epoch().empty());
    BOOST_CHECK(outer.optimizer_state().empty());
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(0));

    BOOST_CHECK(!outer.Commit("e1", "adam", static_cast<int64_t>(-1), true, err));
    BOOST_CHECK_EQUAL(err, "MEMBER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_OUTER_MEMBER);
    BOOST_CHECK(outer.epoch().empty());
    BOOST_CHECK(outer.optimizer_state().empty());
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(0));

    BOOST_CHECK(!outer.Commit("e1", "adam", static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(err, modelnet::DT_OUTER_JOURNAL);
    BOOST_CHECK(outer.epoch().empty());
    BOOST_CHECK(outer.optimizer_state().empty());
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(outer.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(successful_e1_survives_failed_e2_and_replay)
{
    modelnet::DtOuter outer;
    std::string err = "prior";

    BOOST_CHECK(outer.Commit("e1", "adam", static_cast<int64_t>(2), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(outer.epoch(), "e1");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "adam");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(2));

    BOOST_CHECK(!outer.Commit("e2", "sgd", static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(err, modelnet::DT_OUTER_JOURNAL);
    BOOST_CHECK_EQUAL(outer.epoch(), "e1");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "adam");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(2));

    BOOST_CHECK(!outer.Commit("e1", "sgd", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(outer.epoch(), "e1");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "adam");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(2));

    BOOST_CHECK(!outer.Commit("", "sgd", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(err, "EPOCH");
    BOOST_CHECK_EQUAL(outer.epoch(), "e1");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "adam");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(2));

    BOOST_CHECK(!outer.Wan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(outer.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(outer.epoch(), "e1");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "adam");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(2));
    BOOST_CHECK(!outer.permanent_leader());
    BOOST_CHECK(!outer.diloco_complete());
    BOOST_CHECK_EQUAL(outer.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(outer.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!outer.launched());
    BOOST_CHECK(!outer.gpu());
    BOOST_CHECK(!outer.broadcast());
    BOOST_CHECK(!outer.qualified());
    BOOST_CHECK_EQUAL(outer.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(later_successful_epoch_replaces_the_stored_triple)
{
    modelnet::DtOuter outer;
    std::string err = "prior";

    BOOST_CHECK(outer.Commit("e1", "adam", static_cast<int64_t>(2), true, err));
    BOOST_CHECK(outer.Commit("e2", "sgd", static_cast<int64_t>(4), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(outer.epoch(), "e2");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "sgd");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(4));

    BOOST_CHECK(!outer.Commit("e2", "adam", static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(outer.epoch(), "e2");
    BOOST_CHECK_EQUAL(outer.optimizer_state(), "sgd");
    BOOST_CHECK_EQUAL(outer.membership_epoch(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(outer.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!outer.permanent_leader());
    BOOST_CHECK(!outer.diloco_complete());
}

BOOST_AUTO_TEST_SUITE_END()
