// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleupdate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_staleupdate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(local_step_one_stale_remote_refused_later_remote_pending)
{
    modelnet::SwarmStaleUpdate update;
    BOOST_CHECK_EQUAL(update.step(), uint64_t{0});
    BOOST_CHECK(update.hash().empty());
    BOOST_CHECK(update.pending().empty());
    BOOST_CHECK_EQUAL(update.bytes_moved(), int64_t{0});

    std::string err = "prior";
    BOOST_CHECK(!update.Local(1, "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK_EQUAL(update.step(), uint64_t{0});
    BOOST_CHECK(update.hash().empty());

    err = "prior";
    BOOST_CHECK(!update.Local(2, "h-gap", err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(update.step(), uint64_t{0});
    BOOST_CHECK(update.hash().empty());
    BOOST_CHECK(update.pending().empty());

    err = "prior";
    BOOST_CHECK(update.Local(1, "h-local", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(update.step(), uint64_t{1});
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK(update.pending().empty());
    BOOST_CHECK_EQUAL(update.bytes_moved(), int64_t{0});

    err = "prior";
    BOOST_CHECK(!update.Remote(1, "", err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK(update.pending().empty());

    err = "prior";
    BOOST_CHECK(!update.Remote(1, "h-stale", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(update.step(), uint64_t{1});
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK(update.pending().empty());

    err = "prior";
    BOOST_CHECK(!update.Remote(0, "h-older", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK(update.pending().empty());
    BOOST_CHECK_EQUAL(update.bytes_moved(), int64_t{0});

    err = "prior";
    BOOST_CHECK(update.Remote(2, "h-remote", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(update.pending(), "h-remote");
    BOOST_CHECK_EQUAL(update.step(), uint64_t{1});
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK_EQUAL(update.bytes_moved(), int64_t{0});

    err = "prior";
    BOOST_CHECK(!update.Remote(1, "h-stale-again", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(update.hash(), "h-local");
    BOOST_CHECK_EQUAL(update.pending(), "h-remote");
    BOOST_CHECK_EQUAL(update.step(), uint64_t{1});
    BOOST_CHECK_EQUAL(update.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_SUITE_END()
