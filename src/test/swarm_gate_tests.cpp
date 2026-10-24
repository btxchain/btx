// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortbook.h>
#include <modelnet/swarm_verify.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_cohortbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(expiry_revoke_stale_epoch_replay_and_rejoin)
{
    modelnet::SwarmCohortBook book;
    std::string err;
    BOOST_REQUIRE(book.Open(1, err));
    BOOST_REQUIRE(book.Grant("m", "l1", 1000, err));
    BOOST_CHECK(book.Admit(999, 1, "m", "l1", true, true, err));
    BOOST_CHECK_EQUAL(book.Admitted(), 1);
    BOOST_CHECK(book.Admit(999, 1, "m", "l1", true, true, err));
    BOOST_CHECK_EQUAL(book.Admitted(), 1);
    BOOST_CHECK(!book.Admit(1000, 1, "m", "l1", true, true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(!book.Admit(1001, 1, "m", "l1", true, true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");

    modelnet::SwarmCohortBook live;
    BOOST_REQUIRE(live.Open(3, err));
    BOOST_REQUIRE(live.Grant("m", "l2", 5000, err));
    BOOST_CHECK(!live.Admit(100, 2, "m", "l2", true, true, err));
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
    BOOST_REQUIRE(live.Grant("m", "l3", 5000, err));
    BOOST_CHECK(!live.Admit(100, 3, "m", "l2", true, true, err));
    BOOST_CHECK_EQUAL(err, "SUPERSEDED");
    BOOST_REQUIRE(live.Revoke("l3", err));
    BOOST_CHECK(!live.Admit(100, 3, "m", "l3", true, true, err));
    BOOST_CHECK_EQUAL(err, "REVOKED");
    BOOST_REQUIRE(live.Grant("m", "l4", 5000, err));
    BOOST_CHECK(live.Admit(100, 3, "m", "l4", true, true, err));

    fs::path dir = fs::temp_directory_path();
    dir /= fs::u8path("btx-cohort-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    BOOST_REQUIRE(live.Persist(dir, err));
    modelnet::SwarmCohortBook restored;
    BOOST_REQUIRE(restored.Load(dir, err));
    BOOST_CHECK(!restored.Admit(5000, 3, "m", "l4", true, true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_REQUIRE(restored.Grant("m", "l5", 9000, err));
    BOOST_CHECK(restored.Admit(5000, 3, "m", "l5", true, true, err));
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(swarm_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_checkpoint_stays_closed_until_every_child_matches)
{
    modelnet::SwarmVerifyBook book;
    std::string err;
    BOOST_REQUIRE(book.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_CHECK(book.State() == modelnet::SwarmVerifyState::Discovered);
    BOOST_REQUIRE(book.BeginFetch(err));
    BOOST_CHECK(!book.Finish("root", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(book.State() == modelnet::SwarmVerifyState::Incomplete);
    BOOST_CHECK(!book.Activate(err));
    BOOST_CHECK_EQUAL(err, "GATE");

    BOOST_REQUIRE(book.BeginFetch(err));
    BOOST_CHECK(!book.Submit(0, "nope", 1, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_REQUIRE(book.BeginFetch(err));
    modelnet::SwarmVerifyBook fresh;
    BOOST_REQUIRE(fresh.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_REQUIRE(fresh.BeginFetch(err));
    BOOST_CHECK(!fresh.Submit(2, "c", 2, err));
    BOOST_CHECK_EQUAL(err, "LENGTH");
    BOOST_CHECK(!fresh.Submit(5, "c", 3, err));
    BOOST_CHECK_EQUAL(err, "REORDER");

    modelnet::SwarmVerifyBook good;
    BOOST_REQUIRE(good.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_REQUIRE(good.BeginFetch(err));
    BOOST_REQUIRE(good.Submit(0, "a", 1, err));
    BOOST_REQUIRE(good.Submit(0, "a", 1, err));
    BOOST_REQUIRE(good.Submit(1, "b", 2, err));
    BOOST_CHECK(!good.Submit(1, "other", 2, err));
    BOOST_CHECK_EQUAL(err, "DUPLICATE");
    modelnet::SwarmVerifyBook ordered;
    BOOST_REQUIRE(ordered.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_REQUIRE(ordered.BeginFetch(err));
    BOOST_REQUIRE(ordered.Submit(2, "c", 3, err));
    BOOST_REQUIRE(ordered.Submit(0, "a", 1, err));
    BOOST_REQUIRE(ordered.Submit(1, "b", 2, err));
    BOOST_CHECK(!ordered.Finish("other", err));
    BOOST_CHECK_EQUAL(err, "ROOT");
    BOOST_REQUIRE(ordered.BeginFetch(err));
    BOOST_REQUIRE(ordered.Finish("root", err));
    BOOST_CHECK(ordered.State() == modelnet::SwarmVerifyState::Verified);
    BOOST_CHECK(!ordered.BytesStreamed());
    BOOST_REQUIRE(ordered.Activate(err));
    BOOST_CHECK(ordered.State() == modelnet::SwarmVerifyState::Admitted);

    modelnet::SwarmVerifyBook crash;
    BOOST_REQUIRE(crash.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_REQUIRE(crash.BeginFetch(err));
    BOOST_REQUIRE(crash.Submit(0, "a", 1, err));
    BOOST_CHECK(!crash.NotePeerGone(err));
    BOOST_CHECK_EQUAL(err, "PEER");
    fs::path dir = fs::temp_directory_path();
    dir /= fs::u8path("btx-verify-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    BOOST_REQUIRE(crash.Persist(dir, err));
    modelnet::SwarmVerifyBook restored;
    BOOST_REQUIRE(restored.Load(dir, err));
    BOOST_CHECK(restored.State() == modelnet::SwarmVerifyState::Incomplete);
    BOOST_CHECK(!restored.Activate(err));
    fs::remove_all(dir);

    modelnet::SwarmVerifyBook badlen;
    BOOST_CHECK(!badlen.Discover("root", 9, {"a", "b"}, {1, 2}, err));
    BOOST_CHECK_EQUAL(err, "LENGTH");

    modelnet::SwarmVerifyBook middle;
    BOOST_REQUIRE(middle.Discover("root", 6, {"a", "b", "c"}, {1, 2, 3}, err));
    BOOST_REQUIRE(middle.BeginFetch(err));
    BOOST_REQUIRE(middle.Submit(0, "a", 1, err));
    BOOST_REQUIRE(middle.Submit(2, "c", 3, err));
    BOOST_CHECK(!middle.Finish("root", err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK(!middle.Activate(err));
}

BOOST_AUTO_TEST_SUITE_END()
