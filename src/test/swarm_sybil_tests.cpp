// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sybil.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_sybil_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_field_is_sybil)
{
    modelnet::SwarmSybilBook book;
    std::string err = "prior";
    BOOST_CHECK(!book.Admit("", "key-1", "domain-a", err));
    BOOST_CHECK_EQUAL(err, "SYBIL");
    BOOST_CHECK_EQUAL(book.Count(), 0);
    BOOST_CHECK_EQUAL(book.Domains(), 0);

    BOOST_CHECK(!book.Admit("member-1", "", "domain-a", err));
    BOOST_CHECK_EQUAL(err, "SYBIL");

    BOOST_CHECK(!book.Admit("member-1", "key-1", "", err));
    BOOST_CHECK_EQUAL(err, "SYBIL");
    BOOST_CHECK_EQUAL(book.Count(), 0);

    const modelnet::SwarmSybilMember same = modelnet::SwarmAdmitMember("member-1", "member-1", "domain-a", err);
    BOOST_CHECK(!same.admitted);
    BOOST_CHECK(same.member_id.empty());
    BOOST_CHECK_EQUAL(err, "SYBIL");

    const modelnet::SwarmSybilMember empty = modelnet::SwarmAdmitMember("", "key-1", "domain-a", err);
    BOOST_CHECK(!empty.admitted);
    BOOST_CHECK_EQUAL(err, "SYBIL");
    BOOST_CHECK_EQUAL(book.Count(), 0);
    BOOST_CHECK_EQUAL(book.Domains(), 0);
}

BOOST_AUTO_TEST_CASE(idempotent_admit)
{
    std::string err = "prior";
    const modelnet::SwarmSybilMember gate = modelnet::SwarmAdmitMember("member-1", "key-1", "domain-a", err);
    BOOST_CHECK(gate.admitted);
    BOOST_CHECK_EQUAL(gate.member_id, "member-1");
    BOOST_CHECK_EQUAL(gate.key_id, "key-1");
    BOOST_CHECK_EQUAL(gate.trust_domain, "domain-a");
    BOOST_CHECK(err.empty());

    modelnet::SwarmSybilMember fresh;
    BOOST_CHECK(!fresh.admitted);

    modelnet::SwarmSybilBook book;
    BOOST_CHECK(book.Admit("member-1", "key-1", "domain-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    err = "prior";
    BOOST_CHECK(book.Admit("member-1", "key-1", "domain-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);
}

BOOST_AUTO_TEST_CASE(replay_of_changed_key)
{
    modelnet::SwarmSybilBook book;
    std::string err;
    BOOST_REQUIRE(book.Admit("member-1", "key-1", "domain-a", err));
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    BOOST_CHECK(!book.Admit("member-1", "key-2", "domain-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    BOOST_CHECK(!book.Admit("member-1", "key-1", "domain-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    BOOST_CHECK(book.Admit("member-1", "key-1", "domain-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    BOOST_CHECK(!book.Admit("member-1", "key-2", "domain-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(book.Count(), 1);
}

BOOST_AUTO_TEST_CASE(second_member_reuses_first_key)
{
    modelnet::SwarmSybilBook book;
    std::string err;
    BOOST_REQUIRE(book.Admit("member-1", "key-1", "domain-a", err));

    BOOST_CHECK(!book.Admit("member-2", "key-1", "domain-b", err));
    BOOST_CHECK_EQUAL(err, "SYBIL");
    BOOST_CHECK_EQUAL(book.Count(), 1);
    BOOST_CHECK_EQUAL(book.Domains(), 1);

    BOOST_CHECK(book.Admit("member-1", "key-1", "domain-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 1);

    BOOST_CHECK(book.Admit("member-2", "key-2", "domain-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Count(), 2);
    BOOST_CHECK_EQUAL(book.Domains(), 2);

    BOOST_CHECK(book.Admit("member-3", "key-3", "domain-a", err));
    BOOST_CHECK_EQUAL(book.Count(), 3);
    BOOST_CHECK_EQUAL(book.Domains(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
