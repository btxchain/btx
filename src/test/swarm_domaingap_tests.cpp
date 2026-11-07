// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_domaingap.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_domaingap_tests, BasicTestingSetup)

static modelnet::SwarmDomainQuorum HeldNote()
{
    modelnet::SwarmDomainQuorum note;
    note.candidate_id = "cand-1";
    note.domains = 2;
    note.required_domains = 2;
    note.outcomes_agree = true;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_quorum)
{
    modelnet::SwarmDomainQuorum note = HeldNote();
    note.candidate_id.clear();
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult result = modelnet::SwarmNoteDomainQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(domains_below_one_is_quorum)
{
    modelnet::SwarmDomainQuorum zero = HeldNote();
    zero.domains = 0;
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult zero_result = modelnet::SwarmNoteDomainQuorum(zero, err);
    BOOST_CHECK(!zero_result.settled);
    BOOST_CHECK_EQUAL(zero_result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");

    modelnet::SwarmDomainQuorum negative = HeldNote();
    negative.domains = -1;
    err = "prior";
    const modelnet::SwarmDomainQuorumResult negative_result = modelnet::SwarmNoteDomainQuorum(negative, err);
    BOOST_CHECK(!negative_result.settled);
    BOOST_CHECK_EQUAL(negative_result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(required_domains_below_two_is_quorum)
{
    modelnet::SwarmDomainQuorum one = HeldNote();
    one.domains = 1;
    one.required_domains = 1;
    one.outcomes_agree = true;
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult one_result = modelnet::SwarmNoteDomainQuorum(one, err);
    BOOST_CHECK(!one_result.settled);
    BOOST_CHECK_EQUAL(one_result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");

    modelnet::SwarmDomainQuorum zero = HeldNote();
    zero.required_domains = 0;
    zero.outcomes_agree = true;
    err = "prior";
    const modelnet::SwarmDomainQuorumResult zero_result = modelnet::SwarmNoteDomainQuorum(zero, err);
    BOOST_CHECK(!zero_result.settled);
    BOOST_CHECK_EQUAL(zero_result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");

    modelnet::SwarmDomainQuorum negative = HeldNote();
    negative.required_domains = -2;
    err = "prior";
    const modelnet::SwarmDomainQuorumResult negative_result = modelnet::SwarmNoteDomainQuorum(negative, err);
    BOOST_CHECK(!negative_result.settled);
    BOOST_CHECK_EQUAL(negative_result.code, "QUORUM");
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(fewer_domains_than_required_is_domain_even_when_outcomes_agree)
{
    modelnet::SwarmDomainQuorum note = HeldNote();
    note.domains = 2;
    note.required_domains = 3;
    note.outcomes_agree = true;
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult result = modelnet::SwarmNoteDomainQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "DOMAIN");
    BOOST_CHECK_EQUAL(err, "DOMAIN");
}

BOOST_AUTO_TEST_CASE(disagreement_is_split)
{
    modelnet::SwarmDomainQuorum note = HeldNote();
    note.outcomes_agree = false;
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult result = modelnet::SwarmNoteDomainQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");

    modelnet::SwarmDomainQuorum extra = HeldNote();
    extra.domains = 3;
    extra.required_domains = 2;
    extra.outcomes_agree = false;
    err = "prior";
    const modelnet::SwarmDomainQuorumResult extra_result = modelnet::SwarmNoteDomainQuorum(extra, err);
    BOOST_CHECK(!extra_result.settled);
    BOOST_CHECK_EQUAL(extra_result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(agreement_is_held_and_does_not_settle)
{
    modelnet::SwarmDomainQuorum note = HeldNote();
    std::string err = "prior";
    const modelnet::SwarmDomainQuorumResult result = modelnet::SwarmNoteDomainQuorum(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());

    modelnet::SwarmDomainQuorum extra = HeldNote();
    extra.domains = 4;
    extra.required_domains = 2;
    extra.outcomes_agree = true;
    err = "prior";
    const modelnet::SwarmDomainQuorumResult extra_result = modelnet::SwarmNoteDomainQuorum(extra, err);
    BOOST_CHECK(!extra_result.settled);
    BOOST_CHECK_EQUAL(extra_result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
