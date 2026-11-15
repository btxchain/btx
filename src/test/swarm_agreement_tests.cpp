// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agreement.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agreement_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_id_is_agree)
{
    std::string err = "prior";
    modelnet::SwarmAgreement note;
    note.outcomes_agree = true;
    note.want_settle = true;
    const modelnet::SwarmAgreementResult result = modelnet::SwarmNoteAgreement(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "AGREE");
    BOOST_CHECK_EQUAL(err, "AGREE");
}

BOOST_AUTO_TEST_CASE(disagreement_with_want_settle_is_split)
{
    std::string err = "prior";
    modelnet::SwarmAgreement note;
    note.candidate_id = "cand-a";
    note.outcomes_agree = false;
    note.want_settle = true;
    const modelnet::SwarmAgreementResult result = modelnet::SwarmNoteAgreement(note, err);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms_moved, 0);
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(agreement_with_want_settle_is_not_settlement)
{
    std::string err = "prior";
    modelnet::SwarmAgreement note;
    note.candidate_id = "cand-a";
    note.outcomes_agree = true;
    note.want_settle = true;
    const modelnet::SwarmAgreementResult result = modelnet::SwarmNoteAgreement(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLEMENT");
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms_moved, 0);
    BOOST_CHECK_EQUAL(err, "NOT_SETTLEMENT");
}

BOOST_AUTO_TEST_CASE(agreement_without_want_settle_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmAgreement note;
    note.candidate_id = "cand-a";
    note.outcomes_agree = true;
    note.want_settle = false;
    const modelnet::SwarmAgreementResult result = modelnet::SwarmNoteAgreement(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms_moved, 0);
}

BOOST_AUTO_TEST_SUITE_END()
