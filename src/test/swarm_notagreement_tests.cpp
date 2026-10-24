// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notagreement.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notagreement_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_agreement_id_is_agreement)
{
    std::string err = "prior";
    modelnet::SwarmNotAgreement note;
    note.want_settle = true;
    const modelnet::SwarmNotAgreementResult result = modelnet::SwarmNoteNotAgreement(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "AGREEMENT");
    BOOST_CHECK_EQUAL(err, "AGREEMENT");
}

BOOST_AUTO_TEST_CASE(want_settle_is_not_settlement)
{
    std::string err = "prior";
    modelnet::SwarmNotAgreement note;
    note.agreement_id = "agreement-1";
    note.want_settle = true;
    const modelnet::SwarmNotAgreementResult result = modelnet::SwarmNoteNotAgreement(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_SETTLEMENT");
    BOOST_CHECK_EQUAL(err, "NOT_SETTLEMENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotAgreement note;
    note.agreement_id = "agreement-1";
    note.want_settle = false;
    const modelnet::SwarmNotAgreementResult result = modelnet::SwarmNoteNotAgreement(note, err);
    BOOST_CHECK(!result.settled);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
