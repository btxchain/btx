// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcert.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcert_tests, BasicTestingSetup)

static modelnet::SwarmNotCert NotedNote()
{
    modelnet::SwarmNotCert note;
    note.descendant_id = "descendant-1";
    note.want_cert = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_descendant_id_is_descendant)
{
    modelnet::SwarmNotCert note = NotedNote();
    note.descendant_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotCertResult result = modelnet::SwarmNoteNotCert(note, err);
    BOOST_CHECK(!result.issued);
    BOOST_CHECK_EQUAL(result.code, "DESCENDANT");
    BOOST_CHECK_EQUAL(err, "DESCENDANT");
}

BOOST_AUTO_TEST_CASE(want_cert_is_no_cert)
{
    modelnet::SwarmNotCert note = NotedNote();
    note.want_cert = true;
    std::string err = "prior";
    const modelnet::SwarmNotCertResult result = modelnet::SwarmNoteNotCert(note, err);
    BOOST_CHECK(!result.issued);
    BOOST_CHECK_EQUAL(result.code, "NO_CERT");
    BOOST_CHECK_EQUAL(err, "NO_CERT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCert note = NotedNote();
    note.want_cert = false;
    std::string err = "prior";
    const modelnet::SwarmNotCertResult result = modelnet::SwarmNoteNotCert(note, err);
    BOOST_CHECK(!result.issued);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
