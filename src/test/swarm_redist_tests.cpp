// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_redist.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_redist_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_grant)
{
    std::string err = "prior";
    modelnet::SwarmRedistribute note;
    note.download_license = true;
    note.operator_grant = false;
    note.want_redistribute = true;
    const modelnet::SwarmRedistributeResult result = modelnet::SwarmNoteRedistribute(note, err);
    BOOST_CHECK(!result.redistribution_allowed);
    BOOST_CHECK_EQUAL(result.code, "GRANT");
    BOOST_CHECK_EQUAL(err, "GRANT");
}

BOOST_AUTO_TEST_CASE(download_license_without_operator_grant_is_not_redistribution)
{
    std::string err = "prior";
    modelnet::SwarmRedistribute note;
    note.license_id = "lic-a";
    note.download_license = true;
    note.operator_grant = false;
    note.want_redistribute = true;
    const modelnet::SwarmRedistributeResult result = modelnet::SwarmNoteRedistribute(note, err);
    BOOST_CHECK(!result.redistribution_allowed);
    BOOST_CHECK_EQUAL(result.code, "NOT_REDISTRIBUTION");
    BOOST_CHECK_EQUAL(err, "NOT_REDISTRIBUTION");
}

BOOST_AUTO_TEST_CASE(want_redistribute_with_operator_grant_is_held)
{
    std::string err = "prior";
    modelnet::SwarmRedistribute note;
    note.license_id = "lic-a";
    note.download_license = true;
    note.operator_grant = true;
    note.want_redistribute = true;
    const modelnet::SwarmRedistributeResult result = modelnet::SwarmNoteRedistribute(note, err);
    BOOST_CHECK(!result.redistribution_allowed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_does_not_allow_redistribution)
{
    std::string err = "prior";
    modelnet::SwarmRedistribute note;
    note.license_id = "lic-a";
    note.download_license = true;
    note.operator_grant = true;
    note.want_redistribute = false;
    const modelnet::SwarmRedistributeResult result = modelnet::SwarmNoteRedistribute(note, err);
    BOOST_CHECK(!result.redistribution_allowed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
