// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dlgrant.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_dlgrant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_grant)
{
    std::string err = "prior";
    modelnet::SwarmDownloadGrant grant;
    grant.download_license = true;
    grant.operator_grant = false;
    grant.want_train = true;
    const modelnet::SwarmDownloadGrantResult result = modelnet::SwarmNoteDownloadGrant(grant, err);
    BOOST_CHECK(!result.training_allowed);
    BOOST_CHECK_EQUAL(result.code, "GRANT");
    BOOST_CHECK_EQUAL(err, "GRANT");
}

BOOST_AUTO_TEST_CASE(download_license_without_operator_grant_is_not_training)
{
    std::string err = "prior";
    modelnet::SwarmDownloadGrant grant;
    grant.license_id = "lic-a";
    grant.download_license = true;
    grant.operator_grant = false;
    grant.want_train = true;
    const modelnet::SwarmDownloadGrantResult result = modelnet::SwarmNoteDownloadGrant(grant, err);
    BOOST_CHECK(!result.training_allowed);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRAINING");
    BOOST_CHECK_EQUAL(err, "NOT_TRAINING");
}

BOOST_AUTO_TEST_CASE(want_train_with_operator_grant_is_held)
{
    std::string err = "prior";
    modelnet::SwarmDownloadGrant grant;
    grant.license_id = "lic-a";
    grant.download_license = true;
    grant.operator_grant = true;
    grant.want_train = true;
    const modelnet::SwarmDownloadGrantResult result = modelnet::SwarmNoteDownloadGrant(grant, err);
    BOOST_CHECK(!result.training_allowed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(noted_does_not_allow_training)
{
    std::string err = "prior";
    modelnet::SwarmDownloadGrant grant;
    grant.license_id = "lic-a";
    grant.download_license = true;
    grant.operator_grant = true;
    grant.want_train = false;
    const modelnet::SwarmDownloadGrantResult result = modelnet::SwarmNoteDownloadGrant(grant, err);
    BOOST_CHECK(!result.training_allowed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
