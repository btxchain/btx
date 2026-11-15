// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_downloadlic.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_downloadlic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    std::string err = "prior";
    modelnet::SwarmDownloadLic license;
    const modelnet::SwarmDownloadLicResult result = modelnet::SwarmNoteDownloadLicense(license, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(download_true_both_wants_false_is_not_grant)
{
    std::string err = "prior";
    modelnet::SwarmDownloadLic license;
    license.license_id = "license-1";
    license.download = true;
    license.want_train = false;
    license.want_redist = false;
    const modelnet::SwarmDownloadLicResult result = modelnet::SwarmNoteDownloadLicense(license, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "NOT_GRANT");
    BOOST_CHECK_EQUAL(err, "NOT_GRANT");
}

BOOST_AUTO_TEST_CASE(want_train_true_download_false_is_held)
{
    std::string err = "prior";
    modelnet::SwarmDownloadLic license;
    license.license_id = "license-1";
    license.download = false;
    license.want_train = true;
    license.want_redist = false;
    const modelnet::SwarmDownloadLicResult result = modelnet::SwarmNoteDownloadLicense(license, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(download_false_both_wants_false_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmDownloadLic license;
    license.license_id = "license-1";
    license.download = false;
    license.want_train = false;
    license.want_redist = false;
    const modelnet::SwarmDownloadLicResult result = modelnet::SwarmNoteDownloadLicense(license, err);
    BOOST_CHECK(!result.training);
    BOOST_CHECK(!result.granted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
