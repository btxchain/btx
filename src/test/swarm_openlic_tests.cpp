// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_openlic.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_openlic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_license)
{
    modelnet::SwarmOpenLic license;
    license.license_id.clear();
    license.open_local = false;
    license.want_tax = false;
    std::string err;
    const modelnet::SwarmOpenLicResult result = modelnet::SwarmNoteOpenLicense(license, err);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(open_local_not_taxed)
{
    modelnet::SwarmOpenLic license;
    license.license_id = "open-1";
    license.open_local = true;
    license.want_tax = false;
    std::string err;
    const modelnet::SwarmOpenLicResult result = modelnet::SwarmNoteOpenLicense(license, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_TAXED");
    BOOST_CHECK_EQUAL(err, "NOT_TAXED");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_tax_held)
{
    modelnet::SwarmOpenLic license;
    license.license_id = "open-2";
    license.open_local = false;
    license.want_tax = true;
    std::string err;
    const modelnet::SwarmOpenLicResult result = modelnet::SwarmNoteOpenLicense(license, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmOpenLic license;
    license.license_id = "open-3";
    license.open_local = false;
    license.want_tax = false;
    std::string err = "stale";
    const modelnet::SwarmOpenLicResult result = modelnet::SwarmNoteOpenLicense(license, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
