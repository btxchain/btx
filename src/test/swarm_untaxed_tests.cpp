// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_untaxed.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_untaxed_tests, BasicTestingSetup)

static modelnet::SwarmInferenceTax FilledTax()
{
    modelnet::SwarmInferenceTax tax;
    tax.license_id = "lic-1";
    tax.open_license = false;
    tax.local_inference = false;
    tax.want_tax = false;
    return tax;
}

BOOST_AUTO_TEST_CASE(empty_license_id_is_license)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.license_id.clear();
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(empty_license_wins_over_open_local_and_want_tax)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.license_id.clear();
    tax.open_license = true;
    tax.local_inference = true;
    tax.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "LICENSE");
    BOOST_CHECK_EQUAL(err, "LICENSE");
}

BOOST_AUTO_TEST_CASE(open_license_local_inference_is_untaxed_even_when_want_tax)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.open_license = true;
    tax.local_inference = true;
    tax.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "UNTAXED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(open_license_without_local_inference_is_not_untaxed)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.open_license = true;
    tax.local_inference = false;
    tax.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(local_inference_without_open_license_is_not_untaxed)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.open_license = false;
    tax.local_inference = true;
    tax.want_tax = false;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_tax_is_refused)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "TAX_REFUSED");
    BOOST_CHECK_EQUAL(err, "TAX_REFUSED");
}

BOOST_AUTO_TEST_CASE(want_tax_wins_over_open_license_alone)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    tax.open_license = true;
    tax.local_inference = false;
    tax.want_tax = true;
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "TAX_REFUSED");
    BOOST_CHECK_EQUAL(err, "TAX_REFUSED");
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    modelnet::SwarmInferenceTax tax = FilledTax();
    std::string err = "prior";
    const modelnet::SwarmInferenceTaxResult result = modelnet::SwarmNoteInferenceTax(tax, err);
    BOOST_CHECK(!result.taxed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
