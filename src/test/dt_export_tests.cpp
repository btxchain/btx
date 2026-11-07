// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_export/dt_export.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(dt_export_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(adopt_rejects_regression_and_unchanged_cycle)
{
    modelnet::DtExport exp;
    std::string err;
    const std::vector<unsigned char> body{'m', 'o', 'd', 'e', 'l'};
    BOOST_CHECK(exp.Submit("cand", body, err));
    BOOST_CHECK(exp.Report("cand", "author", "eval1", "ad", "d1", false, false, false, err));
    BOOST_CHECK(exp.Report("cand", "author", "eval2", "ad", "d2", false, false, false, err));
    BOOST_CHECK(exp.qualified("cand"));
    BOOST_CHECK(exp.StageAdopt("ch", "cand", err));
    BOOST_CHECK_EQUAL(exp.active("ch"), "cand");
    BOOST_CHECK(!exp.realm_promoted());

    modelnet::DtExport bad;
    BOOST_CHECK(bad.Submit("cand", body, err));
    BOOST_CHECK(!bad.Report("cand", "author", "eval1", "ad", "d1", false, false, true, err));
    BOOST_CHECK_EQUAL(err, "REGRESSION");
    BOOST_CHECK(!bad.qualified("cand"));
    BOOST_CHECK(!bad.StageAdopt("ch", "cand", err));
    BOOST_CHECK_EQUAL(err, "NOT_GRADUATED");
    BOOST_CHECK(bad.active("ch").empty());

    BOOST_CHECK(!exp.SecondCycle("cand", body, err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK(!exp.new_generation());
    const std::vector<unsigned char> next{'m', 'o', 'd', 'e', 'l', '2'};
    BOOST_CHECK(exp.SecondCycle("cand", next, err));
    BOOST_CHECK(exp.new_generation());

    BOOST_CHECK(!exp.Settle(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!exp.settlement_qualified());
    BOOST_CHECK(!exp.gpu());
    BOOST_CHECK_EQUAL(exp.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
