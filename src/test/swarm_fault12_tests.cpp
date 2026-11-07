// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault12.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault12_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_report_id_is_report)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id.clear();
    in.conflict = true;
    in.distinct_evaluators = true;
    in.distinct_domains = true;
    in.want_settle = true;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "REPORT");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "REPORT");
}

BOOST_AUTO_TEST_CASE(conflict_is_quorum_even_if_want_settle)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id = "report-1";
    in.conflict = true;
    in.distinct_evaluators = true;
    in.distinct_domains = true;
    in.want_settle = true;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "QUORUM");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(not_distinct_evaluators_is_quorum)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id = "report-1";
    in.conflict = false;
    in.distinct_evaluators = false;
    in.distinct_domains = true;
    in.want_settle = true;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "QUORUM");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(not_distinct_domains_is_quorum)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id = "report-1";
    in.conflict = false;
    in.distinct_evaluators = true;
    in.distinct_domains = false;
    in.want_settle = true;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "QUORUM");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK_EQUAL(err, "QUORUM");
}

BOOST_AUTO_TEST_CASE(want_settle_is_held)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id = "report-1";
    in.conflict = false;
    in.distinct_evaluators = true;
    in.distinct_domains = true;
    in.want_settle = true;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(otherwise_noted)
{
    std::string err = "prior";
    modelnet::SwarmFault12 in;
    in.report_id = "report-1";
    in.conflict = false;
    in.distinct_evaluators = true;
    in.distinct_domains = true;
    in.want_settle = false;
    const modelnet::SwarmFault12Result out = modelnet::SwarmRecoverFault12(in, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.settled);
    BOOST_CHECK_EQUAL(out.atoms_moved, int64_t{0});
    BOOST_CHECK(!out.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
