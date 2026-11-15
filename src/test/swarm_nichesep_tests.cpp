// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nichesep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_nichesep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_niche_id)
{
    modelnet::SwarmNicheSep niche;
    niche.niche_id.clear();
    niche.other_id = "n2";
    niche.want_merge = false;
    std::string err;
    const modelnet::SwarmNicheSepResult result = modelnet::SwarmKeepNiches(niche, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "NICHE");
    BOOST_CHECK_EQUAL(err, "NICHE");
}

BOOST_AUTO_TEST_CASE(empty_other_id)
{
    modelnet::SwarmNicheSep niche;
    niche.niche_id = "n1";
    niche.other_id.clear();
    niche.want_merge = false;
    std::string err;
    const modelnet::SwarmNicheSepResult result = modelnet::SwarmKeepNiches(niche, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "OTHER");
    BOOST_CHECK_EQUAL(err, "OTHER");
}

BOOST_AUTO_TEST_CASE(same_niche_id)
{
    modelnet::SwarmNicheSep niche;
    niche.niche_id = "n1";
    niche.other_id = "n1";
    niche.want_merge = false;
    std::string err;
    const modelnet::SwarmNicheSepResult result = modelnet::SwarmKeepNiches(niche, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "SAME");
    BOOST_CHECK_EQUAL(err, "SAME");
}

BOOST_AUTO_TEST_CASE(want_merge_held)
{
    modelnet::SwarmNicheSep niche;
    niche.niche_id = "n1";
    niche.other_id = "n2";
    niche.want_merge = true;
    std::string err;
    const modelnet::SwarmNicheSepResult result = modelnet::SwarmKeepNiches(niche, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNicheSep niche;
    niche.niche_id = "n1";
    niche.other_id = "n2";
    niche.want_merge = false;
    std::string err = "stale";
    const modelnet::SwarmNicheSepResult result = modelnet::SwarmKeepNiches(niche, err);
    BOOST_CHECK(!result.merged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
