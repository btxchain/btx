// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familydir.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familydir_tests, BasicTestingSetup)

static modelnet::SwarmFamilyDir NotedFamily()
{
    modelnet::SwarmFamilyDir family;
    family.family_id = "family-1";
    family.want_publish = false;
    return family;
}

BOOST_AUTO_TEST_CASE(empty_family_id_is_family)
{
    modelnet::SwarmFamilyDir family = NotedFamily();
    family.family_id.clear();
    family.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmFamilyDirResult result = modelnet::SwarmNoteFamilyDir(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(want_publish_is_held)
{
    modelnet::SwarmFamilyDir family = NotedFamily();
    family.want_publish = true;
    std::string err = "prior";
    const modelnet::SwarmFamilyDirResult result = modelnet::SwarmNoteFamilyDir(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_publish_false_is_noted)
{
    modelnet::SwarmFamilyDir family = NotedFamily();
    family.want_publish = false;
    std::string err = "prior";
    const modelnet::SwarmFamilyDirResult result = modelnet::SwarmNoteFamilyDir(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
