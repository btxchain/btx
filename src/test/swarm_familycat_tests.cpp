// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familycat.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familycat_tests, BasicTestingSetup)

static modelnet::SwarmFamilyCat ClearFamily()
{
    modelnet::SwarmFamilyCat family;
    family.family_id = "family-1";
    family.private_family = false;
    family.want_publish = false;
    family.want_list = false;
    return family;
}

BOOST_AUTO_TEST_CASE(empty_family_id_is_family)
{
    modelnet::SwarmFamilyCat family = ClearFamily();
    family.family_id.clear();
    family.private_family = true;
    family.want_publish = true;
    family.want_list = true;
    std::string err = "prior";
    const modelnet::SwarmFamilyCatResult result = modelnet::SwarmCatalogFamily(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(private_family_want_list_is_not_published)
{
    modelnet::SwarmFamilyCat family = ClearFamily();
    family.private_family = true;
    family.want_publish = false;
    family.want_list = true;
    std::string err = "prior";
    const modelnet::SwarmFamilyCatResult result = modelnet::SwarmCatalogFamily(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(want_publish_public_is_held)
{
    modelnet::SwarmFamilyCat family = ClearFamily();
    family.private_family = false;
    family.want_publish = true;
    family.want_list = false;
    std::string err = "prior";
    const modelnet::SwarmFamilyCatResult result = modelnet::SwarmCatalogFamily(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(result.listed);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_list_without_publish_is_noted)
{
    modelnet::SwarmFamilyCat family = ClearFamily();
    family.private_family = false;
    family.want_publish = false;
    family.want_list = true;
    std::string err = "prior";
    const modelnet::SwarmFamilyCatResult result = modelnet::SwarmCatalogFamily(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(result.listed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(neither_publish_nor_list_is_noted)
{
    modelnet::SwarmFamilyCat family = ClearFamily();
    family.private_family = false;
    family.want_publish = false;
    family.want_list = false;
    std::string err = "prior";
    const modelnet::SwarmFamilyCatResult result = modelnet::SwarmCatalogFamily(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK(!result.listed);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
