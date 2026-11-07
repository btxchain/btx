// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_privfam_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_family)
{
    std::string err = "prior";
    modelnet::SwarmPrivFam family;
    family.family_id.clear();
    family.private_family = false;
    family.want_publish = false;
    const modelnet::SwarmPrivFamResult result = modelnet::SwarmNotePrivFam(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(private_family_not_published)
{
    std::string err = "prior";
    modelnet::SwarmPrivFam family;
    family.family_id = "fam-1";
    family.private_family = true;
    family.want_publish = false;
    const modelnet::SwarmPrivFamResult result = modelnet::SwarmNotePrivFam(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOT_PUBLISHED");
    BOOST_CHECK_EQUAL(err, "NOT_PUBLISHED");
}

BOOST_AUTO_TEST_CASE(want_publish_held)
{
    std::string err = "prior";
    modelnet::SwarmPrivFam family;
    family.family_id = "fam-1";
    family.private_family = false;
    family.want_publish = true;
    const modelnet::SwarmPrivFamResult result = modelnet::SwarmNotePrivFam(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmPrivFam family;
    family.family_id = "fam-1";
    family.private_family = false;
    family.want_publish = false;
    const modelnet::SwarmPrivFamResult result = modelnet::SwarmNotePrivFam(family, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
