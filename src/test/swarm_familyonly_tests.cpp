// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyonly.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_familyonly_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_family)
{
    std::string err = "prior";
    modelnet::SwarmFamilyOnly note;
    note.same_family = true;
    note.compatible = true;
    note.want_share = true;
    const modelnet::SwarmFamilyOnlyResult result = modelnet::SwarmNoteFamilyOnly(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY");
    BOOST_CHECK_EQUAL(err, "FAMILY");
}

BOOST_AUTO_TEST_CASE(same_family_incompatible_want_share_is_family_not_compat)
{
    std::string err = "prior";
    modelnet::SwarmFamilyOnly note;
    note.page_id = "page-a";
    note.same_family = true;
    note.compatible = false;
    note.want_share = true;
    const modelnet::SwarmFamilyOnlyResult result = modelnet::SwarmNoteFamilyOnly(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(different_family_compatible_want_share_is_separate)
{
    std::string err = "prior";
    modelnet::SwarmFamilyOnly note;
    note.page_id = "page-a";
    note.same_family = false;
    note.compatible = true;
    note.want_share = true;
    const modelnet::SwarmFamilyOnlyResult result = modelnet::SwarmNoteFamilyOnly(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(compatible_same_family_want_share_is_held)
{
    std::string err = "prior";
    modelnet::SwarmFamilyOnly note;
    note.page_id = "page-a";
    note.same_family = true;
    note.compatible = true;
    note.want_share = true;
    const modelnet::SwarmFamilyOnlyResult result = modelnet::SwarmNoteFamilyOnly(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(compatible_same_family_without_share_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmFamilyOnly note;
    note.page_id = "page-a";
    note.same_family = true;
    note.compatible = true;
    note.want_share = false;
    const modelnet::SwarmFamilyOnlyResult result = modelnet::SwarmNoteFamilyOnly(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
