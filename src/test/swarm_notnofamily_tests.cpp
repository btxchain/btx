// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamily.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnofamily_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty)
{
    modelnet::SwarmNotNoFamily note;
    note.page_id.clear();
    note.same_family = true;
    note.compatible = false;
    note.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoFamilyResult result = modelnet::SwarmNoteNotNoFamily(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(same_family_and_incompatible)
{
    modelnet::SwarmNotNoFamily note;
    note.page_id = "page-1";
    note.same_family = true;
    note.compatible = false;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFamilyResult result = modelnet::SwarmNoteNotNoFamily(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(different_family)
{
    modelnet::SwarmNotNoFamily note;
    note.page_id = "page-1";
    note.same_family = false;
    note.compatible = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFamilyResult result = modelnet::SwarmNoteNotNoFamily(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEPARATE");
    BOOST_CHECK_EQUAL(err, "SEPARATE");
}

BOOST_AUTO_TEST_CASE(same_family_and_compatible_want_share_false)
{
    modelnet::SwarmNotNoFamily note;
    note.page_id = "page-1";
    note.same_family = true;
    note.compatible = true;
    note.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoFamilyResult result = modelnet::SwarmNoteNotNoFamily(note, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
