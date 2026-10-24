// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpackage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notpackage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_target_id_is_target)
{
    std::string err = "prior";
    modelnet::SwarmNotPackage note;
    note.want_omit = true;
    const modelnet::SwarmNotPackageResult result = modelnet::SwarmNoteNotPackage(note, err);
    BOOST_CHECK(!result.omitted);
    BOOST_CHECK(!result.packaged);
    BOOST_CHECK_EQUAL(result.code, "TARGET");
    BOOST_CHECK_EQUAL(err, "TARGET");
}

BOOST_AUTO_TEST_CASE(want_omit_is_present)
{
    std::string err = "prior";
    modelnet::SwarmNotPackage note;
    note.target_id = "target-package";
    note.want_omit = true;
    const modelnet::SwarmNotPackageResult result = modelnet::SwarmNoteNotPackage(note, err);
    BOOST_CHECK(!result.omitted);
    BOOST_CHECK(!result.packaged);
    BOOST_CHECK_EQUAL(result.code, "PRESENT");
    BOOST_CHECK_EQUAL(err, "PRESENT");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotPackage note;
    note.target_id = "target-package";
    note.want_omit = false;
    const modelnet::SwarmNotPackageResult result = modelnet::SwarmNoteNotPackage(note, err);
    BOOST_CHECK(!result.omitted);
    BOOST_CHECK(!result.packaged);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
