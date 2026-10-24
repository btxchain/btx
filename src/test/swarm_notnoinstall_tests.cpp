// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinstall.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoinstall_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_package_id_is_package)
{
    modelnet::SwarmNotNoInstall note;
    std::string err = "prior";
    const modelnet::SwarmNotNoInstallResult result = modelnet::SwarmNoteNotNoInstall(note, err);
    BOOST_CHECK_EQUAL(result.installed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "PACKAGE");
    BOOST_CHECK_EQUAL(err, "PACKAGE");
}

BOOST_AUTO_TEST_CASE(want_install_is_not_installed)
{
    modelnet::SwarmNotNoInstall note;
    note.package_id = "pkg-1";
    note.want_install = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoInstallResult result = modelnet::SwarmNoteNotNoInstall(note, err);
    BOOST_CHECK_EQUAL(result.installed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_INSTALLED");
    BOOST_CHECK_EQUAL(err, "NOT_INSTALLED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoInstall note;
    note.package_id = "pkg-1";
    note.want_install = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoInstallResult result = modelnet::SwarmNoteNotNoInstall(note, err);
    BOOST_CHECK_EQUAL(result.installed, false);
    BOOST_CHECK_EQUAL(result.bytes_moved, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
