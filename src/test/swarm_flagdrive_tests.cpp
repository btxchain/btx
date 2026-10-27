// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagdrive.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flagdrive_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_lineage_is_lineage_at_acquire)
{
    modelnet::SwarmFlagDrive drive;
    drive.lineage_id.clear();
    drive.stage = modelnet::SwarmFlagStage::Acquire;
    drive.hardware_seen = true;
    drive.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlagDriveResult result = modelnet::SwarmAdvanceFlagship(drive, err);
    BOOST_CHECK_EQUAL(result.code, "LINEAGE");
    BOOST_CHECK(result.stage == modelnet::SwarmFlagStage::Acquire);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(err, "LINEAGE");
}

BOOST_AUTO_TEST_CASE(unseen_hardware_at_join_stays_unqualified)
{
    modelnet::SwarmFlagDrive drive;
    drive.lineage_id = "lineage-1";
    drive.stage = modelnet::SwarmFlagStage::Join;
    drive.hardware_seen = false;
    drive.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlagDriveResult result = modelnet::SwarmAdvanceFlagship(drive, err);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK(result.stage == modelnet::SwarmFlagStage::Join);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(want_pass_at_train_stays_held)
{
    modelnet::SwarmFlagDrive drive;
    drive.lineage_id = "lineage-1";
    drive.stage = modelnet::SwarmFlagStage::Train;
    drive.hardware_seen = true;
    drive.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlagDriveResult result = modelnet::SwarmAdvanceFlagship(drive, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(result.stage == modelnet::SwarmFlagStage::Train);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(acquire_advances_to_join_noted)
{
    modelnet::SwarmFlagDrive drive;
    drive.lineage_id = "lineage-1";
    drive.stage = modelnet::SwarmFlagStage::Acquire;
    drive.hardware_seen = true;
    drive.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlagDriveResult result = modelnet::SwarmAdvanceFlagship(drive, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(result.stage == modelnet::SwarmFlagStage::Join);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(result.advanced);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(repeat_stays_repeat_noted)
{
    modelnet::SwarmFlagDrive drive;
    drive.lineage_id = "lineage-1";
    drive.stage = modelnet::SwarmFlagStage::Repeat;
    drive.hardware_seen = true;
    drive.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmFlagDriveResult result = modelnet::SwarmAdvanceFlagship(drive, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(result.stage == modelnet::SwarmFlagStage::Repeat);
    BOOST_CHECK(!result.passed);
    BOOST_CHECK(!result.advanced);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
