// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engine.h>
#include <modelnet/swarm_rollout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_accept_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_conversation_is_not_training_data)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmAdmitRollout("e1", "private_conversation", false, "", false, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!modelnet::SwarmAdmitRollout("e1", "credential", true, "evidence", false, err));
    BOOST_CHECK_EQUAL(err, "CREDENTIAL");
    BOOST_CHECK(modelnet::SwarmAdmitRollout("e2", "synthetic_trajectory", false, "public-task", false, err));
    BOOST_CHECK(modelnet::SwarmAdmitRollout("e3", "private_conversation", true, "signed-rights", false, err));
    BOOST_CHECK(!modelnet::SwarmAdmitRollout("e3", "licensed", true, "signed-rights", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
}

BOOST_AUTO_TEST_CASE(an_unmeasured_engine_is_not_advertised)
{
    std::string err;
    const modelnet::SwarmEngineStatus missing = modelnet::SwarmProbeEngine("vllm", fs::u8path("/no/such/vllm"), err);
    BOOST_CHECK(!missing.present);
    BOOST_CHECK(!missing.advertised);
    BOOST_CHECK(!missing.qualified);
    BOOST_CHECK_EQUAL(missing.code, "ENGINE_ABSENT");

    fs::path bin = fs::temp_directory_path();
    bin /= fs::u8path("btx-engine-" + std::to_string(::getpid()));
    {
        std::ofstream out(bin);
        out << "#!/bin/sh\n";
    }
    modelnet::SwarmEngineStatus installed = modelnet::SwarmProbeEngine("torch", bin, err);
    BOOST_CHECK(installed.present);
    BOOST_CHECK(!installed.advertised);
    BOOST_CHECK(!installed.qualified);
    BOOST_CHECK_EQUAL(installed.code, "INSTALLED");
    BOOST_CHECK(!modelnet::SwarmQualifyEngine(installed, false, 0.0, err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!installed.advertised);
    BOOST_CHECK(!installed.qualified);
    BOOST_CHECK(!modelnet::SwarmQualifyEngine(installed, true, 12.5, err));
    BOOST_CHECK(!installed.qualified);
    BOOST_CHECK(!installed.advertised);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    fs::remove(bin);
}

BOOST_AUTO_TEST_SUITE_END()
