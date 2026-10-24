// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <string>

namespace {

void ExpectIdle(const modelnet::SwarmAgentExec& exec)
{
    BOOST_REQUIRE(!exec.launched());
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.gpu());
    BOOST_REQUIRE(!exec.broadcast());
    BOOST_REQUIRE(exec.atoms_moved() == 0);
    BOOST_REQUIRE(exec.automatic_spend() == "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_agentexec_sha_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sha256_computes_hash_and_sets_ran)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "alpha-payload";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.result().size() == expected.size());
    BOOST_REQUIRE(expected.size() == 64);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_second_payload_computes_its_own_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string first_payload = "alpha-payload";
    const std::string second_payload = "beta-payload";
    const std::string first_expected = HexStr(Hash(first_payload));
    const std::string second_expected = HexStr(Hash(second_payload));

    BOOST_REQUIRE(first_expected != second_expected);
    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", first_payload, err));
    BOOST_REQUIRE(exec.result() == first_expected);
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", second_payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == second_expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(replay_of_the_same_path_and_payload_keeps_the_first_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "alpha-payload";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.ran());

    BOOST_REQUIRE(!exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(replay_does_not_replace_a_later_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string first_payload = "alpha-payload";
    const std::string second_payload = "beta-payload";
    const std::string first_expected = HexStr(Hash(first_payload));
    const std::string second_expected = HexStr(Hash(second_payload));

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/one", first_payload, err));
    BOOST_REQUIRE(exec.result() == first_expected);
    BOOST_REQUIRE(exec.Execute("sha256", "weights/two", second_payload, err));
    BOOST_REQUIRE(exec.result() == second_expected);

    BOOST_REQUIRE(!exec.Execute("sha256", "weights/one", first_payload, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(exec.result() == second_expected);
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(same_payload_on_a_different_path_is_not_replay)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "shared-payload";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/one", payload, err));
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.Execute("sha256", "weights/two", payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(empty_payload_is_payload_and_does_not_set_ran)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "weights/blob", "", err));
    BOOST_REQUIRE(err == "PAYLOAD");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(empty_payload_after_a_digest_keeps_the_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "alpha-payload";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(exec.ran());

    BOOST_REQUIRE(!exec.Execute("sha256", "weights/other", "", err));
    BOOST_REQUIRE(err == "PAYLOAD");
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(path_equal_to_the_prefix_hashes_the_payload)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "exact-path";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("weights", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights", payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_SUITE_END()
