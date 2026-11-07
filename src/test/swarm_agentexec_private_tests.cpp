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

BOOST_FIXTURE_TEST_SUITE(swarm_agentexec_private_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(an_allowed_private_prefix_stores_nothing)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("private/", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    BOOST_REQUIRE(!exec.connected());
    BOOST_REQUIRE(!exec.launched());

    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_shorter_prefix_that_covers_a_private_path_is_private_data)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("pri", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(the_private_path_itself_is_private_data)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("private/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "private/", "body", err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!exec.ran());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_non_covering_prefix_denies_a_private_path)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "body", err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(!exec.ran());
    BOOST_REQUIRE(exec.result().empty());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_sibling_prefix_still_hashes)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "public-body";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("private/", err));
    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", payload, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!exec.ran());

    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(private_data_keeps_an_earlier_digest)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "public-body";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("weights/", err));
    BOOST_REQUIRE(exec.Allow("private/", err));
    BOOST_REQUIRE(exec.Execute("sha256", "weights/blob", payload, err));
    BOOST_REQUIRE(exec.result() == expected);

    BOOST_REQUIRE(!exec.Execute("sha256", "private/ledger", "secret-body", err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_CASE(a_name_that_only_shares_the_stem_is_not_private)
{
    modelnet::SwarmAgentExec exec;
    std::string err = "prior";
    const std::string payload = "near-body";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(exec.Allow("private", err));
    BOOST_REQUIRE(exec.Execute("sha256", "private", payload, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.ran());
    BOOST_REQUIRE(exec.result() == expected);

    BOOST_REQUIRE(exec.Allow("privateer/", err));
    const std::string other = "other-body";
    const std::string other_expected = HexStr(Hash(other));
    BOOST_REQUIRE(exec.Execute("sha256", "privateer/a", other, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(exec.result() == other_expected);
    BOOST_REQUIRE(!exec.launched());
    ExpectIdle(exec);
}

BOOST_AUTO_TEST_SUITE_END()
