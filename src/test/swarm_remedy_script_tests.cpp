// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_remedy/remedy.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_remedy_script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_script_inputs_stay_local)
{
    modelnet::SwarmRemedy remedy;
    std::string err = "prior";
    const std::vector<unsigned char> hash(32, 0x46);
    const std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x47);

    const std::vector<unsigned char> missing_both = remedy.Script({}, {}, err);
    BOOST_REQUIRE(missing_both.empty());
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(remedy.script().empty());

    const std::vector<unsigned char> missing_key = remedy.Script(hash, {}, err);
    BOOST_REQUIRE(missing_key.empty());
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(remedy.script().empty());

    const std::vector<unsigned char> missing_hash = remedy.Script({}, pubkey, err);
    BOOST_REQUIRE(missing_hash.empty());
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(remedy.script().empty());

    const std::vector<unsigned char> short_hash(31, 0x46);
    const std::vector<unsigned char> short_script = remedy.Script(short_hash, pubkey, err);
    BOOST_REQUIRE(short_script.empty());
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(remedy.script().empty());

    const std::vector<unsigned char> script = remedy.Script(hash, pubkey, err);
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!script.empty());
    BOOST_REQUIRE(script == remedy.script());
    BOOST_REQUIRE(script == modelnet::SwarmRemedyScript(hash, pubkey));

    std::vector<unsigned char> parsed_hash;
    std::vector<unsigned char> parsed_key;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    BOOST_REQUIRE(ParseP2MRHTLCSha256Leaf(script, parsed_hash, algo, parsed_key));
    BOOST_REQUIRE(algo == PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(parsed_hash == hash);
    BOOST_REQUIRE(parsed_key == pubkey);

    err = "prior";
    const std::vector<unsigned char> wiped = remedy.Script({}, pubkey, err);
    BOOST_REQUIRE(wiped.empty());
    BOOST_REQUIRE_EQUAL(err, "KEY");
    BOOST_REQUIRE(remedy.script() == script);
    BOOST_REQUIRE(!remedy.broadcast());
    BOOST_REQUIRE_EQUAL(remedy.bytes_moved(), 0);
    BOOST_REQUIRE(!remedy.mined());
    BOOST_REQUIRE(!remedy.secret_released());
}

BOOST_AUTO_TEST_SUITE_END()
