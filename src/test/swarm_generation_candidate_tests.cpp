// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

std::string ExpectId(const std::string& parent, const std::string& recipe, const std::string& weights, const std::string& nonce)
{
    const uint256 digest = Hash(parent + recipe, weights + nonce);
    return HexStr(Span<const uint8_t>(digest.data(), static_cast<std::size_t>(digest.size())));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_generation_candidate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_candidate_fields_store_nothing)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";

    BOOST_CHECK(!gen.Produce("", "recipe", "weights", "nonce", err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_CHECK(gen.candidate_id().empty());

    BOOST_CHECK(!gen.Produce("parent", "", "weights", "nonce", err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_CHECK(!gen.Produce("parent", "recipe", "", "nonce", err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_CHECK(!gen.Produce("parent", "recipe", "weights", "", err));
    BOOST_CHECK_EQUAL(err, "CANDIDATE");
    BOOST_CHECK(gen.candidate_id().empty());
    BOOST_CHECK(gen.bytes_moved() == 0);
}

BOOST_AUTO_TEST_CASE(produce_stores_the_hash_and_verify_checks_the_parent)
{
    modelnet::SwarmGenerationEngine gen;
    std::string err = "prior";
    const std::string parent = "parent-a";
    const std::string recipe = "recipe-b";
    const std::string weights = "weights-c";
    const std::string nonce = "nonce-d";
    const std::string expect = ExpectId(parent, recipe, weights, nonce);

    BOOST_CHECK(gen.Produce(parent, recipe, weights, nonce, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(gen.candidate_id(), expect);
    BOOST_CHECK(!gen.verified(expect));
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(!gen.launched());
    BOOST_CHECK(!gen.gpu());

    BOOST_CHECK(!gen.VerifyProvenance("missing", parent, err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!gen.verified(expect));

    BOOST_CHECK(!gen.VerifyProvenance(expect, "other-parent", err));
    BOOST_CHECK_EQUAL(err, "PROVENANCE");
    BOOST_CHECK(!gen.verified(expect));

    BOOST_CHECK(gen.VerifyProvenance(expect, parent, err));
    BOOST_CHECK(gen.verified(expect));

    BOOST_CHECK(!gen.Distribute(expect, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(gen.bytes_moved() == 0);
    BOOST_CHECK(gen.atoms_moved() == 0);
    BOOST_CHECK_EQUAL(gen.candidate_id(), expect);
    BOOST_CHECK(gen.verified(expect));
    BOOST_CHECK(!gen.broadcast());
    BOOST_CHECK_EQUAL(gen.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
