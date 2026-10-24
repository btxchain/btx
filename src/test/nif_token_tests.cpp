// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_token/nif_token.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_token_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_grammar_stores_nothing)
{
    modelnet::NifToken token;
    std::string err;

    BOOST_CHECK(!token.Bind("tok-a", "", "samp-a", err));
    BOOST_CHECK_EQUAL(err, "GRAMMAR");
    BOOST_CHECK(token.tokenizer().empty());
    BOOST_CHECK(token.grammar().empty());
    BOOST_CHECK(token.sampler().empty());
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!token.Continue("tok-a", "", "samp-a", err));
    BOOST_CHECK_EQUAL(err, "COMPAT");
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(sampler_mismatch_is_compat)
{
    modelnet::NifToken token;
    std::string err;

    BOOST_CHECK(token.Bind("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK(!token.Continue("tok-a", "gram-a", "samp-b", err));
    BOOST_CHECK_EQUAL(err, "COMPAT");
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(token.sampler(), "samp-a");
}

BOOST_AUTO_TEST_CASE(matching_triple_continues_once)
{
    modelnet::NifToken token;
    std::string err;

    BOOST_CHECK(token.Bind("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK(token.Continue("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(second_match_is_replay)
{
    modelnet::NifToken token;
    std::string err;

    BOOST_CHECK(token.Bind("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK(token.Continue("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(1));

    BOOST_CHECK(!token.Continue("tok-a", "gram-a", "samp-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(remote_rdma_is_engine_absent)
{
    modelnet::NifToken token;
    std::string err;

    BOOST_CHECK(!token.Remote("rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(token.continuations(), static_cast<int64_t>(0));

    BOOST_CHECK(!token.Approximate(err));
    BOOST_CHECK_EQUAL(err, "APPROXIMATE");
    BOOST_CHECK(!token.approximate_called_exact());
    BOOST_CHECK(!token.launched());
    BOOST_CHECK(!token.gpu());
    BOOST_CHECK(!token.broadcast());
    BOOST_CHECK(!token.all_rank_qualified());
    BOOST_CHECK_EQUAL(token.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(token.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
