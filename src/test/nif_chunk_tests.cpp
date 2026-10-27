// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_chunk/nif_chunk.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_chunk_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(authorize_chunks_against_the_bound_state)
{
    modelnet::NifChunk chunk;
    std::string err = "stale";

    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!chunk.bound());
    BOOST_CHECK(chunk.state().empty());
    BOOST_CHECK(!chunk.qualified());
    BOOST_CHECK(!chunk.launched());
    BOOST_CHECK(!chunk.gpu());
    BOOST_CHECK(!chunk.broadcast());
    BOOST_CHECK_EQUAL(chunk.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(chunk.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(!chunk.Accept("c0", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_STATE);
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!chunk.Accept("", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!chunk.Bind("", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_STATE);
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!chunk.bound());
    BOOST_CHECK(chunk.state().empty());

    BOOST_CHECK(chunk.Bind("s0", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(chunk.bound());
    BOOST_CHECK_EQUAL(chunk.state(), "s0");

    BOOST_CHECK(!chunk.Accept("", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_CHUNK);
    BOOST_CHECK_EQUAL(err, "CHUNK");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK(!chunk.chunk_stored(""));

    BOOST_CHECK(!chunk.Accept("", "s0", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "CHUNK");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(!chunk.Accept("c0", "s0", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_BYTES);
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK(!chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(0));

    BOOST_CHECK(!chunk.Accept("c0", "s0", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));

    BOOST_CHECK(chunk.Accept("c0", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK(!chunk.qualified());

    BOOST_CHECK(!chunk.Accept("c2", "other", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_STALE);
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK(!chunk.chunk_stored("c2"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c2"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.state(), "s0");

    BOOST_CHECK(!chunk.Accept("c0", "other", static_cast<int64_t>(99), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK(chunk.chunk_stored("c0"));

    BOOST_CHECK(!chunk.Accept("c0", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));

    BOOST_CHECK(!chunk.Accept("c0", "s0", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "BYTES");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));

    BOOST_CHECK(chunk.Bind("s0", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(chunk.state(), "s0");
    BOOST_CHECK(chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));

    BOOST_CHECK(chunk.Bind("s1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(chunk.state(), "s1");
    BOOST_CHECK(chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));

    BOOST_CHECK(!chunk.Bind("", err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK_EQUAL(chunk.state(), "s1");
    BOOST_CHECK(chunk.chunk_stored("c0"));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));

    BOOST_CHECK(chunk.Accept("c1", "s1", static_cast<int64_t>(3), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(chunk.chunk_stored("c1"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c1"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));

    BOOST_CHECK(!chunk.Accept("c0", "s1", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK(chunk.chunk_stored("c0"));
    BOOST_CHECK(chunk.chunk_stored("c1"));

    BOOST_CHECK(!chunk.Accept("c3", "s0", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_STALE);
    BOOST_CHECK(!chunk.chunk_stored("c3"));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(chunk.state(), "s1");

    BOOST_CHECK(!chunk.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(7));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c1"), static_cast<int64_t>(3));
    BOOST_CHECK(!chunk.qualified());
    BOOST_CHECK(!chunk.launched());
    BOOST_CHECK(!chunk.gpu());
    BOOST_CHECK(!chunk.broadcast());
    BOOST_CHECK_EQUAL(chunk.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(chunk.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(overflow_leaves_the_running_total)
{
    modelnet::NifChunk chunk;
    std::string err = "stale";

    BOOST_CHECK(chunk.Bind("s0", err));
    BOOST_CHECK(chunk.Accept("c0", "s0", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));

    BOOST_CHECK(!chunk.Accept("c9", "s0", std::numeric_limits<int64_t>::max(), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_CHUNK_OVERFLOW);
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK(!chunk.chunk_stored("c9"));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c9"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c0"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(chunk.Accept("c9", "s0", static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(chunk.stored_bytes("c9"), static_cast<int64_t>(1));

    BOOST_CHECK(chunk.Accept("wide", "s0", std::numeric_limits<int64_t>::max() - static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), std::numeric_limits<int64_t>::max());

    BOOST_CHECK(!chunk.Accept("one-more", "s0", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "OVERFLOW");
    BOOST_CHECK(!chunk.chunk_stored("one-more"));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), std::numeric_limits<int64_t>::max());
    BOOST_CHECK(!chunk.qualified());
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(spend_before_bind_leaves_balance_zero)
{
    modelnet::NifChunk chunk;
    std::string err = "stale";

    BOOST_CHECK(!chunk.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(chunk.balance(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.accepted_bytes(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(chunk.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!chunk.bound());
    BOOST_CHECK(!chunk.qualified());
    BOOST_CHECK(!chunk.launched());
    BOOST_CHECK(!chunk.gpu());
    BOOST_CHECK(!chunk.broadcast());
    BOOST_CHECK_EQUAL(chunk.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
