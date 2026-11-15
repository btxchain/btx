// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_manifest/nif_manifest.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_manifest_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_pieces_in_order_then_seal)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.sealed());
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(manifest.Open("job", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(10), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.stored("job"));
    BOOST_CHECK_EQUAL(manifest.pieces("job"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(0));

    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(0), "piece-0", err));
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(0)), "piece-0");
    BOOST_CHECK(!manifest.Seal("job", err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK(!manifest.sealed());
    BOOST_CHECK(!manifest.sealed("job"));
    BOOST_CHECK(!manifest.compute_proof());

    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(1), "piece-1", err));
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(1)), "piece-1");
    BOOST_CHECK(manifest.Seal("job", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(manifest.sealed());
    BOOST_CHECK(manifest.sealed("job"));
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK_EQUAL(manifest.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.launched());
    BOOST_CHECK(!manifest.gpu());
    BOOST_CHECK(!manifest.broadcast());
    BOOST_CHECK_EQUAL(manifest.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(manifest.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(second_index_first_is_order)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK(manifest.Open("job", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(9), err));
    BOOST_CHECK(!manifest.Accept("job", static_cast<int64_t>(1), "piece-1", err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(0));
    BOOST_CHECK(manifest.digest("job", static_cast<int64_t>(0)).empty());
    BOOST_CHECK(manifest.digest("job", static_cast<int64_t>(1)).empty());
    BOOST_CHECK(!manifest.Seal("job", err));
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
    BOOST_CHECK(!manifest.sealed());
    BOOST_CHECK(!manifest.sealed("job"));

    BOOST_CHECK(!manifest.Accept("job", static_cast<int64_t>(2), "piece-2", err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(0));

    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(0), "piece-0", err));
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(1));
    BOOST_CHECK(!manifest.Accept("job", static_cast<int64_t>(0), "piece-0", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(0)), "piece-0");
}

BOOST_AUTO_TEST_CASE(changed_digest_is_altered)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK(manifest.Open("job", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(8), err));
    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(0), "aa", err));
    BOOST_CHECK(!manifest.Accept("job", static_cast<int64_t>(0), "bb", err));
    BOOST_CHECK_EQUAL(err, "ALTERED");
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(0)), "aa");
    BOOST_CHECK(!manifest.sealed("job"));

    BOOST_CHECK(!manifest.Accept("job", static_cast<int64_t>(0), "aa", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(0)), "aa");
}

BOOST_AUTO_TEST_CASE(expiry_stores_nothing)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.Open("", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.stored(""));

    BOOST_CHECK(!manifest.Open("zero", static_cast<int64_t>(0), static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.stored("zero"));
    BOOST_CHECK_EQUAL(manifest.pieces("zero"), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.Open("neg", static_cast<int64_t>(-1), static_cast<int64_t>(1), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "PIECE");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.Open("eq", static_cast<int64_t>(2), static_cast<int64_t>(5), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.stored("eq"));
    BOOST_CHECK_EQUAL(manifest.accepted("eq"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(manifest.pieces("eq"), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.Open("late", static_cast<int64_t>(2), static_cast<int64_t>(6), static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
    BOOST_CHECK(!manifest.stored("late"));

    BOOST_CHECK(manifest.Open("keep", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!manifest.Open("keep", static_cast<int64_t>(9), static_cast<int64_t>(1), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(manifest.pieces("keep"), static_cast<int64_t>(2));

    BOOST_CHECK(!manifest.Open("other", static_cast<int64_t>(2), static_cast<int64_t>(4), static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(1));
    BOOST_CHECK(!manifest.stored("other"));
    BOOST_CHECK(manifest.stored("keep"));
}

BOOST_AUTO_TEST_CASE(producer_claim_is_not_a_compute_proof)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(manifest.Open("job", static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(7), err));
    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(0), "piece-0", err));
    BOOST_CHECK(manifest.Accept("job", static_cast<int64_t>(1), "piece-1", err));
    BOOST_CHECK(manifest.Seal("job", err));
    BOOST_CHECK(manifest.sealed());
    BOOST_CHECK(!manifest.compute_proof());

    BOOST_CHECK(!manifest.Claim("job", err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(!manifest.Claim("job", true, err));
    BOOST_CHECK_EQUAL(err, "CLAIM");
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(manifest.sealed("job"));
    BOOST_CHECK_EQUAL(manifest.accepted("job"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(manifest.digest("job", static_cast<int64_t>(0)), "piece-0");
    BOOST_CHECK_EQUAL(manifest.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(manifest.Claim("job", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(manifest.sealed());
}

BOOST_AUTO_TEST_CASE(rdma_is_engine_absent)
{
    modelnet::NifManifest manifest;
    std::string err;

    BOOST_CHECK(!modelnet::NifDtEngineLinked("rdma"));
    BOOST_CHECK(!modelnet::NifDtEngineLinked("nixl"));
    BOOST_CHECK(!modelnet::NifDtEngineLinked("mooncake"));

    BOOST_CHECK(!manifest.Remote("rdma", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(manifest.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.Remote("nixl", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(manifest.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.Remote("mooncake", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(manifest.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!manifest.launched());
    BOOST_CHECK(!manifest.gpu());
    BOOST_CHECK(!manifest.broadcast());
    BOOST_CHECK_EQUAL(manifest.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(manifest.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!manifest.compute_proof());
    BOOST_CHECK(!manifest.sealed());
    BOOST_CHECK_EQUAL(manifest.count(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
