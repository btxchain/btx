// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Per-stripe repair: global n is not sufficiency. Coordinator: add this
// file to test_btx. Do not treat global shard count as reconstructable.

#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_gap_erasure_tests, BasicTestingSetup)

namespace {

modelnet::ErasureManifest MakeMan(int k, int n, const std::vector<std::vector<int>>& position_sets)
{
    modelnet::ErasureManifest m;
    m.profile = "test-k-n";
    m.data_shards = k;
    m.total_shards = n;
    m.shard_bytes = 4;
    m.stripe_count = position_sets.size();
    m.final_real_piece_count = k;
    m.stripes.reserve(position_sets.size());
    for (size_t i = 0; i < position_sets.size(); ++i) {
        modelnet::ErasureStripe s;
        s.stripe_index = static_cast<uint32_t>(i);
        s.positions = position_sets[i];
        m.stripes.push_back(std::move(s));
    }
    return m;
}

} // namespace

BOOST_AUTO_TEST_CASE(repair_refuses_when_global_n_is_not_sufficiency)
{
    using namespace modelnet;
    // Stripe 0 holds all n positions; stripe 1 holds k-1. Global count 4+1 looks
    // "enough" for k=2; ErasureManifestReconstructable is still false.
    const auto man = MakeMan(2, 4, {{0, 1, 2, 3}, {0}});
    BOOST_CHECK(!ErasureManifestReconstructable(man));
    BOOST_CHECK_EQUAL(EvaluateErasureHealth(man).global_position_count, 5);

    std::vector<std::vector<unsigned char>> data{{1, 2, 3, 4}, {5, 6, 7, 8}};
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 4, coded, err));
    std::vector<std::vector<unsigned char>> out;
    BOOST_CHECK(!RepairCanonicalFromShards(man, {coded[0], coded[2]}, {0, 2}, out, err));
    BOOST_CHECK(err.find("global n is not sufficiency") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(repair_requires_distinct_k_then_reconstruct_shards)
{
    using namespace modelnet;
    const auto man = MakeMan(2, 4, {{0, 2}, {1, 3}});
    BOOST_CHECK(ErasureManifestReconstructable(man));

    std::vector<std::vector<unsigned char>> data{{9, 8, 7, 6}, {1, 3, 5, 7}};
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 4, coded, err));

    std::vector<std::vector<unsigned char>> out;
    BOOST_CHECK(!RepairCanonicalFromShards(man, {coded[0]}, {0}, out, err));
    BOOST_CHECK_EQUAL(err, "distinct k positions required");

    BOOST_CHECK(!RepairCanonicalFromShards(man, {coded[0], coded[0]}, {0, 0}, out, err));
    BOOST_CHECK_EQUAL(err, "distinct k positions required");

    BOOST_REQUIRE(RepairCanonicalFromShards(man, {coded[0], coded[2]}, {0, 2}, out, err, 0));
    BOOST_REQUIRE_EQUAL(out.size(), 2);
    BOOST_CHECK(out[0] == data[0]);
    BOOST_CHECK(out[1] == data[1]);
}

BOOST_AUTO_TEST_SUITE_END()
