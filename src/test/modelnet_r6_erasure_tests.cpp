// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Independent review lane R6 (Erasure), SPEC 14.
//
// Part A pins the honest per-stripe behaviour that already held before the R6
// fixes, so nobody can refactor the padding path back out from under it.
//
// Part B was originally a set of deliberate RED assertions, one per finding
// R6-01..R6-12. It has been inverted: every assertion now states the FIXED
// behaviour and fails against the vulnerable tree at 573b4aa4.
//
// Part C addresses the SPEC 14 health surface directly: the per-stripe record
// must expose k_required, independent_shards, distinct_failure_domains and
// reconstructable, independent_shards must count stored shards only, and the
// record must keep that shape whatever verdict a stripe earns.
//
// Scope note: a global shard count is never sufficiency. Neither is an
// encode/decode round trip. Every proof here is addressed to one stripe.
//
// Store-lane findings (R6-04 shard hashing, R6-05 stripe binding, R6-08
// restart, R6-10 bounded reads) live in erasure_store.cpp. Every case below
// asserts a refusal or an acceptance, including the error strings, and none of
// them is a warning: the file is green against the fixed tree and is therefore
// ready to register in src/test/CMakeLists.txt.

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <modelnet/io_executor.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <numeric>
#include <set>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r6_erasure_tests, BasicTestingSetup)

namespace {

constexpr int kK = modelnet::ERASURE_K_16_20;
constexpr int kN = modelnet::ERASURE_N_16_20;
constexpr uint32_t kShardBytes = modelnet::ERASURE_SHARD_BYTES_16_20;

std::string Hex96(char c) { return std::string(96, c); }

std::vector<int> Range(int lo, int hi_exclusive)
{
    std::vector<int> v(static_cast<size_t>(hi_exclusive - lo));
    std::iota(v.begin(), v.end(), lo);
    return v;
}

/** Struct manifest. file_size_bytes is left 0, so no padding claim is proven. */
modelnet::ErasureManifest Man(int k, int n, const std::vector<std::vector<int>>& sets, int final_real_pieces)
{
    modelnet::ErasureManifest m;
    m.profile = "r6-review-k-n";
    m.data_shards = k;
    m.total_shards = n;
    m.shard_bytes = 8;
    m.stripe_count = sets.size();
    m.final_real_piece_count = final_real_pieces;
    m.stripes.reserve(sets.size());
    for (size_t i = 0; i < sets.size(); ++i) {
        modelnet::ErasureStripe s;
        s.stripe_index = static_cast<uint32_t>(i);
        s.positions = sets[i];
        m.stripes.push_back(std::move(s));
    }
    return m;
}

/** Like Man(), but array order and the stripe_index of each entry are independent. */
modelnet::ErasureManifest ManIdx(int k, int n, uint64_t stripe_count,
                                 const std::vector<std::pair<uint32_t, std::vector<int>>>& entries,
                                 int final_real_pieces)
{
    modelnet::ErasureManifest m;
    m.profile = "r6-review-k-n";
    m.data_shards = k;
    m.total_shards = n;
    m.shard_bytes = 8;
    m.stripe_count = stripe_count;
    m.final_real_piece_count = final_real_pieces;
    m.stripes.reserve(entries.size());
    for (const auto& [idx, positions] : entries) {
        modelnet::ErasureStripe s;
        s.stripe_index = idx;
        s.positions = positions;
        m.stripes.push_back(std::move(s));
    }
    return m;
}

/** The file size a manifest must declare for its padding claim to be honest. */
uint64_t HonestSize(int k, uint32_t shard_bytes, size_t stripe_count, int final_real_pieces)
{
    if (stripe_count == 0) return 0;
    return static_cast<uint64_t>(stripe_count - 1) * static_cast<uint64_t>(k) * shard_bytes +
           static_cast<uint64_t>(final_real_pieces) * shard_bytes;
}

/** Give a struct manifest the geometry its final_real_piece_count claims. */
void SetHonestGeometry(modelnet::ErasureManifest& m)
{
    m.file_size_bytes =
        HonestSize(m.data_shards, m.shard_bytes, m.stripe_count, m.final_real_piece_count);
}

UniValue ManJsonRaw(int k, int n, uint32_t shard_bytes, const std::vector<std::vector<int>>& sets,
                    int final_real_pieces, const std::string& profile, const std::string& poly,
                    uint64_t file_size_bytes)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", 1);
    o.pushKV("profile", profile);
    o.pushKV("canonical_artifact_id", Hex96('a'));
    o.pushKV("canonical_manifest_id", Hex96('c'));
    o.pushKV("file_index", 0);
    o.pushKV("file_size_bytes", std::to_string(file_size_bytes));
    o.pushKV("data_shards", k);
    o.pushKV("total_shards", n);
    o.pushKV("shard_bytes", static_cast<int64_t>(shard_bytes));
    o.pushKV("field_polynomial", poly);
    o.pushKV("stripe_count", std::to_string(sets.size()));
    o.pushKV("final_real_piece_count", final_real_pieces);
    o.pushKV("shard_index_root", Hex96('b'));
    UniValue stripes(UniValue::VARR);
    for (size_t i = 0; i < sets.size(); ++i) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("index", static_cast<int>(i));
        UniValue pos(UniValue::VARR);
        for (int p : sets[i]) pos.push_back(p);
        e.pushKV("positions", pos);
        stripes.push_back(std::move(e));
    }
    o.pushKV("stripes", stripes);
    return o;
}

/** A manifest that parses: the reserved 16/20 profile with honest geometry. */
UniValue ManJson(const std::vector<std::vector<int>>& sets, int final_real_pieces)
{
    return ManJsonRaw(kK, kN, kShardBytes, sets, final_real_pieces,
                      modelnet::ERASURE_PROFILE_CAUCHY_16_20_V1, modelnet::ERASURE_FIELD_POLYNOMIAL,
                      HonestSize(kK, kShardBytes, sets.size(), final_real_pieces));
}

/** Replace the declared stripe_index of each entry, keeping positions and array order. */
void ReindexStripes(UniValue& manifest_json, const std::vector<int>& indices)
{
    UniValue stripes(UniValue::VARR);
    const auto& old = manifest_json["stripes"].getValues();
    BOOST_REQUIRE_EQUAL(old.size(), indices.size());
    for (size_t i = 0; i < old.size(); ++i) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("index", indices[i]);
        e.pushKV("positions", old[i]["positions"]);
        stripes.push_back(std::move(e));
    }
    manifest_json.pushKV("stripes", stripes);
}

/** Attach one failure-domain label per stored position of every stripe. */
void SetFailureDomains(UniValue& manifest_json, const std::vector<std::vector<std::string>>& domains)
{
    UniValue stripes(UniValue::VARR);
    const auto& old = manifest_json["stripes"].getValues();
    BOOST_REQUIRE_EQUAL(old.size(), domains.size());
    for (size_t i = 0; i < old.size(); ++i) {
        UniValue e = old[i];
        UniValue labels(UniValue::VARR);
        for (const auto& d : domains[i]) labels.push_back(d);
        e.pushKV("failure_domains", labels);
        stripes.push_back(std::move(e));
    }
    manifest_json.pushKV("stripes", stripes);
}

void SetRequiredExtensions(UniValue& manifest_json, const std::vector<std::string>& names)
{
    UniValue ext(UniValue::VARR);
    for (const auto& n : names) ext.push_back(n);
    manifest_json.pushKV("required_extensions", ext);
}

std::vector<std::vector<unsigned char>> DataShards(int k, size_t len)
{
    std::vector<std::vector<unsigned char>> d;
    d.reserve(static_cast<size_t>(k));
    for (int i = 0; i < k; ++i) {
        d.emplace_back(len, static_cast<unsigned char>(0x40 + i));
    }
    return d;
}

std::string Sha384Hex(const std::vector<unsigned char>& bytes)
{
    unsigned char digest[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(digest);
    return HexStr(Span<const unsigned char>{digest, CSHA384::OUTPUT_SIZE});
}

void WriteBytes(const fs::path& p, const std::vector<unsigned char>& bytes)
{
    std::ofstream out(fs::PathToString(p), std::ios::binary);
    BOOST_REQUIRE(out);
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    BOOST_REQUIRE(out);
}

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream in(fs::PathToString(p), std::ios::binary);
    BOOST_REQUIRE(in);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

} // namespace

// ---------------------------------------------------------------------------
// Part A. Properties that held before the R6 fixes. Pin them.
// ---------------------------------------------------------------------------

/** k exactly, and k+N, are each judged on their own stripe. */
BOOST_AUTO_TEST_CASE(r6_a_k_exact_and_k_plus_n_are_judged_per_stripe)
{
    using namespace modelnet;
    // final_real_piece_count == k, so no dummy-zero padding is claimed anywhere.
    const auto man = Man(16, 20, {Range(0, 16), Range(0, 20)}, 16);
    BOOST_REQUIRE(ErasureManifestReconstructable(man));

    const auto h = EvaluateErasureHealth(man);
    BOOST_REQUIRE_EQUAL(h.stripes.size(), 2U);
    BOOST_CHECK_EQUAL(h.k, 16);
    BOOST_CHECK_EQUAL(h.n, 20);
    // Stripe 0 sits exactly on k. No surplus anywhere else may be borrowed for it.
    BOOST_CHECK_EQUAL(h.stripes[0].distinct_stored, 16);
    BOOST_CHECK_EQUAL(h.stripes[0].deficit, 0);
    BOOST_CHECK(h.stripes[0].reconstructable);
    // Stripe 1 holds k+4. The surplus is confined to stripe 1.
    BOOST_CHECK_EQUAL(h.stripes[1].distinct_stored, 20);
    BOOST_CHECK_EQUAL(h.stripes[1].deficit, 0);
    BOOST_CHECK_EQUAL(h.reconstructable_stripes, 2U);
    BOOST_CHECK_EQUAL(h.deficit_stripes, 0U);
    BOOST_CHECK_EQUAL(h.global_position_count, 36U);
}

/** Enormous global surplus does not carry one k-1 stripe. */
BOOST_AUTO_TEST_CASE(r6_a_k_minus_one_survives_a_large_global_surplus)
{
    using namespace modelnet;
    std::vector<std::vector<int>> sets;
    for (int i = 0; i < 9; ++i) sets.push_back(i == 4 ? Range(0, 15) : Range(0, 20));
    const auto man = Man(16, 20, sets, 16);

    const auto h = EvaluateErasureHealth(man);
    // 8*20 + 15 = 175 stored positions against 9*16 = 144 "needed". The naive
    // global comparison says yes by a margin of 31. Per stripe it is no.
    BOOST_CHECK_EQUAL(h.global_position_count, 175U);
    BOOST_CHECK_GT(h.global_position_count, 144U);
    BOOST_CHECK(!h.reconstructable);
    BOOST_CHECK(!ErasureManifestReconstructable(man));
    // The single offender is named, not merely counted.
    BOOST_CHECK_EQUAL(h.deficit_stripes, 1U);
    BOOST_CHECK_EQUAL(h.reconstructable_stripes, 8U);
    BOOST_REQUIRE_EQUAL(h.stripes.size(), 9U);
    BOOST_CHECK_EQUAL(h.stripes[4].stripe_index, 4U);
    BOOST_CHECK_EQUAL(h.stripes[4].distinct_stored, 15);
    BOOST_CHECK_EQUAL(h.stripes[4].deficit, 1);
    BOOST_CHECK(!h.stripes[4].reconstructable);
    for (size_t i = 0; i < h.stripes.size(); ++i) {
        if (i == 4) continue;
        BOOST_CHECK_MESSAGE(h.stripes[i].reconstructable, "stripe " << i << " should stand on its own");
    }
}

/** Uneven distribution: the verdict tracks the worst stripe, not the mean. */
BOOST_AUTO_TEST_CASE(r6_a_uneven_distribution_tracks_the_worst_stripe)
{
    using namespace modelnet;
    const auto bad = Man(16, 20, {Range(0, 20), Range(0, 16), Range(0, 15)}, 16);
    BOOST_CHECK(!ErasureManifestReconstructable(bad));
    const auto hb = EvaluateErasureHealth(bad);
    BOOST_CHECK_EQUAL(hb.stripes[2].deficit, 1);

    // Mean stored per stripe rises from 17.0 to 17.33 and the verdict flips to
    // true only because the worst stripe reached k.
    const auto good = Man(16, 20, {Range(0, 20), Range(0, 16), Range(0, 16)}, 16);
    BOOST_CHECK(ErasureManifestReconstructable(good));
    const auto hg = EvaluateErasureHealth(good);
    BOOST_CHECK_EQUAL(hg.deficit_stripes, 0U);
}

/** Duplicate positions inside one stripe are not independent shards. */
BOOST_AUTO_TEST_CASE(r6_a_duplicate_positions_are_not_independent_shards)
{
    using namespace modelnet;
    const auto man = Man(16, 20, {std::vector<int>(20, 3)}, 16);
    BOOST_CHECK(!ErasureManifestReconstructable(man));
    const auto h = EvaluateErasureHealth(man);
    BOOST_CHECK_EQUAL(h.stripes[0].distinct_stored, 1);
    BOOST_CHECK_EQUAL(h.stripes[0].independent_shards, 1);
    BOOST_CHECK_EQUAL(h.stripes[0].deficit, 15);
    // R6-12: the informational counter sums distinct positions, so twenty
    // copies of position 3 report 1 rather than an inflatable 20.
    BOOST_CHECK_EQUAL(h.global_position_count, 1U);
}

/** The repair entry point takes exactly k distinct positions: not k-1, not k+1. */
BOOST_AUTO_TEST_CASE(r6_a_repair_arity_is_exactly_k)
{
    using namespace modelnet;
    const auto man = Man(16, 20, {Range(0, 16), Range(0, 20)}, 16);
    const auto data = DataShards(16, 8);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 20, coded, err));
    BOOST_REQUIRE_EQUAL(coded.size(), 20U);

    std::vector<std::vector<unsigned char>> out;

    // k-1.
    std::vector<std::vector<unsigned char>> short_set(coded.begin(), coded.begin() + 15);
    BOOST_CHECK(!RepairCanonicalFromShards(man, short_set, Range(0, 15), out, err, 1));
    BOOST_CHECK_EQUAL(err, "distinct k positions required");

    // k+1. Refused rather than narrowed to a k-subset. Fail-closed, worth pinning.
    std::vector<std::vector<unsigned char>> long_set(coded.begin(), coded.begin() + 17);
    BOOST_CHECK(!RepairCanonicalFromShards(man, long_set, Range(0, 17), out, err, 1));
    BOOST_CHECK_EQUAL(err, "distinct k positions required");

    // Exactly k, using four parity positions, round-trips. Stripe 1 stores all
    // twenty positions, so every supplied position belongs to the named stripe.
    std::vector<int> mixed = Range(0, 12);
    for (int p : {16, 17, 18, 19}) mixed.push_back(p);
    std::vector<std::vector<unsigned char>> mixed_shards;
    for (int p : mixed) mixed_shards.push_back(coded[static_cast<size_t>(p)]);
    BOOST_REQUIRE_MESSAGE(RepairCanonicalFromShards(man, mixed_shards, mixed, out, err, 1), err);
    BOOST_REQUIRE_EQUAL(out.size(), 16U);
    for (size_t i = 0; i < out.size(); ++i) {
        BOOST_CHECK_MESSAGE(out[i] == data[i], "data shard " << i << " mismatch");
    }
}

/** Parser bounds that do hold. */
BOOST_AUTO_TEST_CASE(r6_a_parser_bounds_that_hold)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    UniValue too_many = ManJson({Range(0, 16)}, 16);
    too_many.pushKV("stripe_count", std::string("1000001"));
    BOOST_CHECK(!ParseErasureManifest(too_many, m, err));
    BOOST_CHECK_EQUAL(err, "stripe_count");

    UniValue mismatch = ManJson({Range(0, 16), Range(0, 16)}, 16);
    mismatch.pushKV("stripe_count", std::string("3"));
    BOOST_CHECK(!ParseErasureManifest(mismatch, m, err));
    BOOST_CHECK_EQUAL(err, "stripes");

    UniValue v2 = ManJson({Range(0, 16)}, 16);
    v2.pushKV("version", 2);
    BOOST_CHECK(!ParseErasureManifest(v2, m, err));
    BOOST_CHECK_EQUAL(err, "version");

    // The reserved profile name pins its own dimensions.
    UniValue wrong_dims = ManJsonRaw(8, 20, kShardBytes, {Range(0, 8)}, 8,
                                     ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                     HonestSize(8, kShardBytes, 1, 8));
    BOOST_CHECK(!ParseErasureManifest(wrong_dims, m, err));
    BOOST_CHECK_EQUAL(err, "profile dimensions");

    // A position outside 0..n-1 is refused.
    UniValue over = ManJson({{0, 1, 2, 20}}, 16);
    BOOST_CHECK(!ParseErasureManifest(over, m, err));
    BOOST_CHECK_EQUAL(err, "position");
}

/** Unknown extension objects are still walked for floats and for secrets. */
BOOST_AUTO_TEST_CASE(r6_a_unknown_extension_cannot_smuggle_floats_or_secrets)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    UniValue with_secret = ManJson({Range(0, 16)}, 16);
    UniValue ext(UniValue::VOBJ);
    ext.pushKV("wallet_seed", std::string("deadbeef"));
    with_secret.pushKV("r6_future_extension", ext);
    BOOST_CHECK(!ParseErasureManifest(with_secret, m, err));
    BOOST_CHECK(err.find("secret-bearing key") != std::string::npos);

    UniValue with_float = ManJson({Range(0, 16)}, 16);
    UniValue ext2(UniValue::VOBJ);
    ext2.pushKV("durability", UniValue(UniValue::VNUM, "0.9999"));
    with_float.pushKV("r6_future_extension", ext2);
    BOOST_CHECK(!ParseErasureManifest(with_float, m, err));
    BOOST_CHECK_EQUAL(err, "floats prohibited");
}

// ---------------------------------------------------------------------------
// Part B. The R6 findings, inverted: each assertion states the fixed behaviour
// and fails against the vulnerable tree.
// ---------------------------------------------------------------------------

/**
 * R6-01. Two separate forgeries are closed. The credit now follows
 * stripe_index == stripe_count-1 instead of whichever stripe sits last in the
 * array, and a declared final_real_piece_count mints nothing at all unless
 * file_size_bytes proves the tail really is short.
 */
BOOST_AUTO_TEST_CASE(r6_b_padding_credit_cannot_be_forged)
{
    using namespace modelnet;
    // Logical stripe 0 holds a single parity shard. It is placed LAST in the
    // array and final_real_piece_count is declared 1, which used to mint 15
    // free data slots for it. Stripe 0 is not the tail of the file.
    const auto forged = ManIdx(16, 20, 2, {{1, Range(0, 20)}, {0, {19}}}, 1);

    const auto h = EvaluateErasureHealth(forged);
    BOOST_REQUIRE_EQUAL(h.stripes.size(), 2U);
    // Health preserves array order, so slot 1 is the starved logical stripe 0.
    BOOST_REQUIRE_EQUAL(h.stripes[0].stripe_index, 1U);
    BOOST_REQUIRE_EQUAL(h.stripes[1].stripe_index, 0U);

    BOOST_CHECK_EQUAL(h.stripes[1].independent_shards, 1);
    BOOST_CHECK_MESSAGE(h.stripes[1].padding_credit == 0,
                        "R6-01: stripe_index 0 is not the file tail, so it receives no dummy-zero "
                        "credit; got padding_credit " << h.stripes[1].padding_credit);
    BOOST_CHECK_EQUAL(h.stripes[1].distinct_effective, 1);
    BOOST_CHECK_EQUAL(h.stripes[1].deficit, 15);
    BOOST_CHECK_MESSAGE(!h.stripes[1].reconstructable,
                        "R6-01: a stripe with 1 stored shard and k=16 must not be reconstructable");
    BOOST_CHECK(!h.reconstructable);
    BOOST_CHECK(!ErasureManifestReconstructable(forged));
    BOOST_CHECK_EQUAL(h.deficit_stripes, 1U);
    BOOST_CHECK_EQUAL(h.reconstructable_stripes, 1U);
    BOOST_CHECK_EQUAL(h.stripes[0].distinct_effective, 20);

    // Second forgery: put the starved stripe at the tail index instead. The
    // claim is still unproven, because file_size_bytes is not set, so the
    // credit is still zero and the verdict is still no.
    const auto unproven = ManIdx(16, 20, 2, {{0, Range(0, 16)}, {1, {0}}}, 1);
    BOOST_CHECK(ErasureTailPaddingSlots(unproven).empty());
    BOOST_CHECK_MESSAGE(!ErasureManifestReconstructable(unproven),
                        "R6-01: final_real_piece_count is attacker-chosen, so an unproven padding "
                        "claim must be worth no slots at all");
    const auto hu = EvaluateErasureHealth(unproven);
    BOOST_CHECK_EQUAL(hu.stripes[1].padding_credit, 0);
    BOOST_CHECK_EQUAL(hu.stripes[1].deficit, 15);
    BOOST_CHECK_EQUAL(hu.padding_credited_stripe, -1);

    // An honestly short tail, whose file_size_bytes agrees, is credited. The
    // credit lands on stripe_index 1 whatever the array order is.
    auto tail_last = ManIdx(16, 20, 2, {{0, Range(0, 16)}, {1, {0}}}, 1);
    SetHonestGeometry(tail_last);
    auto tail_first = ManIdx(16, 20, 2, {{1, {0}}, {0, Range(0, 16)}}, 1);
    SetHonestGeometry(tail_first);
    BOOST_REQUIRE_EQUAL(ErasureTailPaddingSlots(tail_last).size(), 15U);
    BOOST_CHECK(ErasureManifestReconstructable(tail_last));
    BOOST_CHECK_MESSAGE(ErasureManifestReconstructable(tail_first),
                        "R6-01: the verdict is keyed on stripe_index, so reordering the array must "
                        "not change it");

    const auto ht = EvaluateErasureHealth(tail_first);
    BOOST_REQUIRE_EQUAL(ht.stripes.size(), 2U);
    BOOST_REQUIRE_EQUAL(ht.stripes[0].stripe_index, 1U);
    BOOST_CHECK_EQUAL(ht.stripes[0].independent_shards, 1);
    BOOST_CHECK_EQUAL(ht.stripes[0].padding_credit, 15);
    BOOST_CHECK_EQUAL(ht.stripes[0].distinct_effective, 16);
    BOOST_CHECK(ht.stripes[0].reconstructable);
    BOOST_CHECK_EQUAL(ht.deficit_stripes, 0U);
    BOOST_CHECK_EQUAL(ht.padding_credited_stripe, 1);
    // The tail is short by construction, and the record says so out loud
    // rather than folding the padding into the shard count.
    BOOST_CHECK_MESSAGE(ht.stripes[0].independent_shards < ht.stripes[0].k_required,
                        "R6-01: a credited tail stripe must still report fewer independent shards "
                        "than k, so an operator can see it is short by construction");
}

/**
 * R6-02. stripe_count, file_size_bytes, shard_bytes and final_real_piece_count
 * are cross-checked. A padding claim must be derived from file_size_bytes, and
 * a file_size_bytes that no stripe set could hold is refused outright.
 */
BOOST_AUTO_TEST_CASE(r6_b_geometry_is_cross_checked)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    // One stripe of 16 x 4 MiB holds at most 64 MiB. This manifest claims 8 EiB,
    // which would need 137438953472 stripes.
    UniValue huge = ManJson({Range(0, 16)}, 16);
    huge.pushKV("file_size_bytes", std::string("9223372036854775807"));
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(huge, m, err),
                        "R6-02: a file_size_bytes needing more stripes than the parser will hold "
                        "must be refused, not carried");
    BOOST_CHECK_EQUAL(err, "file_size_bytes");

    // A full-length tail that nevertheless claims one real piece, which would
    // harvest k-1 free slots.
    UniValue lying_tail = ManJsonRaw(kK, kN, kShardBytes, {Range(0, 16), Range(0, 16)}, 1,
                                     ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                     HonestSize(kK, kShardBytes, 2, 16));
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(lying_tail, m, err),
                        "R6-02: final_real_piece_count must be derived from file_size_bytes, not asserted");
    BOOST_CHECK_EQUAL(err, "final_real_piece_count");

    // stripe_count 0 with a non-zero payload.
    UniValue empty = ManJsonRaw(kK, kN, kShardBytes, {}, 16, ERASURE_PROFILE_CAUCHY_16_20_V1,
                                ERASURE_FIELD_POLYNOMIAL, 1048576);
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(empty, m, err),
                        "R6-02: stripe_count 0 with a non-empty file must be rejected");
    BOOST_CHECK_EQUAL(err, "stripe_count");

    // And the converse: stripes that describe a zero-byte file.
    UniValue no_bytes = ManJson({Range(0, 16)}, 16);
    no_bytes.pushKV("file_size_bytes", std::string("0"));
    BOOST_CHECK(!ParseErasureManifest(no_bytes, m, err));
    BOOST_CHECK_EQUAL(err, "file_size_bytes");

    // An honestly short tail parses, is credited, and is reported consistent.
    UniValue honest = ManJsonRaw(kK, kN, kShardBytes, {Range(0, 16), Range(0, 5)}, 5,
                                 ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                 HonestSize(kK, kShardBytes, 2, 5));
    ErasureManifest hm;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(honest, hm, err), err);
    BOOST_CHECK(ErasureGeometryConsistent(hm));
    BOOST_CHECK_EQUAL(ErasureTailPaddingSlots(hm).size(), 11U);
    BOOST_CHECK(ErasureManifestReconstructable(hm));
    const auto hh = EvaluateErasureHealth(hm);
    BOOST_CHECK(hh.geometry_consistent);
    BOOST_REQUIRE_EQUAL(hh.stripes.size(), 2U);
    BOOST_CHECK_EQUAL(hh.stripes[1].independent_shards, 5);
    BOOST_CHECK_EQUAL(hh.stripes[1].padding_credit, 11);
    BOOST_CHECK(hh.stripes[1].reconstructable);

    // The same stripe sets with one byte more of declared payload no longer
    // justify 11 free slots, so the claim is refused.
    UniValue off_by_one_byte = ManJsonRaw(kK, kN, kShardBytes, {Range(0, 16), Range(0, 5)}, 5,
                                          ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                          HonestSize(kK, kShardBytes, 2, 5) + kShardBytes);
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(off_by_one_byte, m, err),
                        "R6-02: one extra shard of declared payload makes the tail six pieces, so a "
                        "claim of five must be refused");
}

/**
 * R6-03. The stripe index set must be exactly {0..stripe_count-1} in ascending
 * order. This is also the precondition for R6-01: without it the tail stripe is
 * not identifiable.
 */
BOOST_AUTO_TEST_CASE(r6_b_stripe_index_set_must_cover_the_declared_range)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    // Stripes 7 and 999 of a 2-stripe file prove nothing about stripes 0 and 1.
    UniValue wild = ManJson({Range(0, 16), Range(0, 16)}, 16);
    ReindexStripes(wild, {7, 999});
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(wild, m, err),
                        "R6-03: stripe indices must lie in {0..stripe_count-1}");
    BOOST_CHECK_EQUAL(err, "stripe index");

    // Off by one at the top of the range.
    UniValue off_by_one = ManJson({Range(0, 16), Range(0, 16)}, 16);
    ReindexStripes(off_by_one, {0, 2});
    BOOST_CHECK(!ParseErasureManifest(off_by_one, m, err));
    BOOST_CHECK_EQUAL(err, "stripe index");

    // A single stripe declaring index 1 leaves stripe 0 unaccounted for.
    UniValue lone = ManJson({Range(0, 16)}, 16);
    ReindexStripes(lone, {1});
    BOOST_CHECK(!ParseErasureManifest(lone, m, err));
    BOOST_CHECK_EQUAL(err, "stripe index");

    // Duplicates were already refused. Keep them refused.
    UniValue dupes = ManJson({Range(0, 16), Range(0, 16)}, 16);
    ReindexStripes(dupes, {0, 0});
    BOOST_CHECK(!ParseErasureManifest(dupes, m, err));
    BOOST_CHECK_EQUAL(err, "duplicate stripe");

    // Complete coverage out of order is refused so that the array order health
    // echoes back is the stripe order.
    UniValue reordered = ManJson({Range(0, 16), Range(0, 16)}, 16);
    ReindexStripes(reordered, {1, 0});
    BOOST_CHECK(!ParseErasureManifest(reordered, m, err));
    BOOST_CHECK_EQUAL(err, "stripe order");

    // The well-formed case still parses.
    UniValue ok = ManJson({Range(0, 16), Range(0, 16)}, 16);
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(ok, m, err), err);
    BOOST_REQUIRE_EQUAL(m.stripes.size(), 2U);
    BOOST_CHECK_EQUAL(m.stripes[0].stripe_index, 0U);
    BOOST_CHECK_EQUAL(m.stripes[1].stripe_index, 1U);
    BOOST_CHECK(ErasureStripeIndexSetOk(m));
}

/**
 * R6-04. A shard that does not match its declared shard_hash_hex is refused
 * rather than decoded into silently wrong canonical data. The manifest lane
 * additionally binds shard_index_root to the declared inventory, so the root
 * can no longer sit alongside a substituted set.
 */
BOOST_AUTO_TEST_CASE(r6_b_corrupted_shard_is_refused)
{
    using namespace modelnet;
    const auto data = DataShards(16, 64);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 20, coded, err));

    // One stripe storing every position, with the honest SHA-384 of each.
    auto man = Man(16, 20, {Range(0, 20)}, 16);
    for (int p : man.stripes[0].positions) {
        man.stripes[0].shard_hash_hex.push_back(Sha384Hex(coded[static_cast<size_t>(p)]));
    }
    BOOST_REQUIRE_EQUAL(man.stripes[0].shard_hash_hex.size(), 20U);

    std::vector<int> pos = Range(0, 15);
    pos.push_back(16); // fifteen data positions plus one parity position
    std::vector<std::vector<unsigned char>> shards;
    for (int p : pos) shards.push_back(coded[static_cast<size_t>(p)]);

    // Honest shards against honest hashes still round-trip. This also pins that
    // the hash is looked up by position and not by the caller's array slot:
    // slot 15 carries position 16, so a slot-indexed lookup would compare the
    // shard for position 16 against the hash of position 15 and refuse here.
    std::vector<std::vector<unsigned char>> out;
    BOOST_REQUIRE_MESSAGE(RepairCanonicalFromShards(man, shards, pos, out, err, 0), err);
    BOOST_REQUIRE_EQUAL(out.size(), 16U);
    for (size_t i = 0; i < out.size(); ++i) {
        BOOST_CHECK_MESSAGE(out[i] == data[i], "data shard " << i << " mismatch");
    }

    // One flipped bit in the parity shard.
    auto bad_parity = shards;
    bad_parity.back()[0] ^= 0xff;
    std::vector<std::vector<unsigned char>> out_parity;
    std::string parity_err;
    BOOST_CHECK_MESSAGE(!RepairCanonicalFromShards(man, bad_parity, pos, out_parity, parity_err, 0),
                        "R6-04: a shard that does not match its declared shard_hash_hex must be refused");
    // The refusal names the hash check, and nothing is handed back to the caller.
    BOOST_CHECK_EQUAL(parity_err, "shard hash mismatch");
    BOOST_CHECK(out_parity.empty());

    // A single flipped bit deep inside an interior data shard is caught too,
    // not just a wholesale corruption of the first byte of a parity shard.
    auto bad_data = shards;
    bad_data[3][7] ^= 0x01;
    std::vector<std::vector<unsigned char>> out_data;
    std::string data_err;
    BOOST_CHECK_MESSAGE(!RepairCanonicalFromShards(man, bad_data, pos, out_data, data_err, 0),
                        "R6-04: the whole shard must be hashed, so one flipped bit at offset 7 of "
                        "the shard for position 3 is refused");

    // shard_hash_hex stays optional: a manifest that declares none still repairs.
    const auto no_hashes = Man(16, 20, {Range(0, 20)}, 16);
    std::vector<std::vector<unsigned char>> out_plain;
    BOOST_CHECK_MESSAGE(RepairCanonicalFromShards(no_hashes, shards, pos, out_plain, err, 0), err);
}

/** R6-04. shard_index_root commits to the declared (stripe, position, hash) triples. */
BOOST_AUTO_TEST_CASE(r6_b_shard_index_root_binds_the_inventory)
{
    using namespace modelnet;
    std::string err;

    // Build the inventory as a struct manifest first so its root can be computed.
    ErasureManifest src;
    src.profile = ERASURE_PROFILE_CAUCHY_16_20_V1;
    src.canonical_artifact_id = Hex96('a');
    src.canonical_manifest_id = Hex96('c');
    src.file_index = 0;
    src.file_size_bytes = HonestSize(kK, kShardBytes, 1, 16);
    src.stripe_count = 1;
    src.final_real_piece_count = 16;
    ErasureStripe stripe;
    stripe.stripe_index = 0;
    stripe.positions = Range(0, 16);
    for (int p : stripe.positions) {
        stripe.shard_hash_hex.push_back(Hex96(static_cast<char>('0' + (p % 10))));
    }
    src.stripes.push_back(stripe);

    std::string root;
    BOOST_REQUIRE_MESSAGE(ErasureShardIndexRootHex(src, root, err), err);
    BOOST_CHECK_EQUAL(root.size(), 96U);

    UniValue json = ManJson({Range(0, 16)}, 16);
    UniValue stripes(UniValue::VARR);
    UniValue e = json["stripes"][0];
    UniValue hashes(UniValue::VARR);
    for (const auto& h : stripe.shard_hash_hex) hashes.push_back(h);
    e.pushKV("shard_hashes", hashes);
    stripes.push_back(e);
    json.pushKV("stripes", stripes);

    // The placeholder root does not commit to this inventory.
    ErasureManifest m;
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(json, m, err),
                        "R6-04: a shard_index_root that commits to nothing must be refused once the "
                        "manifest declares shard hashes");
    BOOST_CHECK_EQUAL(err, "shard_index_root");

    // The committed root parses.
    json.pushKV("shard_index_root", root);
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(json, m, err), err);
    BOOST_CHECK_EQUAL(m.shard_index_root, root);

    // Substituting one shard hash invalidates the root.
    UniValue tampered = json;
    UniValue tampered_stripes(UniValue::VARR);
    UniValue te = tampered["stripes"][0];
    UniValue th(UniValue::VARR);
    for (size_t i = 0; i < stripe.shard_hash_hex.size(); ++i) {
        th.push_back(i == 7 ? Hex96('f') : stripe.shard_hash_hex[i]);
    }
    te.pushKV("shard_hashes", th);
    tampered_stripes.push_back(te);
    tampered.pushKV("stripes", tampered_stripes);
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(tampered, m, err),
                        "R6-04: substituting one shard hash must invalidate shard_index_root");

    // Hashes are all or nothing: half an inventory commits to half a file.
    UniValue partial = ManJson({Range(0, 16), Range(0, 16)}, 16);
    UniValue partial_stripes(UniValue::VARR);
    UniValue p0 = partial["stripes"][0];
    p0.pushKV("shard_hashes", hashes);
    partial_stripes.push_back(p0);
    partial_stripes.push_back(partial["stripes"][1]);
    partial.pushKV("stripes", partial_stripes);
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(partial, m, err),
                        "R6-04: a manifest that hashes one stripe and not the other must be refused");
    BOOST_CHECK_EQUAL(err, "shard_hashes");
}

/**
 * R6-05. Repair binds to a named stripe. In a manifest where stripe 0 stores
 * the even positions and stripe 1 the odd ones, stripe 1's shards are no longer
 * accepted as a repair of stripe 0, and a multi-stripe manifest may not be
 * repaired with no stripe named at all.
 */
BOOST_AUTO_TEST_CASE(r6_b_repair_binds_to_one_stripe)
{
    using namespace modelnet;
    std::vector<int> even, odd;
    for (int i = 0; i < 20; i += 2) even.push_back(i);
    for (int i = 1; i < 20; i += 2) odd.push_back(i);
    // Pad each to k=16 distinct so the manifest is reconstructable overall.
    auto s0 = even;
    for (int p : odd) { if (static_cast<int>(s0.size()) < 16) s0.push_back(p); }
    auto s1 = odd;
    for (int p : even) { if (static_cast<int>(s1.size()) < 16) s1.push_back(p); }
    const auto man = Man(16, 20, {s0, s1}, 16);
    BOOST_REQUIRE(ErasureManifestReconstructable(man));

    // The manifest lane exposes the membership gate the repair path needs.
    std::string gate_err;
    BOOST_CHECK_MESSAGE(ErasureStripeAcceptsPositions(man, 1, s1, gate_err), gate_err);
    BOOST_CHECK_MESSAGE(!ErasureStripeAcceptsPositions(man, 0, s1, gate_err),
                        "R6-05: stripe 1's positions are not stored by stripe 0");
    BOOST_CHECK_MESSAGE(!ErasureStripeAcceptsPositions(man, 2, s1, gate_err),
                        "R6-05: stripe 2 does not exist in a 2-stripe manifest");
    std::vector<int> stored;
    BOOST_REQUIRE(ErasureStripeStoredPositions(man, 1, stored));
    BOOST_CHECK(stored == s1);
    BOOST_CHECK(ErasureStripeIndexReconstructable(man, 0));
    BOOST_CHECK(ErasureStripeIndexReconstructable(man, 1));

    const auto data = DataShards(16, 32);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 20, coded, err));
    std::vector<std::vector<unsigned char>> shards;
    for (int p : s1) shards.push_back(coded[static_cast<size_t>(p)]);

    // Named correctly, the repair runs and returns the canonical data shards.
    std::vector<std::vector<unsigned char>> out;
    BOOST_REQUIRE_MESSAGE(RepairCanonicalFromShards(man, shards, s1, out, err, 1), err);
    BOOST_REQUIRE_EQUAL(out.size(), 16U);
    for (size_t i = 0; i < out.size(); ++i) {
        BOOST_CHECK_MESSAGE(out[i] == data[i], "data shard " << i << " mismatch");
    }

    // Named as stripe 0, the same shards are refused.
    std::vector<std::vector<unsigned char>> cross;
    std::string cross_err;
    BOOST_CHECK_MESSAGE(!RepairCanonicalFromShards(man, shards, s1, cross, cross_err, 0),
                        "R6-05: every supplied position must be stored by the named stripe");

    // Named as nothing at all, a multi-stripe manifest is refused.
    std::vector<std::vector<unsigned char>> unbound;
    std::string unbound_err;
    BOOST_CHECK_MESSAGE(!RepairCanonicalFromShards(man, shards, s1, unbound, unbound_err),
                        "R6-05: a repair against a multi-stripe manifest must name its stripe");

    // A stripe that does not exist is refused.
    std::vector<std::vector<unsigned char>> nostripe;
    std::string nostripe_err;
    BOOST_CHECK(!RepairCanonicalFromShards(man, shards, s1, nostripe, nostripe_err, 7));
}

/**
 * R6-06. A deficit stripe publishes an addressable repair target, so a healer
 * can act on the health record instead of inferring the hole from a count.
 */
BOOST_AUTO_TEST_CASE(r6_b_deficit_stripe_publishes_a_repair_target)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    // A 9-stripe file whose stripe 4 has no entry at all is still a whole
    // manifest error: the array length is part of the geometry.
    std::vector<std::vector<int>> sets;
    for (int i = 0; i < 9; ++i) sets.push_back(Range(0, 16));
    UniValue o = ManJson(sets, 16);
    UniValue stripes(UniValue::VARR);
    for (size_t i = 0; i < 9; ++i) {
        if (i == 4) continue;
        stripes.push_back(o["stripes"][i]);
    }
    o.pushKV("stripes", stripes);
    BOOST_CHECK(!ParseErasureManifest(o, m, err));
    BOOST_CHECK_EQUAL(err, "stripes");

    // With the entry present but empty, health names stripe 4 and hands the
    // healer the positions to fetch.
    sets[4].clear();
    const auto man = Man(16, 20, sets, 16);
    const auto h = EvaluateErasureHealth(man);
    BOOST_REQUIRE_EQUAL(h.stripes.size(), 9U);
    BOOST_CHECK_EQUAL(h.stripes[4].stripe_index, 4U);
    BOOST_CHECK_EQUAL(h.stripes[4].independent_shards, 0);
    BOOST_CHECK_EQUAL(h.stripes[4].deficit, 16);
    BOOST_CHECK(!h.stripes[4].reconstructable);
    BOOST_CHECK_EQUAL(h.deficit_stripes, 1U);
    BOOST_CHECK(!h.reconstructable);
    BOOST_CHECK_EQUAL(h.stripes[4].repair_fetch_positions.size(), 20U);

    const UniValue hj = ErasureHealthJson(h);
    BOOST_REQUIRE(hj["stripes"].isArray());
    const UniValue target = hj["stripes"][4]["repair_target"];
    BOOST_CHECK_MESSAGE(hj["stripes"][4].exists("repair_target"),
                        "R6-06: a deficit stripe must publish an addressable repair target");
    BOOST_CHECK_EQUAL(target["stripe_index"].getInt<int>(), 4);
    BOOST_CHECK_EQUAL(target["k_required"].getInt<int>(), 16);
    BOOST_CHECK_EQUAL(target["need"].getInt<int>(), 16);
    BOOST_REQUIRE(target["fetch_positions"].isArray());
    BOOST_CHECK_EQUAL(target["fetch_positions"].getValues().size(), 20U);
    // A healthy stripe carries no handle, so a healer cannot be pointed at one.
    BOOST_CHECK(!hj["stripes"][0].exists("repair_target"));

    // A stripe missing four positions asks for exactly the ones it lacks.
    auto partial = Man(16, 20, {Range(0, 15)}, 16);
    const auto hp = EvaluateErasureHealth(partial);
    BOOST_REQUIRE_EQUAL(hp.stripes.size(), 1U);
    BOOST_CHECK_EQUAL(hp.stripes[0].deficit, 1);
    BOOST_CHECK(hp.stripes[0].repair_fetch_positions == std::vector<int>({15, 16, 17, 18, 19}));
}

/**
 * R6-07. Failure domains exist, are counted per stripe, and gate a verdict of
 * their own. Sixteen shards on one host and sixteen shards on sixteen hosts are
 * no longer the same manifest and no longer the same health record.
 */
BOOST_AUTO_TEST_CASE(r6_b_failure_domains_gate_preservation)
{
    using namespace modelnet;
    std::string err;

    std::vector<std::string> sixteen_hosts;
    for (int i = 0; i < 16; ++i) sixteen_hosts.push_back("host-" + std::to_string(i));
    const std::vector<std::string> one_host(16, "host-0");

    UniValue spread = ManJson({Range(0, 16)}, 16);
    SetFailureDomains(spread, {sixteen_hosts});
    SetRequiredExtensions(spread, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    ErasureManifest sm;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(spread, sm, err), err);
    BOOST_REQUIRE_EQUAL(sm.stripes.size(), 1U);
    BOOST_CHECK_EQUAL(sm.stripes[0].failure_domains.size(), 16U);

    UniValue correlated = ManJson({Range(0, 16)}, 16);
    SetFailureDomains(correlated, {one_host});
    SetRequiredExtensions(correlated, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    ErasureManifest cm;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(correlated, cm, err), err);

    // The two manifests are no longer the same object.
    BOOST_CHECK_MESSAGE(ErasureManifestJson(sm).write() != ErasureManifestJson(cm).write(),
                        "R6-07: correlated and independent placement must not serialise identically");

    const auto hs = EvaluateErasureHealth(sm);
    const auto hc = EvaluateErasureHealth(cm);
    BOOST_REQUIRE_EQUAL(hs.stripes.size(), 1U);
    BOOST_REQUIRE_EQUAL(hc.stripes.size(), 1U);
    // n - k + 1 == 5: the 16/20 profile advertises a margin of four losses.
    BOOST_CHECK_EQUAL(hs.required_failure_domains, 5);
    BOOST_CHECK_EQUAL(hs.stripes[0].distinct_failure_domains, 16);
    BOOST_CHECK_EQUAL(hc.stripes[0].distinct_failure_domains, 1);

    // Arithmetic sufficiency is identical. Durability is not.
    BOOST_CHECK(hs.stripes[0].reconstructable);
    BOOST_CHECK(hc.stripes[0].reconstructable);
    BOOST_CHECK_MESSAGE(hs.stripes[0].preservation_reconstructable,
                        "R6-07: sixteen independent domains meet the declared tolerance");
    BOOST_CHECK_MESSAGE(!hc.stripes[0].preservation_reconstructable,
                        "R6-07: k met inside a single failure domain is arithmetic, not preservation");
    BOOST_CHECK(hs.preservation_reconstructable);
    BOOST_CHECK(!hc.preservation_reconstructable);
    BOOST_CHECK(ErasureManifestPreservationReconstructable(sm));
    BOOST_CHECK(!ErasureManifestPreservationReconstructable(cm));
    // The two gates are reported independently, so neither can mask the other.
    BOOST_CHECK(ErasureManifestReconstructable(cm));

    // Undeclared placement is never read as independent.
    UniValue silent = ManJson({Range(0, 16)}, 16);
    ErasureManifest qm;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(silent, qm, err), err);
    const auto hq = EvaluateErasureHealth(qm);
    BOOST_CHECK(!hq.stripes[0].failure_domains_declared);
    BOOST_CHECK_EQUAL(hq.stripes[0].distinct_failure_domains, 0);
    BOOST_CHECK(hq.stripes[0].reconstructable);
    BOOST_CHECK_MESSAGE(!hq.stripes[0].preservation_reconstructable,
                        "R6-07: a manifest that declares no domains has not earned a durability claim");

    // Repeating one position cannot manufacture a domain: the count is taken
    // over distinct stored positions.
    UniValue repeated = ManJsonRaw(kK, kN, kShardBytes, {std::vector<int>(16, 3)}, 16,
                                   ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                   HonestSize(kK, kShardBytes, 1, 16));
    SetFailureDomains(repeated, {sixteen_hosts});
    SetRequiredExtensions(repeated, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    ErasureManifest rm;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(repeated, rm, err), err);
    const auto hr = EvaluateErasureHealth(rm);
    BOOST_CHECK_EQUAL(hr.stripes[0].independent_shards, 1);
    BOOST_CHECK_MESSAGE(hr.stripes[0].distinct_failure_domains == 1,
                        "R6-07: sixteen labels on one repeated position is one domain, not sixteen; "
                        "got " << hr.stripes[0].distinct_failure_domains);
    BOOST_CHECK(!hr.stripes[0].reconstructable);

    // One label per stored position, or the count is not a count of origins.
    UniValue ragged = ManJson({Range(0, 16)}, 16);
    SetFailureDomains(ragged, {{"host-0", "host-1", "host-2"}});
    SetRequiredExtensions(ragged, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(ragged, qm, err),
                        "R6-07: three labels for sixteen positions must be refused");
    BOOST_CHECK_EQUAL(err, "failure_domains");
}

/**
 * R6-09. The profile name is allowlisted and the field polynomial is checked
 * against the one field GfMul implements, so a codec the node cannot run is no
 * longer admitted and decoded with the wrong parameters.
 */
BOOST_AUTO_TEST_CASE(r6_b_codec_mismatch_is_refused)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    // A different GF(256) polynomial under the reserved name.
    UniValue other_field = ManJsonRaw(kK, kN, kShardBytes, {Range(0, 16)}, 16,
                                      ERASURE_PROFILE_CAUCHY_16_20_V1, "0x187",
                                      HonestSize(kK, kShardBytes, 1, 16));
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(other_field, m, err),
                        "R6-09: field_polynomial must be validated against the implemented field");
    BOOST_CHECK_EQUAL(err, "field_polynomial");

    // An unknown profile name carrying arbitrary dimensions.
    UniValue unknown = ManJsonRaw(16, 20, 8, {Range(0, 16)}, 16, "not-a-btx-profile",
                                  ERASURE_FIELD_POLYNOMIAL, HonestSize(16, 8, 1, 16));
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(unknown, m, err),
                        "R6-09: profile must be checked against an allowlist");
    BOOST_CHECK_EQUAL(err, "profile");

    // The NONSHIPPING 64/80 geometry, previously admitted under a free-form name.
    UniValue big = ManJsonRaw(64, 80, kShardBytes, {Range(0, 64)}, 64, "BTX-EC-Cauchy-64-80-v1",
                              ERASURE_FIELD_POLYNOMIAL, HonestSize(64, kShardBytes, 1, 64));
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(big, m, err),
                        "R6-09: getevaluatedtransport reports erasure_64_80 NONSHIPPING, so a 64/80 "
                        "manifest must not parse and be evaluated as reconstructable");
    BOOST_CHECK_EQUAL(err, "profile");

    // The reserved profile still pins its own dimensions.
    UniValue wrong_bytes = ManJsonRaw(kK, kN, 8, {Range(0, 16)}, 16,
                                      ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                                      HonestSize(kK, 8, 1, 16));
    BOOST_CHECK(!ParseErasureManifest(wrong_bytes, m, err));
    BOOST_CHECK_EQUAL(err, "profile dimensions");

    // And the reserved profile round-trips through its own serialisation.
    UniValue ok_man = ManJson({Range(0, 16)}, 16);
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(ok_man, m, err), err);
    ErasureManifest m2;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(ErasureManifestJson(m), m2, err), err);
    BOOST_CHECK_EQUAL(m2.profile, m.profile);
    BOOST_CHECK_EQUAL(m2.field_polynomial, ERASURE_FIELD_POLYNOMIAL);
    BOOST_CHECK_EQUAL(m2.file_size_bytes, m.file_size_bytes);
    BOOST_CHECK_EQUAL(m2.stripe_count, m.stripe_count);
}

/**
 * R6-11. A must-understand list exists, so the failure-domain field cannot be
 * shipped past an older peer that would silently ignore it and answer
 * reconstructable on a manifest a newer peer rejects.
 */
BOOST_AUTO_TEST_CASE(r6_b_required_extensions_are_must_understand)
{
    using namespace modelnet;
    ErasureManifest m;
    std::string err;

    UniValue unknown_ext = ManJson({Range(0, 16)}, 16);
    SetRequiredExtensions(unknown_ext, {"r6-future-security-field-v1"});
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(unknown_ext, m, err),
                        "R6-11: an unrecognised required extension must be a hard parse failure");
    BOOST_CHECK_EQUAL(err, "required_extensions");

    UniValue dupe_ext = ManJson({Range(0, 16)}, 16);
    SetRequiredExtensions(dupe_ext, {ERASURE_EXT_FAILURE_DOMAIN_V1, ERASURE_EXT_FAILURE_DOMAIN_V1});
    BOOST_CHECK(!ParseErasureManifest(dupe_ext, m, err));
    BOOST_CHECK_EQUAL(err, "required_extensions");

    // Domains without the extension listed would be a silent downgrade.
    std::vector<std::string> hosts;
    for (int i = 0; i < 16; ++i) hosts.push_back("host-" + std::to_string(i));
    UniValue silent_domains = ManJson({Range(0, 16)}, 16);
    SetFailureDomains(silent_domains, {hosts});
    BOOST_CHECK_MESSAGE(!ParseErasureManifest(silent_domains, m, err),
                        "R6-11: declaring failure domains requires listing the extension that an old "
                        "peer must refuse");
    BOOST_CHECK_EQUAL(err, "required_extensions");

    // Listed, it parses and the list survives the round trip.
    UniValue declared = ManJson({Range(0, 16)}, 16);
    SetFailureDomains(declared, {hosts});
    SetRequiredExtensions(declared, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(declared, m, err), err);
    BOOST_REQUIRE_EQUAL(m.required_extensions.size(), 1U);
    BOOST_CHECK_EQUAL(m.required_extensions[0], ERASURE_EXT_FAILURE_DOMAIN_V1);
    ErasureManifest m2;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(ErasureManifestJson(m), m2, err), err);
    BOOST_CHECK(m2.required_extensions == m.required_extensions);
    BOOST_CHECK_EQUAL(m2.stripes.at(0).failure_domains.size(), 16U);
}

/**
 * R6-08. An interrupted repair no longer poisons its destination for good. The
 * write goes to a temp file, is fsynced, and is renamed into place, so a restart
 * completes instead of failing forever on a truncated prefix.
 */
BOOST_AUTO_TEST_CASE(r6_b_repair_restart_completes)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "r6-restart";
    fs::create_directories(tmp);

    const auto data = DataShards(2, 4096);
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards(data, 4, coded, err));
    auto man = Man(2, 4, {{0, 2}, {1, 3}}, 2);
    man.shard_bytes = 4096;
    SetHonestGeometry(man);
    WriteBytes(tmp / "s0.bin", coded[0]);
    WriteBytes(tmp / "s2.bin", coded[2]);
    const std::vector<std::string> paths{fs::PathToString(tmp / "s0.bin"), fs::PathToString(tmp / "s2.bin")};

    std::vector<unsigned char> want = data[0];
    want.insert(want.end(), data[1].begin(), data[1].end());

    // Simulate a crash partway through a previous repair: the destination
    // exists and holds a truncated prefix of the correct output.
    const fs::path dest = tmp / "repaired.bin";
    WriteBytes(dest, std::vector<unsigned char>(data[0].begin(), data[0].begin() + 100));

    BOOST_CHECK_MESSAGE(RepairStripeFromFiles(man, paths, {0, 2}, fs::PathToString(dest), err, 0),
                        "R6-08: a restart after an interrupted repair must complete; it failed with \"" +
                            err + "\"");
    const auto got = ReadBytes(dest);
    BOOST_CHECK_MESSAGE(got.size() == want.size(),
                        "R6-08: the poisoned 100-byte prefix must not survive as a completed repair; "
                        "destination is " << got.size() << " bytes");
    BOOST_CHECK(got == want);
    BOOST_CHECK_EQUAL(Sha384Hex(got), Sha384Hex(want));

    // A fresh destination works too, and leaves no temp file behind.
    const fs::path fresh = tmp / "repaired-2.bin";
    BOOST_REQUIRE_MESSAGE(RepairStripeFromFiles(man, paths, {0, 2}, fs::PathToString(fresh), err, 0), err);
    BOOST_CHECK(ReadBytes(fresh) == want);
    BOOST_CHECK(!fs::exists(fs::PathFromString(fs::PathToString(fresh) + ".tmp")));
}

/**
 * R6-10. A shard read is bounded by and required to equal man.shard_bytes, so a
 * truncated set no longer decodes to garbage and an oversized file is not
 * slurped whole into RAM.
 */
BOOST_AUTO_TEST_CASE(r6_b_shard_reads_are_bounded_by_shard_bytes)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "r6-bounded";
    fs::create_directories(tmp);

    // Every shard file is 8 bytes while the manifest declares 4096. The files
    // agree with each other, so the codec's own equal-length check is happy.
    std::vector<std::vector<unsigned char>> coded;
    std::string err;
    BOOST_REQUIRE(EncodeShards({{1, 2, 3, 4, 5, 6, 7, 8}, {8, 7, 6, 5, 4, 3, 2, 1}}, 4, coded, err));
    WriteBytes(tmp / "t0.bin", coded[0]);
    WriteBytes(tmp / "t2.bin", coded[2]);

    auto man = Man(2, 4, {{0, 2}, {1, 3}}, 2);
    man.shard_bytes = 4096;
    const std::vector<std::string> paths{fs::PathToString(tmp / "t0.bin"), fs::PathToString(tmp / "t2.bin")};
    const fs::path out = tmp / "out.bin";
    BOOST_CHECK_MESSAGE(!RepairStripeFromFiles(man, paths, {0, 2}, fs::PathToString(out), err, 0),
                        "R6-10: a shard file that is not exactly man.shard_bytes must be refused");
    BOOST_CHECK(!fs::exists(out));

    // An oversized file is refused on the same rule, so the peak read is
    // O(k * shard_bytes) rather than O(k * largest file).
    WriteBytes(tmp / "big0.bin", std::vector<unsigned char>(4097, 0x5a));
    WriteBytes(tmp / "big2.bin", std::vector<unsigned char>(4097, 0x5b));
    const std::vector<std::string> big{fs::PathToString(tmp / "big0.bin"), fs::PathToString(tmp / "big2.bin")};
    BOOST_CHECK_MESSAGE(!RepairStripeFromFiles(man, big, {0, 2}, fs::PathToString(tmp / "big.bin"), err, 0),
                        "R6-10: an oversized shard file must be refused, not read whole");

    // The executor bound is the module's own, not the caller's request size.
    BOOST_REQUIRE_EQUAL(IO_EXECUTOR_MAX_OUTSTANDING, 8U);
    std::vector<std::string> many;
    for (int i = 0; i < 64; ++i) {
        many.push_back(fs::PathToString(tmp / fs::PathFromString("absent-" + std::to_string(i) + ".bin")));
    }
    std::string berr;
    BOOST_CHECK(!RepairStripeFromFiles(man, many, std::vector<int>(64, 0),
                                       fs::PathToString(tmp / "out2.bin"), berr, 0));
    BOOST_CHECK(!fs::exists(tmp / "out2.bin"));
    BOOST_CHECK_MESSAGE(berr == "distinct k positions required",
                        "R6-10: arity must be validated before any I/O; got \"" + berr + "\"");
}

// ---------------------------------------------------------------------------
// Part C. The SPEC 14 health surface itself.
// ---------------------------------------------------------------------------

/**
 * SPEC 14 requires four fields per stripe: k_required, independent_shards,
 * distinct_failure_domains and reconstructable. independent_shards must count
 * stored shards only: locally supplyable dummy zeros are by definition not
 * independent, so on an honestly short tail independent_shards stays below
 * k_required while the stripe is still reconstructable, and the record has to
 * say both.
 */
BOOST_AUTO_TEST_CASE(r6_c_spec14_per_stripe_record)
{
    using namespace modelnet;
    std::string err;

    // A full interior stripe and an honestly short tail holding one real piece.
    std::vector<std::string> hosts;
    for (int i = 0; i < 16; ++i) hosts.push_back("host-" + std::to_string(i));
    UniValue json = ManJsonRaw(kK, kN, kShardBytes, {Range(0, 16), {0}}, 1,
                               ERASURE_PROFILE_CAUCHY_16_20_V1, ERASURE_FIELD_POLYNOMIAL,
                               HonestSize(kK, kShardBytes, 2, 1));
    SetFailureDomains(json, {hosts, {"host-0"}});
    SetRequiredExtensions(json, {ERASURE_EXT_FAILURE_DOMAIN_V1});
    ErasureManifest m;
    BOOST_REQUIRE_MESSAGE(ParseErasureManifest(json, m, err), err);

    const auto h = EvaluateErasureHealth(m);
    BOOST_REQUIRE_EQUAL(h.stripes.size(), 2U);
    BOOST_REQUIRE(h.reconstructable);

    const UniValue hj = ErasureHealthJson(h);
    BOOST_REQUIRE(hj["stripes"].isArray());
    const auto& arr = hj["stripes"].getValues();
    BOOST_REQUIRE_EQUAL(arr.size(), 2U);

    for (size_t i = 0; i < arr.size(); ++i) {
        for (const char* key : {"k_required", "independent_shards", "distinct_failure_domains", "reconstructable"}) {
            BOOST_CHECK_MESSAGE(arr[i].exists(key),
                                "SPEC 14: stripe " << i << " is missing per-stripe \"" << key << "\"");
        }
        BOOST_CHECK_EQUAL(arr[i]["k_required"].getInt<int>(), 16);
    }

    // Interior stripe: sixteen stored shards, all independent, sixteen domains.
    BOOST_CHECK_EQUAL(arr[0]["independent_shards"].getInt<int>(), 16);
    BOOST_CHECK_EQUAL(arr[0]["padding_credit"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(arr[0]["distinct_failure_domains"].getInt<int>(), 16);
    BOOST_CHECK(arr[0]["reconstructable"].get_bool());
    BOOST_CHECK(arr[0]["preservation_reconstructable"].get_bool());

    // Tail stripe: one independent shard and fifteen locally supplyable zeros.
    BOOST_CHECK_MESSAGE(arr[1]["independent_shards"].getInt<int>() == 1,
                        "SPEC 14: independent_shards must count stored shards only, never the "
                        "dummy-zero padding counted by distinct_effective");
    BOOST_CHECK_EQUAL(arr[1]["padding_credit"].getInt<int>(), 15);
    BOOST_CHECK_EQUAL(arr[1]["distinct_effective"].getInt<int>(), 16);
    BOOST_CHECK(arr[1]["reconstructable"].get_bool());
    // One real piece on one host: arithmetic yes, durability no.
    BOOST_CHECK_EQUAL(arr[1]["distinct_failure_domains"].getInt<int>(), 1);
    BOOST_CHECK(!arr[1]["preservation_reconstructable"].get_bool());
    BOOST_CHECK(!hj["preservation_reconstructable"].get_bool());
    BOOST_CHECK(hj["reconstructable"].get_bool());

    // The global counter stays labelled as not sufficiency, and it is the sum
    // of distinct stored positions: 16 + 1.
    BOOST_CHECK_EQUAL(hj["k"].getInt<int>(), 16);
    BOOST_CHECK_EQUAL(hj["n"].getInt<int>(), 20);
    BOOST_CHECK(hj["global_count_not_sufficiency"].get_bool());
    BOOST_CHECK_EQUAL(hj["global_position_count"].get_str(), "17");
    BOOST_CHECK_EQUAL(hj["deficit_stripes"].get_str(), "0");
    BOOST_CHECK_EQUAL(hj["required_failure_domains"].getInt<int>(), 5);
    BOOST_CHECK(hj["geometry_consistent"].get_bool());
    BOOST_CHECK_EQUAL(hj["padding_credited_stripe"].getInt<int>(), 1);

    // A deficit stripe carries the same quartet, so a reader never has to infer
    // the shape of the record from the verdict.
    const auto starved = ManIdx(16, 20, 2, {{0, {19}}, {1, Range(0, 16)}}, 16);
    const UniValue sj = ErasureHealthJson(EvaluateErasureHealth(starved));
    BOOST_REQUIRE(sj["stripes"].isArray());
    const UniValue s0 = sj["stripes"][0];
    for (const char* key : {"k_required", "independent_shards", "distinct_failure_domains", "reconstructable"}) {
        BOOST_CHECK_MESSAGE(s0.exists(key), "SPEC 14: deficit stripe is missing \"" << key << "\"");
    }
    BOOST_CHECK_EQUAL(s0["independent_shards"].getInt<int>(), 1);
    BOOST_CHECK(!s0["reconstructable"].get_bool());
    BOOST_CHECK(!sj["reconstructable"].get_bool());
    BOOST_CHECK(!sj["preservation_reconstructable"].get_bool());
}

/**
 * The SPEC 14 record is a schema, not a best effort. Every stripe carries the
 * whole key set whatever its verdict, so a reader never has to infer the shape
 * of a record from the answer it was hoping for, and the fields are arithmetically
 * consistent with each other. repair_target is the one deliberately conditional
 * key: its presence is exactly the deficit signal.
 */
BOOST_AUTO_TEST_CASE(r6_c_spec14_json_keys)
{
    using namespace modelnet;

    // One case per stripe state a reader has to survive.
    std::vector<std::pair<std::string, ErasureManifest>> cases;
    {
        auto healthy = Man(kK, kN, {Range(0, 16)}, 16);
        SetHonestGeometry(healthy);
        cases.emplace_back("healthy, placement undeclared", healthy);

        auto deficit = Man(kK, kN, {Range(0, 15)}, 16);
        SetHonestGeometry(deficit);
        cases.emplace_back("one shard short of k", deficit);

        auto hole = Man(kK, kN, {{}}, 16);
        SetHonestGeometry(hole);
        cases.emplace_back("stripe stores nothing", hole);

        auto tail = ManIdx(kK, kN, 2, {{0, Range(0, 16)}, {1, {0}}}, 1);
        SetHonestGeometry(tail);
        cases.emplace_back("proven short tail", tail);

        auto correlated = Man(kK, kN, {Range(0, 16)}, 16);
        SetHonestGeometry(correlated);
        correlated.stripes[0].failure_domains.assign(16, "host-a");
        cases.emplace_back("k met inside one failure domain", correlated);

        auto spread = Man(kK, kN, {Range(0, 16)}, 16);
        SetHonestGeometry(spread);
        for (int i = 0; i < 16; ++i) {
            spread.stripes[0].failure_domains.push_back("rack-" + std::to_string(i % 5));
        }
        cases.emplace_back("k met across n-k+1 domains", spread);
    }

    for (const auto& [label, man] : cases) {
        const auto h = EvaluateErasureHealth(man);
        const UniValue hj = ErasureHealthJson(h);

        // The manifest-level record.
        for (const char* key : {"reconstructable", "preservation_reconstructable", "geometry_consistent",
                                "stripe_count", "reconstructable_stripes", "deficit_stripes",
                                "preservation_stripes", "global_position_count",
                                "global_count_not_sufficiency", "k", "n", "required_failure_domains",
                                "padding_credited_stripe", "stripes"}) {
            BOOST_CHECK_MESSAGE(hj.exists(key), label << ": health is missing \"" << key << "\"");
        }
        BOOST_CHECK_MESSAGE(hj["k"].getInt<int>() == kK, label << ": k");
        BOOST_CHECK_MESSAGE(hj["n"].getInt<int>() == kN, label << ": n");
        // n - k + 1: the whole coding margin may be lost without losing a stripe.
        BOOST_CHECK_MESSAGE(hj["required_failure_domains"].getInt<int>() == kN - kK + 1,
                            label << ": required_failure_domains");
        // The global counter is published and is always labelled as not sufficiency.
        BOOST_CHECK_MESSAGE(hj["global_count_not_sufficiency"].get_bool(),
                            label << ": the global count must never lose its label");

        BOOST_REQUIRE(hj["stripes"].isArray());
        const auto& arr = hj["stripes"].getValues();
        BOOST_REQUIRE_EQUAL(arr.size(), h.stripes.size());

        for (size_t i = 0; i < arr.size(); ++i) {
            const UniValue& e = arr[i];
            const std::string where = label + ", stripe " + std::to_string(i);
            for (const char* key : {"stripe_index", "k_required", "independent_shards", "distinct_stored",
                                    "padding_credit", "distinct_effective", "distinct_failure_domains",
                                    "required_failure_domains", "failure_domains_declared", "deficit",
                                    "reconstructable", "preservation_reconstructable"}) {
                BOOST_CHECK_MESSAGE(e.exists(key), where << ": missing \"" << key << "\"");
            }

            const int k_required = e["k_required"].getInt<int>();
            const int independent = e["independent_shards"].getInt<int>();
            const int credit = e["padding_credit"].getInt<int>();
            const int effective = e["distinct_effective"].getInt<int>();
            const int deficit = e["deficit"].getInt<int>();
            const int domains = e["distinct_failure_domains"].getInt<int>();
            const bool declared = e["failure_domains_declared"].get_bool();
            const bool ok = e["reconstructable"].get_bool();
            const bool preserved = e["preservation_reconstructable"].get_bool();

            BOOST_CHECK_MESSAGE(k_required == kK, where << ": k_required must be k");
            // distinct_stored is the retained name for independent_shards, so a
            // reader of either name gets the same count.
            BOOST_CHECK_MESSAGE(e["distinct_stored"].getInt<int>() == independent,
                                where << ": distinct_stored and independent_shards must agree");
            // The verdict decomposes: only the first term is durable.
            BOOST_CHECK_MESSAGE(independent + credit == effective,
                                where << ": independent_shards + padding_credit must be distinct_effective");
            BOOST_CHECK_MESSAGE(deficit == std::max(0, k_required - effective),
                                where << ": deficit must be the shortfall against k");
            BOOST_CHECK_MESSAGE(ok == (deficit == 0), where << ": reconstructable must mean no deficit");
            // Durability is strictly stronger than arithmetic, and undeclared
            // placement is never read as tolerant.
            BOOST_CHECK_MESSAGE(!preserved || ok, where << ": preservation must imply reconstructable");
            BOOST_CHECK_MESSAGE(!preserved || declared,
                                where << ": preservation must require declared placement");
            BOOST_CHECK_MESSAGE(!preserved || domains >= e["required_failure_domains"].getInt<int>(),
                                where << ": preservation must require the domain tolerance");
            BOOST_CHECK_MESSAGE(declared || domains == 0,
                                where << ": undeclared placement must report zero domains, not a count");

            // The repair handle is present exactly when there is something to repair.
            BOOST_CHECK_MESSAGE(e.exists("repair_target") == !ok,
                                where << ": repair_target must be published iff the stripe has a deficit");
            if (!ok) {
                const UniValue target = e["repair_target"];
                BOOST_CHECK_MESSAGE(target["handle"].get_str() ==
                                        "stripe:" + std::to_string(e["stripe_index"].getInt<int>()),
                                    where << ": the handle must name the stripe");
                BOOST_CHECK_MESSAGE(target["need"].getInt<int>() == deficit, where << ": target need");
                BOOST_REQUIRE(target["fetch_positions"].isArray());
                // A healer is told enough positions to close the deficit, and
                // never a position the stripe already has.
                BOOST_CHECK_MESSAGE(
                    static_cast<int>(target["fetch_positions"].getValues().size()) >= deficit,
                    where << ": fetch_positions must be able to close the deficit");
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
