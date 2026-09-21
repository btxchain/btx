// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// NETWORK-02 Lane G+H extras. Coordinator: add this file to test_btx and
// erasure_manifest.cpp / package_export.cpp to bitcoin_modelnet. Do not treat
// packaged acceptance-matrix.csv as native PASS.

#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <modelnet/package_export.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_network02_gh_tests, BasicTestingSetup)

namespace {

std::string Hex96(char c)
{
    return std::string(96, c);
}

UniValue BaseErasureJson()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", 1);
    o.pushKV("profile", modelnet::ERASURE_PROFILE_CAUCHY_16_20_V1);
    o.pushKV("canonical_artifact_id", Hex96('f'));
    o.pushKV("canonical_manifest_id", Hex96('a'));
    o.pushKV("file_index", 0);
    o.pushKV("file_size_bytes", "429496729600");
    o.pushKV("data_shards", 16);
    o.pushKV("total_shards", 20);
    o.pushKV("shard_bytes", 4194304);
    o.pushKV("field_polynomial", "0x11d");
    o.pushKV("stripe_count", "2");
    o.pushKV("final_real_piece_count", 16);
    o.pushKV("shard_index_root", Hex96('b'));
    return o;
}

UniValue PosArray(int begin, int end)
{
    UniValue a(UniValue::VARR);
    for (int i = begin; i < end; ++i) a.push_back(i);
    return a;
}

UniValue Stripe(int index, int begin, int end)
{
    UniValue s(UniValue::VOBJ);
    s.pushKV("index", index);
    s.pushKV("positions", PosArray(begin, end));
    return s;
}

} // namespace

BOOST_AUTO_TEST_CASE(erasure_summary_json_not_reconstructable)
{
    UniValue raw = BaseErasureJson();
    raw.pushKV("stripe_count", "6400");
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseErasureManifest(raw, m, err), err);
    BOOST_CHECK_EQUAL(m.stripe_count, 6400);
    BOOST_CHECK(m.stripes.empty());
    BOOST_CHECK(!modelnet::ErasureManifestReconstructable(m));
    const auto health = modelnet::EvaluateErasureHealth(m);
    BOOST_CHECK(!health.reconstructable);
    BOOST_CHECK_EQUAL(health.global_position_count, 0);
    BOOST_CHECK_EQUAL(health.deficit_stripes, 6400);
}

BOOST_AUTO_TEST_CASE(erasure_global_shard_count_is_not_sufficiency)
{
    UniValue raw = BaseErasureJson();
    UniValue stripes(UniValue::VARR);
    // Stripe 0 has all 20 positions; stripe 1 has 15. Global 35 looks "enough"; it is not.
    stripes.push_back(Stripe(0, 0, 20));
    stripes.push_back(Stripe(1, 0, 15));
    raw.pushKV("stripes", stripes);
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseErasureManifest(raw, m, err), err);
    BOOST_REQUIRE_EQUAL(m.stripes.size(), 2);
    BOOST_CHECK(modelnet::StripeReconstructable(modelnet::ErasureEffectivePositionSets(m), m.data_shards) ==
                modelnet::ErasureManifestReconstructable(m));
    BOOST_CHECK(!modelnet::ErasureManifestReconstructable(m));
    const auto health = modelnet::EvaluateErasureHealth(m);
    BOOST_CHECK_EQUAL(health.global_position_count, 35);
    BOOST_CHECK(!health.reconstructable);
    BOOST_CHECK_EQUAL(health.reconstructable_stripes, 1);
    BOOST_CHECK_EQUAL(health.deficit_stripes, 1);
    BOOST_CHECK(health.stripes[0].reconstructable);
    BOOST_CHECK(!health.stripes[1].reconstructable);
}

BOOST_AUTO_TEST_CASE(erasure_per_stripe_k_distinct_is_reconstructable)
{
    UniValue raw = BaseErasureJson();
    UniValue stripes(UniValue::VARR);
    stripes.push_back(Stripe(0, 0, 16));
    stripes.push_back(Stripe(1, 4, 20));
    raw.pushKV("stripes", stripes);
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseErasureManifest(raw, m, err), err);
    BOOST_CHECK(modelnet::StripeReconstructable(modelnet::ErasureEffectivePositionSets(m), 16));
    BOOST_CHECK(modelnet::ErasureManifestReconstructable(m));
    const UniValue dumped = modelnet::ErasureManifestJson(m);
    BOOST_CHECK(!dumped.exists("credential_ref"));
    BOOST_CHECK(!dumped.exists("private_key"));
    BOOST_CHECK(!dumped.exists("seed"));
}

BOOST_AUTO_TEST_CASE(erasure_duplicate_positions_do_not_count)
{
    UniValue raw = BaseErasureJson();
    raw.pushKV("stripe_count", "1");
    UniValue pos(UniValue::VARR);
    for (int i = 0; i < 16; ++i) pos.push_back(0);
    UniValue s(UniValue::VOBJ);
    s.pushKV("index", 0);
    s.pushKV("positions", pos);
    UniValue stripes(UniValue::VARR);
    stripes.push_back(s);
    raw.pushKV("stripes", stripes);
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseErasureManifest(raw, m, err), err);
    BOOST_CHECK(!modelnet::StripeReconstructable(modelnet::ErasureStoredPositionSets(m), 16));
    BOOST_CHECK(!modelnet::ErasureManifestReconstructable(m));
}

BOOST_AUTO_TEST_CASE(erasure_tail_dummy_zeros_are_not_stored_replicas)
{
    UniValue raw = BaseErasureJson();
    raw.pushKV("stripe_count", "1");
    raw.pushKV("final_real_piece_count", 12);
    // 12 real data + 2 parity = 14 stored; dummy zeros 12..15 make effective >= 16.
    UniValue pos(UniValue::VARR);
    for (int i = 0; i < 12; ++i) pos.push_back(i);
    pos.push_back(16);
    pos.push_back(17);
    UniValue s(UniValue::VOBJ);
    s.pushKV("index", 0);
    s.pushKV("positions", pos);
    UniValue stripes(UniValue::VARR);
    stripes.push_back(s);
    raw.pushKV("stripes", stripes);
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::ParseErasureManifest(raw, m, err), err);
    BOOST_CHECK(!modelnet::StripeReconstructable(modelnet::ErasureStoredPositionSets(m), 16));
    BOOST_CHECK(modelnet::StripeReconstructable(modelnet::ErasureEffectivePositionSets(m), 16));
    BOOST_CHECK(modelnet::ErasureManifestReconstructable(m));
    const auto health = modelnet::EvaluateErasureHealth(m);
    BOOST_CHECK_EQUAL(health.stripes[0].distinct_stored, 14);
    BOOST_CHECK_EQUAL(health.stripes[0].distinct_effective, 18);
    BOOST_CHECK(health.reconstructable);
}

BOOST_AUTO_TEST_CASE(erasure_json_refuses_secrets)
{
    UniValue raw = BaseErasureJson();
    raw.pushKV("credential_ref", "env:BTX_CLOUD_CREDENTIAL");
    modelnet::ErasureManifest m;
    std::string err;
    BOOST_CHECK(!modelnet::ParseErasureManifest(raw, m, err));
    BOOST_CHECK(err.find("secret-bearing") != std::string::npos);

    UniValue raw2 = BaseErasureJson();
    raw2.pushKV("private_key", "hex");
    BOOST_CHECK(!modelnet::ParseErasureManifest(raw2, m, err));
    UniValue raw3 = BaseErasureJson();
    raw3.pushKV("seed", "operator-seed");
    BOOST_CHECK(!modelnet::ParseErasureManifest(raw3, m, err));
}

BOOST_AUTO_TEST_CASE(package_magnet_analog_vs_binary_bundle)
{
    UniValue fields(UniValue::VOBJ);
    fields.pushKV("uri", "btx://model/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    fields.pushKV("kind", "MODEL");
    fields.pushKV("copy_text", "btx://model/aaa family=demo");
    UniValue magnet;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeMagnetAnalog(fields, magnet, err), err);
    BOOST_CHECK(modelnet::IsMagnetAnalogObject(magnet));
    BOOST_CHECK_EQUAL(magnet["schema_version"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(magnet["uri"].get_str().find("dn="), std::string::npos);

    std::vector<unsigned char> bundle;
    UniValue core(UniValue::VOBJ);
    core.pushKV("schema_version", 1);
    core.pushKV("kind", "btxbundle");
    BOOST_REQUIRE_MESSAGE(modelnet::EncodePublicBtxBundle(core, bundle, err), err);
    BOOST_REQUIRE(modelnet::LooksLikeBtxBundle(bundle));
    BOOST_CHECK_EQUAL(bundle[0], 'B');
    const std::string magnet_json = magnet.write();
    BOOST_CHECK(!modelnet::LooksLikeBtxBundle(Span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(magnet_json.data()), magnet_json.size()}));

    UniValue decoded;
    BOOST_REQUIRE(modelnet::DecodePublicBtxBundle(Span<const unsigned char>{bundle.data(), bundle.size()}, decoded, err));
    BOOST_CHECK_EQUAL(decoded["kind"].get_str(), "btxbundle");
}

BOOST_AUTO_TEST_CASE(package_export_refuses_secret_keys)
{
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("credential_ref"));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("private_key"));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("seed"));
    BOOST_CHECK(!modelnet::PublicExportKeyForbidden("seeded"));
    BOOST_CHECK(!modelnet::PublicExportKeyForbidden("uri"));

    UniValue bad(UniValue::VOBJ);
    bad.pushKV("uri", "btx://model/x");
    bad.pushKV("credential_ref", "env:BTX_CLOUD_CREDENTIAL");
    UniValue magnet;
    std::string err;
    BOOST_CHECK(!modelnet::EncodeMagnetAnalog(bad, magnet, err));
    BOOST_CHECK(err.find("secret-bearing") != std::string::npos);

    UniValue pk(UniValue::VOBJ);
    pk.pushKV("kind", "btxbundle");
    pk.pushKV("private_key", "00");
    std::vector<unsigned char> bytes;
    BOOST_CHECK(!modelnet::EncodePublicBtxBundle(pk, bytes, err));

    UniValue sd(UniValue::VOBJ);
    sd.pushKV("kind", "btxbundle");
    sd.pushKV("seed", "s");
    BOOST_CHECK(!modelnet::EncodePublicBtxBundle(sd, bytes, err));
}

BOOST_AUTO_TEST_CASE(package_dn_query_stays_on_copy_text)
{
    UniValue fields(UniValue::VOBJ);
    fields.pushKV("uri", "btx://model/abc?dn=demo");
    fields.pushKV("copy_text", "btx://model/abc?dn=demo");
    UniValue magnet;
    std::string err;
    BOOST_CHECK(!modelnet::EncodeMagnetAnalog(fields, magnet, err));
    BOOST_CHECK_EQUAL(err, "dn= stays on copy_text only");

    fields.pushKV("uri", "btx://model/abc");
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeMagnetAnalog(fields, magnet, err), err);
    BOOST_CHECK(magnet["copy_text"].get_str().find("dn=") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
