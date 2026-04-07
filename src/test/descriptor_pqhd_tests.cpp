// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <pq/pq_keyderivation.h>
#include <pqkey.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(descriptor_pqhd_tests, BasicTestingSetup)

static std::string MakeTestSeedHex()
{
    // Deterministic test seed
    std::array<unsigned char, 32> seed{};
    for (size_t i = 0; i < 32; i++) seed[i] = static_cast<unsigned char>(i + 1);
    return HexStr(seed);
}

BOOST_AUTO_TEST_CASE(parse_pqhd_basic)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_CHECK_MESSAGE(!descs.empty(), "Parse failed: " + error);
    BOOST_CHECK_EQUAL(descs.size(), 1u);
}

BOOST_AUTO_TEST_CASE(parse_pqhd_round_trip)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE(!descs.empty());

    // Public form should use fingerprint, not seed
    std::string pub_str = descs[0]->ToString();
    BOOST_CHECK(pub_str.find(seed_hex) == std::string::npos); // Seed must NOT appear in public form
    BOOST_CHECK(pub_str.find("pqhd(") != std::string::npos); // But pqhd must appear

    // Private form should include seed
    std::string priv_str;
    BOOST_CHECK(descs[0]->ToPrivateString(keys, priv_str));
    BOOST_CHECK(priv_str.find(seed_hex) != std::string::npos); // Seed appears in private form

    // Re-parse the private form
    FlatSigningProvider keys2;
    auto descs2 = Parse(priv_str, keys2, error, false);
    BOOST_CHECK_MESSAGE(!descs2.empty(), "Re-parse failed: " + error);
}

BOOST_AUTO_TEST_CASE(pqhd_deterministic_expansion)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE(!descs.empty());

    // Expand at position 0 twice — must produce identical scripts
    FlatSigningProvider out1, out2;
    std::vector<CScript> scripts1, scripts2;
    descs[0]->Expand(0, keys, scripts1, out1);
    descs[0]->Expand(0, keys, scripts2, out2);
    BOOST_REQUIRE(!scripts1.empty());
    BOOST_REQUIRE(!scripts2.empty());
    BOOST_CHECK(scripts1[0] == scripts2[0]);
}

BOOST_AUTO_TEST_CASE(pqhd_different_indices_different_keys)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE(!descs.empty());

    FlatSigningProvider out0, out1;
    std::vector<CScript> scripts0, scripts1;
    descs[0]->Expand(0, keys, scripts0, out0);
    descs[0]->Expand(1, keys, scripts1, out1);
    BOOST_REQUIRE(!scripts0.empty());
    BOOST_REQUIRE(!scripts1.empty());
    BOOST_CHECK(scripts0[0] != scripts1[0]); // Different indices must produce different outputs
}

BOOST_AUTO_TEST_CASE(pqhd_internal_vs_external)
{
    std::string seed_hex = MakeTestSeedHex();
    // External (change=0) vs Internal (change=1)
    std::string desc_ext = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";
    std::string desc_int = "mr(pqhd(" + seed_hex + "/0h/0h/1/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/1/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs_ext = Parse(desc_ext, keys, error, false);
    auto descs_int = Parse(desc_int, keys, error, false);
    BOOST_REQUIRE(!descs_ext.empty());
    BOOST_REQUIRE(!descs_int.empty());

    FlatSigningProvider out_ext, out_int;
    std::vector<CScript> scripts_ext, scripts_int;
    descs_ext[0]->Expand(0, keys, scripts_ext, out_ext);
    descs_int[0]->Expand(0, keys, scripts_int, out_int);
    BOOST_REQUIRE(!scripts_ext.empty());
    BOOST_REQUIRE(!scripts_int.empty());
    BOOST_CHECK(scripts_ext[0] != scripts_int[0]); // External and internal must differ
}

BOOST_AUTO_TEST_CASE(pqhd_signing_round_trip)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE(!descs.empty());

    // Expand at position 0 — should derive PQ keys
    FlatSigningProvider out;
    std::vector<CScript> scripts;
    descs[0]->Expand(0, keys, scripts, out);
    BOOST_REQUIRE(!scripts.empty());

    // ExpandPrivate should populate pq_keys
    descs[0]->ExpandPrivate(0, keys, out);
    BOOST_CHECK(!out.pq_keys.empty());
}

BOOST_AUTO_TEST_CASE(pqhd_cache_round_trip)
{
    std::string seed_hex = MakeTestSeedHex();
    std::string desc_str = "mr(pqhd(" + seed_hex + "/0h/0h/0/*),pk_slh(pqhd(" + seed_hex + "/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_REQUIRE(!descs.empty());

    // Derive with write_cache
    FlatSigningProvider out1;
    std::vector<CScript> scripts1;
    DescriptorCache write_cache;
    descs[0]->Expand(0, keys, scripts1, out1, &write_cache);
    BOOST_REQUIRE(!scripts1.empty());

    // Derive from read_cache
    FlatSigningProvider out2;
    std::vector<CScript> scripts2;
    descs[0]->ExpandFromCache(0, write_cache, scripts2, out2);
    BOOST_REQUIRE(!scripts2.empty());

    // Must produce identical scripts
    BOOST_CHECK(scripts1[0] == scripts2[0]);
}

BOOST_AUTO_TEST_CASE(pqhd_invalid_inputs)
{
    FlatSigningProvider keys;
    std::string error;

    // Bad hex (too short)
    auto d1 = Parse("mr(pqhd(0102/0h/0h/0/*))", keys, error, false);
    BOOST_CHECK(d1.empty());

    // Missing hardened on coin_type
    std::string seed_hex = MakeTestSeedHex();
    auto d2 = Parse("mr(pqhd(" + seed_hex + "/0/0h/0/*))", keys, error, false);
    BOOST_CHECK(d2.empty());

    // Missing hardened on account
    auto d3 = Parse("mr(pqhd(" + seed_hex + "/0h/0/0/*))", keys, error, false);
    BOOST_CHECK(d3.empty());

    // Missing wildcard
    auto d4 = Parse("mr(pqhd(" + seed_hex + "/0h/0h/0/5))", keys, error, false);
    BOOST_CHECK(d4.empty());

    // Wrong number of path components
    auto d5 = Parse("mr(pqhd(" + seed_hex + "/0h/0h/*))", keys, error, false);
    BOOST_CHECK(d5.empty());
}

BOOST_AUTO_TEST_CASE(pqhd_fingerprint_form_parses)
{
    // The public/DB-persisted form uses fingerprint instead of seed
    std::string desc_str = "mr(pqhd(01020304/0h/0h/0/*),pk_slh(pqhd(01020304/0h/0h/0/*)))";

    FlatSigningProvider keys;
    std::string error;
    auto descs = Parse(desc_str, keys, error, false);
    BOOST_CHECK_MESSAGE(!descs.empty(), "Fingerprint form parse failed: " + error);
    BOOST_REQUIRE(!descs.empty());

    // Public round-trip must preserve the supplied fingerprint so descriptor IDs stay stable.
    const std::string pub_str = descs[0]->ToString();
    BOOST_CHECK(pub_str.find("01020304") != std::string::npos);
    BOOST_CHECK(pub_str.find("00000000") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
