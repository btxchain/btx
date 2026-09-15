// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Remaining V11 acceptance-matrix Boost cases. These are the matrix ids that had
// no attributed Boost case in modelnet_tests.cpp, modelnet_bridge_tests.cpp,
// modelnet_firstrun_tests.cpp, modelnet_funding_tests.cpp,
// modelnet_cuda_qual_tests.cpp, modelnet_planner_tests.cpp or
// modelnet_v11_negative_tests.cpp at the time this file was added.
//
// V11 id -> BOOST_AUTO_TEST_CASE (this file)
// V11-URI-01    v11_uri_01_all_nine_kinds_preserve_digest
// V11-URI-02    v11_uri_02_exact_length_contract
// V11-URI-03    v11_uri_03_bech32m_only
// V11-URI-04    v11_uri_04_single_symbol_mutations
// V11-URI-05    v11_uri_05_unknown_version_or_kind_rejected
// V11-URI-06    v11_uri_06_nonzero_residual_padding_rejected
// V11-URI-07    v11_uri_07_case_rules
// V11-URI-08    v11_uri_08_hostile_inputs_rejected
// V11-URI-09    v11_uri_09_paths_rejected
// V11-URI-10    v11_uri_10_explicit_local_forms
// V11-URI-11    v11_uri_11_authority_not_dns
// V11-URI-13    v11_uri_13_not_a_spending_or_payment_input
// V11-URI-15    v11_uri_15_typed_hash_domain
// V11-RESOLVE-01 v11_resolve_01_cpu_only_cache
// V11-RESOLVE-02 v11_resolve_02_local_cache_hit
// V11-RESOLVE-03 v11_resolve_03_independent_router_no_domain
// V11-RESOLVE-04 v11_resolve_04_router_removal_direct_transfer
// V11-RESOLVE-05 v11_resolve_05_exact_record_root
// V11-RESOLVE-06 v11_resolve_06_typed_identity_lookup
// V11-RESOLVE-10 v11_resolve_10_monetary_endpoints_hidden
// V11-FREE-01   v11_free_01_identity_only_no_wallet
// V11-FREE-05   v11_free_05_zero_price_no_balance
// V11-FREE-14   v11_free_14_exposure_and_fee_ceiling
// V11-FREE-15   v11_free_15_release_not_substituted
// V11-COMM-06   v11_comm_06_follow_does_not_raise_budget
// V11-COMM-07   v11_comm_07_no_onchain_membership
// V11-COMM-08   v11_comm_08_preservation_local_limits
// V11-COMM-10   v11_comm_10_third_party_no_credit
// V11-BRIDGE-01 v11_bridge_01_link_only_full_uri
// V11-BRIDGE-02 v11_bridge_02_no_https_fallback_disclosed
// V11-BRIDGE-03 v11_bridge_03_upstream_pq1
// V11-BRIDGE-04 v11_bridge_04_token_longer_than_dns_label
// V11-BRIDGE-05 v11_bridge_05_42_43_split_exact
// V11-BRIDGE-06 v11_bridge_06_certificate_depth
// V11-BRIDGE-07 v11_bridge_07_no_implicit_download
// V11-BRIDGE-08 v11_bridge_08_wallet_private_unreachable
// V11-BRIDGE-09 v11_bridge_09_no_arbitrary_proxy
// V11-BRIDGE-11 v11_bridge_11_json_only_isolation
// V11-BRIDGE-12 v11_bridge_12_browser_not_native_pq
// V11-LOCAL-01   v11_local_01_open_uri_preview_only
// V11-LOCAL-02   v11_local_02_export_verified_path
// V11-LOCAL-03   v11_local_03_unsupported_no_remote_inference
// V11-LOCAL-04   v11_local_04_models_before_finance
// V11-LOCAL-05   v11_local_05_storage_consent
// V11-DOC-02    v11_doc_02_documented_vectors_identical
// V11-DOC-03    v11_doc_03_inference_removed
// V11-DOC-04    v11_doc_04_bridge_scoped_optional
//
// Matrix ids deliberately NOT asserted here (no native API / no implementation to
// assert against yet, so a "real assertion" would be fabricated):
// V11-URI-12  OS handler is the src/btx-open.cpp entry point, not a library call.
//   V11-URI-14  short display: src/test/modelnet_uri_resolve_tests.cpp uri_14_short_display_copy_is_full_canonical
//   V11-RESOLVE-07/08/09  no eight-router/four-query bound, 60s negative cache,
//                         or missing-bootstrap error API in the helper.
//   V11-BRIDGE-10  the bridge never emits bytes; range->chunk mapping lives in the
//                  native piece wire, which is not the browser edge.
//   V11-COMM-09    no rescue-work jitter API.
//   V11-DOC-01     needs the external baseline bytes, outside this repository.
//   V11-MIG-01..05 no migration/versioning API present.
//   V11-ISO-01..05 integration/isolation gates, not unit-testable in this binary.

#include <modelnet/catalog.h>
#include <modelnet/cores.h>
#include <modelnet/firstrun.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/qualification.h>
#include <modelnet/records.h>
#include <modelnet/resource_uri.h>
#include <modelnet/router.h>
#include <modelnet/swarm.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>

#include <bech32.h>
#include <crypto/common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ds_remaining_tests, BasicTestingSetup)

namespace {

constexpr const char* kBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

modelnet::Digest48 Dg(unsigned char seed)
{
    modelnet::Digest48 d;
    for (size_t i = 0; i < d.data.size(); ++i) {
        d.data[i] = static_cast<unsigned char>(seed + i);
    }
    return d;
}

std::string ToUpperCopy(std::string s)
{
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

UniValue LoadVectors()
{
    std::ifstream in{MODELNET_V11_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    return v;
}

modelnet::SignedFreeGrant IssueGrant(std::vector<unsigned char>& pk,
                                     const modelnet::Digest48& model,
                                     const modelnet::Digest48& artifact,
                                     const modelnet::Digest48& buyer,
                                     std::string& err)
{
    std::vector<unsigned char> sk;
    BOOST_REQUIRE_MESSAGE(modelnet::GenerateMlDsa44(pk, sk, err), err);
    modelnet::FreeGrantParams p;
    p.buyer_id = buyer;
    p.model_id = model;
    p.artifact_id = artifact;
    p.file_index = 0;
    p.first_piece = 0;
    p.piece_count = 2;
    p.maximum_bytes = 128;
    p.queue_class = 0;
    modelnet::SignedFreeGrant g;
    BOOST_REQUIRE_MESSAGE(modelnet::IssueFreeGrant(p, sk, pk, g, err), err);
    return g;
}

} // namespace

// ---------------------------------------------------------------------------
// Section 3 - compact BTX resource URI
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_uri_01_all_nine_kinds_preserve_digest)
{
    const UniValue vec = LoadVectors();
    const UniValue& rows = vec["resource_vectors"];
    BOOST_REQUIRE(rows.isArray());
    BOOST_REQUIRE_EQUAL(rows.size(), 9u);

    int seen_kinds = 0;
    for (unsigned int i = 0; i < rows.size(); ++i) {
        const UniValue& row = rows[i];
        modelnet::Digest48 digest;
        std::string err;
        BOOST_REQUIRE(modelnet::Digest48::FromHex(row["digest"].get_str(), digest, err));
        const int kind_int = row["kind"].getInt<int>();
        const auto kind = static_cast<modelnet::ResourceKind>(kind_int);

        std::string uri;
        BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(kind, digest, uri, err), err);
        BOOST_CHECK_EQUAL(uri, row["uri"].get_str());
        BOOST_CHECK_EQUAL(modelnet::ResourceKindName(kind), row["name"].get_str());

        // The exact 48-byte digest survives the round trip unchanged.
        modelnet::Resource out;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(uri, out, err), err);
        BOOST_CHECK(out.kind == kind);
        BOOST_CHECK(out.digest == digest);
        BOOST_CHECK_EQUAL(out.digest.Hex(), row["digest"].get_str());
        ++seen_kinds;
    }
    BOOST_CHECK_EQUAL(seen_kinds, 9);
}

BOOST_AUTO_TEST_CASE(v11_uri_02_exact_length_contract)
{
    const UniValue vec = LoadVectors();
    for (const auto& row : vec["resource_vectors"].getValues()) {
        const std::string token = row["token"].get_str();
        const std::string uri = row["uri"].get_str();
        const std::string internal = row["internal_bech32m"].get_str();

        BOOST_CHECK_EQUAL(token.size(), 85u);
        BOOST_CHECK_EQUAL(uri.size(), 91u);
        BOOST_CHECK_EQUAL(internal.size(), 89u);
        BOOST_CHECK_EQUAL(uri, "btx://" + token);
        BOOST_CHECK_EQUAL(internal, "btx1" + token);
        BOOST_CHECK_EQUAL(internal.substr(0, 4), "btx1");
        // No literal btx1 duplication inside the visible URI body.
        BOOST_CHECK(uri.find("btx1") == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(v11_uri_03_bech32m_only)
{
    const modelnet::Digest48 digest = Dg(0x40);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::RELEASE, digest, uri, err), err);
    const std::string token = uri.substr(6);

    // Bech32m (BIP350) is accepted.
    modelnet::Resource out;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(uri, out, err), err);
    BOOST_CHECK(out.digest == digest);

    // The same payload encoded with legacy Bech32 (BIP173) must be rejected.
    std::vector<unsigned char> values;
    values.push_back(modelnet::RESOURCE_VERSION);
    values.push_back(static_cast<unsigned char>(modelnet::ResourceKind::RELEASE));
    const bool converted = ConvertBits<8, 5, true>(
        [&](unsigned char c) { values.push_back(c); }, digest.data.begin(), digest.data.end());
    BOOST_REQUIRE(converted);
    const std::string legacy_full = bech32::Encode(bech32::Encoding::BECH32, "btx", values);
    BOOST_REQUIRE_EQUAL(legacy_full.substr(0, 4), "btx1");
    const std::string legacy_uri = "btx://" + legacy_full.substr(4);
    BOOST_CHECK_EQUAL(legacy_uri.size(), 91u);
    BOOST_CHECK(!modelnet::DecodeResource(legacy_uri, out, err));
    BOOST_CHECK(err.find("checksum") != std::string::npos);

    // Sanity: the bech32m token really decodes as BECH32M.
    const auto decoded = bech32::Decode("btx1" + token, bech32::CharLimit::BECH32);
    BOOST_CHECK(decoded.encoding == bech32::Encoding::BECH32M);
}

BOOST_AUTO_TEST_CASE(v11_uri_04_single_symbol_mutations)
{
    const modelnet::Digest48 digest = Dg(0x71);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, digest, uri, err), err);

    int checked = 0;
    int rejected = 0;
    for (size_t pos = 6; pos < uri.size(); ++pos) {
        for (const char* c = kBech32Charset; *c != '\0'; ++c) {
            if (uri[pos] == *c) continue;
            std::string mutated = uri;
            mutated[pos] = *c;
            modelnet::Resource out;
            std::string merr;
            ++checked;
            if (!modelnet::DecodeResource(mutated, out, merr)) {
                ++rejected;
            } else {
                // An accepted mutation would have to carry the same digest; the
                // checksum already makes that impossible for a single symbol.
                BOOST_CHECK(out.digest == digest);
            }
        }
    }
    BOOST_CHECK_GT(checked, 2000);
    BOOST_CHECK_EQUAL(rejected, checked);
}

BOOST_AUTO_TEST_CASE(v11_uri_05_unknown_version_or_kind_rejected)
{
    const modelnet::Digest48 digest = Dg(0x55);
    std::string err;

    std::string token;
    BOOST_REQUIRE_MESSAGE(modelnet::RawToken(2, 0, digest, token, err), err);
    BOOST_REQUIRE_EQUAL(token.size(), 85u);
    modelnet::Resource out;
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + token, out, err));
    BOOST_CHECK(err.find("version") != std::string::npos);

    token.clear();
    err.clear();
    // Kind 15 is outside the current registry (0–8 original + 9–14 bounty types).
    BOOST_REQUIRE_MESSAGE(modelnet::RawToken(modelnet::RESOURCE_VERSION, 15, digest, token, err), err);
    modelnet::Resource out2;
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + token, out2, err));
    BOOST_CHECK(err.find("type") != std::string::npos);

    // Unknown version never reaches a lookup: the decoder has no registry beyond
    // EncodeResource/DecodeResource, so rejection is the observable behavior.
    BOOST_CHECK(modelnet::EncodeResource(static_cast<modelnet::ResourceKind>(99), digest, token, err) == false);
}

BOOST_AUTO_TEST_CASE(v11_uri_06_nonzero_residual_padding_rejected)
{
    const modelnet::Digest48 digest = Dg(0x33);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::COLLECTION, digest, uri, err), err);
    const std::string token = uri.substr(6);

    const auto decoded = bech32::Decode("btx1" + token, bech32::CharLimit::BECH32);
    BOOST_REQUIRE(decoded.encoding == bech32::Encoding::BECH32M);
    BOOST_REQUIRE_EQUAL(decoded.data.size(), 79u);
    // The 48-byte payload leaves a single zero padding bit in the last symbol.
    BOOST_CHECK_EQUAL(decoded.data.back() & 1, 0);

    std::vector<unsigned char> tampered = decoded.data;
    tampered.back() |= 1;
    const std::string full = bech32::Encode(bech32::Encoding::BECH32M, "btx", tampered);
    BOOST_REQUIRE_EQUAL(full.size(), 89u);

    // Checksum is valid; the nonzero residual bit must still be rejected.
    modelnet::Resource out;
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + full.substr(4), out, err));
}

BOOST_AUTO_TEST_CASE(v11_uri_07_case_rules)
{
    const modelnet::Digest48 digest = Dg(0x21);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::ALIAS, digest, uri, err), err);
    const std::string token = uri.substr(6);

    // Uniform upper case normalizes to the canonical lower-case URI.
    modelnet::Resource out;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource("btx://" + ToUpperCopy(token), out, err), err);
    BOOST_CHECK_EQUAL(out.Uri(), uri);
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(ToUpperCopy(token), out, err), err);
    BOOST_CHECK_EQUAL(out.Uri(), uri);

    // Scheme case is independently insensitive.
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource("BTX://" + token, out, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource("BtX://" + token, out, err), err);

    // Mixed token case is rejected.
    std::string mixed = token;
    mixed[10] = static_cast<char>(std::toupper(static_cast<unsigned char>(mixed[10])));
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + mixed, out, err));
    BOOST_CHECK(err.find("mixed case") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(v11_uri_08_hostile_inputs_rejected)
{
    const modelnet::Digest48 digest = Dg(0x11);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::PROVIDER, digest, uri, err), err);
    const std::string token = uri.substr(6);

    const std::vector<std::string> hostile = {
        "btx://" + token + "@host.example",        // userinfo
        "btx://" + token + ":8333",                // port
        "btx://" + token + "?amount=1",            // query
        "btx://" + token + "#frag",                // fragment
        "btx://" + token + "%20",                  // percent escape
        "btx://" + token + " ",                    // whitespace
        "btx://" + token + "\t",                   // control
        "btx://" + token + std::string("\xc3\xa9"),// unicode
        token.substr(0, 40) + "." + token.substr(41), // dotted authority
    };
    for (const std::string& bad : hostile) {
        modelnet::Resource out;
        std::string berr;
        // Rejection happens locally, before any network side effect.
        BOOST_CHECK_MESSAGE(!modelnet::DecodeResource(bad, out, berr), "accepted hostile input: " + bad);
        BOOST_CHECK(!berr.empty());
    }

    // The raw 512-byte input cap rejects long input before allocation.
    std::string long_input = "btx://" + token + std::string(600, 'a');
    modelnet::Resource out;
    BOOST_CHECK(!modelnet::DecodeResource(long_input, out, err));
}

BOOST_AUTO_TEST_CASE(v11_uri_09_paths_rejected)
{
    const modelnet::Digest48 digest = Dg(0x09);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::CIRCLE, digest, uri, err), err);
    const std::string token = uri.substr(6);

    modelnet::Resource out;
    // A single platform-appended empty path is tolerated.
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(uri + "/", out, err), err);
    BOOST_CHECK(out.digest == digest);

    BOOST_CHECK(!modelnet::DecodeResource(uri + "//", out, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "/x", out, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://model/" + token, out, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://m/" + token, out, err));
}

BOOST_AUTO_TEST_CASE(v11_uri_10_explicit_local_forms)
{
    const modelnet::Digest48 digest = Dg(0x7f);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::IDENTITY, digest, uri, err), err);
    const std::string token = uri.substr(6);

    modelnet::Resource out;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(token, out, err), err);
    BOOST_CHECK_EQUAL(out.Uri(), uri);
    BOOST_CHECK(out.digest == digest);

    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource("btx:" + token, out, err), err);
    BOOST_CHECK_EQUAL(out.Uri(), uri);

    BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource("BTX:" + ToUpperCopy(token), out, err), err);
    BOOST_CHECK_EQUAL(out.Uri(), uri);

    // Canonical output is always the full btx:// form, never the bare token.
    BOOST_CHECK_EQUAL(out.Uri().compare(0, 6, "btx://"), 0);
    BOOST_CHECK_NE(out.Uri(), token);
}

BOOST_AUTO_TEST_CASE(v11_uri_11_authority_not_dns)
{
    const modelnet::Digest48 digest = Dg(0x5a);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, digest, uri, err), err);
    const std::string token = uri.substr(6);

    // The 85-character authority is an application identifier, not an Internet
    // host name: it exceeds the 63-octet DNS label limit and cannot contain a dot.
    BOOST_CHECK_EQUAL(token.size(), 85u);
    BOOST_CHECK_GT(token.size(), 63u);
    BOOST_CHECK(token.find('.') == std::string::npos);
    BOOST_CHECK(token.find("btx1") == std::string::npos);
    for (char c : token) {
        BOOST_CHECK_MESSAGE(std::string(kBech32Charset).find(c) != std::string::npos,
                            std::string("non-bech32 authority symbol: ") + c);
    }

    // Bridge host splitting keeps every label within the DNS label limit and
    // reconstructs the exact token, i.e. the authority is never passed to IDNA.
    std::string host;
    BOOST_REQUIRE_MESSAGE(modelnet::SplitBridgeHost(uri, "bridge.example.org", host, err), err);
    std::vector<std::string> labels;
    size_t start = 0;
    while (start <= host.size()) {
        const size_t dot = host.find('.', start);
        labels.push_back(host.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    // 42 + 43 token labels plus the three configured suffix labels.
    BOOST_REQUIRE_EQUAL(labels.size(), 5u);
    for (const std::string& label : labels) {
        BOOST_CHECK_LE(label.size(), 63u);
        BOOST_CHECK_GT(label.size(), 0u);
    }
    BOOST_CHECK_EQUAL(labels[0] + labels[1], token);
}

BOOST_AUTO_TEST_CASE(v11_uri_13_not_a_spending_or_payment_input)
{
    const modelnet::Digest48 digest = Dg(0x13);
    std::string uri;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(modelnet::ResourceKind::RELEASE, digest, uri, err), err);

    // A resource reference is never a spending address and never a research
    // identity, so it cannot enter a payment parser as financial input.
    BOOST_CHECK(!modelnet::SpendingAddressIsResearchIdentity(uri));
    BOOST_CHECK(!modelnet::SpendingAddressIsResearchIdentity(uri.substr(6)));

    const fs::path tmp = m_path_root / "v11-uri-13";
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "decoderesource");
    UniValue params(UniValue::VARR);
    params.push_back(uri);
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["uri"].get_str(), uri);
    BOOST_CHECK(!result.exists("address"));
    BOOST_CHECK(!result.exists("amount"));

    // A resource URI is still not a spending input: claim/sign without a
    // frozen HTLC template fail closed (invalid params), never auto-spend.
    UniValue claim(UniValue::VOBJ);
    claim.pushKV("method", "buildmodelhtlcclaim");
    claim.pushKV("params", UniValue(UniValue::VARR));
    UniValue claim_result;
    std::string claim_code;
    err.clear();
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, claim, claim_result, claim_code, err));
    BOOST_CHECK(claim_code != "NOT_IMPLEMENTED");
    BOOST_CHECK_EQUAL(claim_code, "INVALID_PARAMETER");

    UniValue sign(UniValue::VOBJ);
    sign.pushKV("method", "signmodelfunding");
    sign.pushKV("params", UniValue(UniValue::VARR));
    UniValue sign_result;
    std::string sign_code;
    err.clear();
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, sign, sign_result, sign_code, err));
    BOOST_CHECK(sign_code != "NOT_IMPLEMENTED");
    BOOST_CHECK_EQUAL(sign_code, "INVALID_PARAMETER");
}

BOOST_AUTO_TEST_CASE(v11_uri_15_typed_hash_domain)
{
    std::vector<unsigned char> pk;
    std::string err;
    const modelnet::Digest48 model = Dg(0xa0);
    const modelnet::Digest48 artifact = Dg(0xb0);
    const modelnet::Digest48 buyer = modelnet::ResearchIdentityId(std::vector<unsigned char>(64, 0x01));
    const modelnet::SignedFreeGrant grant = IssueGrant(pk, model, artifact, buyer, err);

    // The record id is bound to the expected kind domain and field layout.
    modelnet::Digest48 grant_id;
    BOOST_REQUIRE_MESSAGE(modelnet::RecordId(modelnet::RECORD_FREE_GRANT, grant.body, grant_id, err), err);
    BOOST_CHECK_EQUAL(grant_id.Hex(), grant.object_id.Hex());

    // Relabelling the signed body as another kind is rejected: the typed layout
    // and the hash domain are both part of the root lookup.
    modelnet::Digest48 relabelled;
    std::string relabel_err;
    bool relabel_ok = false;
    try {
        relabel_ok = modelnet::RecordId(modelnet::RECORD_SERVICE_RECEIPT, grant.body, relabelled, relabel_err);
    } catch (const std::exception& e) {
        relabel_err = e.what();
        relabel_ok = false;
    }
    BOOST_CHECK(!relabel_ok);
    BOOST_CHECK(!relabel_err.empty());

    UniValue wrong_kind_body;
    std::string decode_err;
    BOOST_CHECK(!modelnet::DecodeRecord(modelnet::RECORD_SERVICE_RECEIPT, grant.payload, wrong_kind_body, decode_err));

    // The payload decodes under its real kind.
    UniValue ok_body;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeRecord(modelnet::RECORD_FREE_GRANT, grant.payload, ok_body, err), err);
    BOOST_CHECK_EQUAL(ok_body["model_id"].get_str(), model.Hex());

    BOOST_CHECK(std::string(modelnet::RecordKindName(modelnet::RECORD_FREE_GRANT)) !=
                std::string(modelnet::RecordKindName(modelnet::RECORD_SERVICE_RECEIPT)));
}

// ---------------------------------------------------------------------------
// Section 4 - resolution and community relays
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_resolve_01_cpu_only_cache)
{
    modelnet::RouterCache cache;
    modelnet::SignedRecordHint hint;
    hint.record_id = Dg(0xc1);
    hint.kind = modelnet::RECORD_COLLECTION;
    hint.expiry = 0; // no expiry
    hint.provider_id = "198.51.100.7:8443";
    hint.payload = {1, 2, 3};

    std::string err;
    BOOST_REQUIRE_MESSAGE(cache.Insert(hint, 1000, err), err);
    BOOST_CHECK_EQUAL(cache.Size(), 1u);

    // Resolution is pure local map lookup: no wallet, GPU, or chain-sync object
    // is involved in constructing or querying the CPU-only cache.
    const auto found = cache.LookupExact(hint.record_id, 1000);
    BOOST_REQUIRE_EQUAL(found.size(), 1u);
    BOOST_CHECK(found[0].record_id == hint.record_id);
    BOOST_CHECK(found[0].payload == hint.payload);

    // Absent ids return an empty candidate set rather than a fabricated root.
    BOOST_CHECK(cache.LookupExact(Dg(0xff), 1000).empty());
}

BOOST_AUTO_TEST_CASE(v11_resolve_02_local_cache_hit)
{
    modelnet::RouterCache cache;
    const modelnet::Digest48 id = Dg(0xc2);
    modelnet::SignedRecordHint hint;
    hint.record_id = id;
    hint.kind = modelnet::RECORD_IDENTITY_CARD;
    hint.expiry = 10'000;
    hint.provider_id = "router.local:8443";

    std::string err;
    BOOST_REQUIRE_MESSAGE(cache.Insert(hint, 1'000, err), err);

    // A known record is answered from the local cache with no router contact.
    const auto hit = cache.LookupExact(id, 1'000);
    BOOST_REQUIRE_EQUAL(hit.size(), 1u);
    BOOST_CHECK_EQUAL(hit[0].provider_id, hint.provider_id);
    BOOST_CHECK_EQUAL(cache.All(1'000).size(), 1u);

    // After expiry the cache stops answering and stops advertising.
    BOOST_CHECK(cache.LookupExact(id, 20'000).empty());
    BOOST_CHECK(cache.All(20'000).empty());
    cache.Expire(20'000);
    BOOST_CHECK_EQUAL(cache.Size(), 0u);
}

BOOST_AUTO_TEST_CASE(v11_resolve_03_independent_router_no_domain)
{
    modelnet::RouterCache cache;
    std::string err;

    // Any independently reachable host is accepted; there is no allowlist that
    // requires an official domain.
    modelnet::SignedRecordHint ip;
    ip.record_id = Dg(0xc3);
    ip.kind = modelnet::RECORD_POLICY_BUNDLE;
    ip.provider_id = "203.0.113.9:8443";
    ip.payload = {9};
    BOOST_REQUIRE_MESSAGE(cache.Insert(ip, 0, err), err);

    modelnet::SignedRecordHint bare;
    bare.record_id = Dg(0xc4);
    bare.kind = modelnet::RECORD_ALIAS;
    bare.provider_id = "unaffiliated-router";
    bare.payload = {4};
    BOOST_REQUIRE_MESSAGE(cache.Insert(bare, 0, err), err);

    BOOST_CHECK_EQUAL(cache.LookupExact(ip.record_id, 0).size(), 1u);
    BOOST_CHECK_EQUAL(cache.LookupExact(bare.record_id, 0).size(), 1u);
}

BOOST_AUTO_TEST_CASE(v11_resolve_04_router_removal_direct_transfer)
{
    // A direct transfer plan is built from verified peer availability alone; no
    // RouterCache object participates, so removing the router cannot abort it.
    std::vector<modelnet::PieceNeed> missing;
    modelnet::PieceNeed need;
    need.file_index = 0;
    need.piece_index = 0;
    need.length = 64;
    missing.push_back(need);

    modelnet::SourceOffer direct;
    direct.peer = "direct-host.example:8443";
    direct.paid = false;
    direct.available = true;

    const modelnet::HybridPlan plan = modelnet::PlanRetrieval(
        missing, {direct}, modelnet::RetrievalMode::FREE_ONLY, /*budget_atoms=*/0, /*approved=*/false);
    BOOST_REQUIRE_EQUAL(plan.free_pieces.size(), 1u);
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.paid_atoms, 0);
}

BOOST_AUTO_TEST_CASE(v11_resolve_05_exact_record_root)
{
    modelnet::RouterCache cache;
    std::string err;

    const modelnet::Digest48 selected = Dg(0xd1);
    modelnet::SignedRecordHint good;
    good.record_id = selected;
    good.kind = modelnet::RECORD_COLLECTION;
    good.provider_id = "host-a";
    good.payload = {0xaa, 0xbb};

    modelnet::SignedRecordHint other;
    other.record_id = Dg(0xd2);
    other.kind = modelnet::RECORD_COLLECTION;
    other.provider_id = "host-b";
    other.payload = {0xcc};

    BOOST_REQUIRE_MESSAGE(cache.Insert(good, 0, err), err);
    BOOST_REQUIRE_MESSAGE(cache.Insert(other, 0, err), err);

    // Lookup is keyed by the exact record id: an unrelated (possibly malicious)
    // record cannot replace the selected model root's candidates.
    const auto found = cache.LookupExact(selected, 0);
    BOOST_REQUIRE_EQUAL(found.size(), 1u);
    BOOST_CHECK(found[0].payload == good.payload);
    BOOST_CHECK_EQUAL(found[0].provider_id, "host-a");

    // An omitted record simply yields no candidates; the caller keeps its
    // already-selected root rather than accepting a substitute.
    BOOST_CHECK(cache.LookupExact(Dg(0xdd), 0).empty());
    BOOST_CHECK_EQUAL(cache.All(0).size(), 2u);
}

BOOST_AUTO_TEST_CASE(v11_resolve_06_typed_identity_lookup)
{
    const std::vector<unsigned char> pk(1312, 0x2a);
    const modelnet::Digest48 provider_id = modelnet::ProviderId(pk);
    const modelnet::Digest48 research_id = modelnet::ResearchIdentityId(pk);

    // Provider/service identity and research identity are distinct key digests.
    BOOST_CHECK(provider_id != research_id);
    BOOST_CHECK(modelnet::ServiceSignerId(pk) == provider_id);

    modelnet::RouterCache cache;
    modelnet::SignedRecordHint card;
    card.record_id = provider_id;
    card.kind = modelnet::RECORD_IDENTITY_CARD;
    card.provider_id = "identity-host";
    card.payload = {0x01};
    std::string err;
    BOOST_REQUIRE_MESSAGE(cache.Insert(card, 0, err), err);

    // A typed identity lookup verifies the exact key digest; it does not answer
    // for a different identity domain or for a model digest.
    BOOST_CHECK_EQUAL(cache.LookupExact(provider_id, 0).size(), 1u);
    BOOST_CHECK(cache.LookupExact(research_id, 0).empty());
    BOOST_CHECK(cache.LookupExact(Dg(0x66), 0).empty());
}

BOOST_AUTO_TEST_CASE(v11_resolve_10_monetary_endpoints_hidden)
{
    const fs::path tmp = m_path_root / "v11-resolve-10";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    std::string err;

    // Monolithic/helper RPC table exposes no wallet method.
    for (const std::string method : {"getnewaddress", "sendtoaddress", "listunspent", "dumpwallet", "signrawtransaction"}) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", UniValue(UniValue::VARR));
        UniValue result;
        std::string code;
        err.clear();
        BOOST_CHECK_MESSAGE(!modelnet::DispatchHelperRpc(cat, rpc, result, code, err), method);
        BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
    }

    // The HTTP surface hides the same endpoints behind the generic 404.
    for (const std::string path : {"/btx-model/2/wallet/dump", "/btx-model/2/sendtoaddress", "/btx-model/2/wallet"}) {
        modelnet::NativeRequest req;
        req.method = "GET";
        req.path = path;
        modelnet::NativeResponse resp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
        BOOST_CHECK_EQUAL(resp.status, 404);
        BOOST_CHECK(resp.body.find("wallet") == std::string::npos || resp.body.find("NOT_FOUND") != std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// Section 5 - free-first retrieval
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_free_01_identity_only_no_wallet)
{
    const fs::path tmp = m_path_root / "v11-free-01";
    std::string err;

    // A fresh identity-only client creates a service identity and a PQ buyer id
    // with no wallet, balance, or chain state.
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    modelnet::Digest48 signer_id;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadOrCreateServiceIdentity(tmp, pk, sk, signer_id, err), err);
    BOOST_CHECK_EQUAL(pk.size(), modelnet::MLDSA44_PK);
    BOOST_CHECK_EQUAL(sk.size(), modelnet::MLDSA44_SK);
    BOOST_CHECK(signer_id == modelnet::ProviderId(pk));

    std::vector<unsigned char> buyer_pk;
    std::vector<unsigned char> buyer_sk;
    BOOST_REQUIRE_MESSAGE(modelnet::GenerateMlDsa44(buyer_pk, buyer_sk, err), err);
    const modelnet::Digest48 buyer = modelnet::ResearchIdentityId(buyer_pk);

    modelnet::FreeGrantParams p;
    p.buyer_id = buyer;
    p.model_id = Dg(0xe0);
    p.artifact_id = Dg(0xe1);
    p.file_index = 0;
    p.first_piece = 0;
    p.piece_count = 2;
    p.maximum_bytes = 128;

    modelnet::SignedFreeGrant grant;
    BOOST_REQUIRE_MESSAGE(modelnet::IssueFreeGrant(p, sk, pk, grant, err), err);
    BOOST_CHECK(!grant.signature.empty());

    UniValue body;
    BOOST_REQUIRE_MESSAGE(
        modelnet::VerifyFreeGrant(grant.payload, grant.signature, grant.pubkey,
                                  static_cast<int64_t>(std::time(nullptr)), {}, body, err),
        err);
    BOOST_CHECK_EQUAL(body["buyer_id"].get_str(), buyer.Hex());
    BOOST_CHECK_EQUAL(body["model_id"].get_str(), p.model_id.Hex());
    BOOST_CHECK_EQUAL(body["artifact_id"].get_str(), p.artifact_id.Hex());
    BOOST_CHECK_EQUAL(body["piece_count"].getInt<int>(), 2);
    BOOST_CHECK(!modelnet::GrantHasPaymentFields(body));

    // The grant is single use and survives a helper "restart" (fresh call, file
    // backed nonce store).
    uint64_t sequence = 0;
    const std::string nonce = body["grant_nonce"].get_str();
    BOOST_REQUIRE_MESSAGE(modelnet::ConsumeGrantNonce(tmp, nonce, sequence, err), err);
    BOOST_CHECK_GE(sequence, 1u);
    std::string replay_err;
    uint64_t replay_seq = 0;
    BOOST_CHECK(!modelnet::ConsumeGrantNonce(tmp, nonce, replay_seq, replay_err));
    BOOST_CHECK_EQUAL(replay_err, "replay");
}

BOOST_AUTO_TEST_CASE(v11_free_05_zero_price_no_balance)
{
    std::string err;
    modelnet::PlanChoice choice = modelnet::PlanChoice::PAID;

    // FREE_ONLY never reaches a paid branch, with or without a free ETA, and a
    // missing/zero free source just waits. No buyer balance or unlock is implied.
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, nullptr,
                                       /*budget_atoms=*/0, /*exposure_ok=*/true, std::nullopt,
                                       /*value_per_second_atoms=*/0, /*approved=*/false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);

    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::optional<int>{5}, nullptr, 0,
                                       true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::FREE);

    // Even with an attractive paid alternative, FREE_ONLY does not spend.
    modelnet::PaidPlan paid;
    paid.price_atoms = 1;
    paid.fee_atoms = 0;
    paid.total_eta_s = 1;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, &paid, 1000, true,
                                       std::nullopt, 1000, true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);

    // The free path carries no automatic spend and no wallet unlock.
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    const UniValue policy = modelnet::PolicyToJson(modelnet::PreservationPolicy{});
    BOOST_CHECK_EQUAL(policy["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(policy["retrieval_default"].get_str(), "FREE_ONLY");
}

BOOST_AUTO_TEST_CASE(v11_free_14_exposure_and_fee_ceiling)
{
    std::string err;
    modelnet::PaidPlan paid;
    paid.price_atoms = 100;
    paid.fee_atoms = 10;
    paid.total_eta_s = 5;
    paid.safe = true;
    paid.deliverable = true;

    modelnet::PlanChoice choice = modelnet::PlanChoice::FREE;

    // Aggregate cost is price + fee; it fits the approved budget and exposure.
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid,
                                       /*budget_atoms=*/110, /*exposure_ok=*/true, std::nullopt, 0, false,
                                       choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::PAID);

    // Outstanding commitments already at the ceiling block a further purchase.
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid, 110,
                                       /*exposure_ok=*/false, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);

    // A budget that covers the price but not the fee is not enough.
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid,
                                       /*budget_atoms=*/109, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
}

BOOST_AUTO_TEST_CASE(v11_free_15_release_not_substituted)
{
    std::string err;
    modelnet::PaidPlan paid;
    paid.price_atoms = 1;
    paid.fee_atoms = 0;
    paid.total_eta_s = 1;
    // A release campaign is not a substitutable artifact for missing free chunks.
    paid.requires_release = true;

    modelnet::PlanChoice choice = modelnet::PlanChoice::PAID;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid,
                                       /*budget_atoms=*/modelnet::MAX_MONEY_ATOMS, /*exposure_ok=*/true, std::nullopt,
                                       /*value_per_second_atoms=*/0, /*approved=*/true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);

    // Explicit paid selection is also refused while the campaign is unreleased.
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::EXPLICIT_PAID, std::nullopt, &paid, modelnet::MAX_MONEY_ATOMS,
                                       true, std::nullopt, 0, true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
}

// ---------------------------------------------------------------------------
// Section 9 - communities, collections and circles
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_comm_06_follow_does_not_raise_budget)
{
    // Following/subscribing to a collection is a local policy action: it never
    // raises the operator's storage budget.
    BOOST_CHECK(!modelnet::CollectionFollowRaisesQuota());
    BOOST_CHECK(!modelnet::CollectionLoadsCode());

    modelnet::PreservationPolicy p;
    p.storage_quota_bytes = uint64_t{1} << 30;
    p.seed_mode = modelnet::SeedMode::AUTO;
    p.seed_upon_download = true;

    const UniValue json = modelnet::PolicyToJson(p);
    BOOST_CHECK_EQUAL(json["storage_quota_bytes"].getInt<uint64_t>(), uint64_t{1} << 30);
    BOOST_CHECK_EQUAL(json["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(json["demand_propagation"].get_bool());

    // With no allocated budget, following cannot enable propagation.
    modelnet::PreservationPolicy zero;
    zero.seed_mode = modelnet::SeedMode::AUTO;
    zero.seed_upon_download = true;
    const UniValue zero_json = modelnet::PolicyToJson(zero);
    BOOST_CHECK(!zero_json["demand_propagation"].get_bool());
    BOOST_CHECK(!zero_json["preservation_propagation"].get_bool());
}

BOOST_AUTO_TEST_CASE(v11_comm_07_no_onchain_membership)
{
    BOOST_CHECK(!modelnet::CircleHasOnChainMembership());

    const fs::path tmp = m_path_root / "v11-comm-07";
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "joinmodelcircle");
    UniValue params(UniValue::VARR);
    params.push_back(Dg(0xf0).Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);
    BOOST_CHECK_EQUAL(result["on_chain_membership"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["schema_version"].getInt<int>(), 2);
}

BOOST_AUTO_TEST_CASE(v11_comm_08_preservation_local_limits)
{
    modelnet::PreservationPolicy p;
    p.preserve_rare = true;
    p.storage_quota_bytes = uint64_t{1} << 30;
    p.allow_encrypted = false;

    // Local pins/limits/profile/content choices gate unsolicited fetching.
    BOOST_CHECK(modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 2, 4096, 4096));
    BOOST_CHECK(!modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::BYTES_VERIFIED, true, 2, 4096, 4096));
    BOOST_CHECK(!modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::FAILED, false, 2, 4096, 4096));
    BOOST_CHECK(!modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 0, 4096, 4096));
    BOOST_CHECK(!modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 3, 4096, 4096));
    BOOST_CHECK(!modelnet::MayPreserveFetch(p, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 2, 8192, 4096));

    modelnet::PreservationPolicy off = p;
    off.preserve_rare = false;
    BOOST_CHECK(!modelnet::MayPreserveFetch(off, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 2, 4096, 4096));

    // Locally pinned content is never selected for unsolicited preservation.
    modelnet::PreserveCandidate rare;
    rare.model_id = Dg(0x01);
    rare.bytes = 3000;
    rare.observed_sources = 1;
    rare.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;

    modelnet::PreserveCandidate pinned;
    pinned.model_id = Dg(0x02);
    pinned.bytes = 1;
    pinned.observed_sources = 1;
    pinned.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;

    modelnet::PreserveCandidate chosen;
    const std::set<modelnet::Digest48> local{pinned.model_id};
    BOOST_REQUIRE(modelnet::SelectPreserveRare({rare, pinned}, local, 10'000, p, chosen));
    BOOST_CHECK(chosen.model_id == rare.model_id);

    // Eviction never removes a pin and prefers the more replicated content.
    modelnet::EvictItem pin_item;
    pin_item.pinned = true;
    pin_item.seeded = true;
    pin_item.bytes = 10'000;
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(pin_item), 1000);

    modelnet::EvictItem under_replicated;
    under_replicated.observed_sources = 2;
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(under_replicated), 80);

    modelnet::EvictItem seeded;
    seeded.seeded = true;
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(seeded), 40);

    modelnet::EvictItem common;
    BOOST_CHECK_EQUAL(modelnet::EvictPriority(common), 0);
}

BOOST_AUTO_TEST_CASE(v11_comm_10_third_party_no_credit)
{
    modelnet::ReciprocityLedger ledger;
    const int64_t now = 1'000'000;

    // Third-party/self-reported receipts never mint useful-free credit.
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("peer-a", 8 << 20, now));
    BOOST_CHECK_EQUAL(ledger.Effective("peer-a", now), 0);
    BOOST_CHECK_EQUAL(ledger.Weight("peer-a", now), 1);

    // A locally verified, needed free piece does earn credit.
    BOOST_REQUIRE(ledger.Received("peer-a", Dg(0x02).Hex(), 0, 0, 64 << 20, now,
                                  /*verified=*/true, /*needed=*/true, /*paid=*/false,
                                  /*observed_sources=*/1));
    BOOST_CHECK_GT(ledger.Effective("peer-a", now), 0);

    // Duplicate delivery of the same piece earns nothing further.
    BOOST_CHECK(!ledger.Received("peer-a", Dg(0x02).Hex(), 0, 0, 64 << 20, now, true, true, false, 1));
}

// ---------------------------------------------------------------------------
// Section 10 - optional browser bridge
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_bridge_01_link_only_full_uri)
{
    const UniValue vec = LoadVectors();
    const UniValue& row = vec["resource_vectors"][0];
    const std::string uri = row["uri"].get_str();

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.ok);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);

    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_CHECK_EQUAL(obj["canonical"].get_str(), uri);
    BOOST_CHECK_EQUAL(obj["open_in_btx"].get_str(), uri);
    BOOST_CHECK_EQUAL(obj["kind"].get_str(), row["name"].get_str());
    BOOST_CHECK_EQUAL(obj["digest"].get_str(), row["digest"].get_str());

    // The exact 91-character native URI is also reachable through the bare
    // token path, never a truncated host label.
    modelnet::BrowserBridgeResponse bare;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + row["token"].get_str(), bare));
    BOOST_CHECK_EQUAL(bare.http_status, 200);
    BOOST_CHECK_EQUAL(bare.canonical_btx, uri);
}

BOOST_AUTO_TEST_CASE(v11_bridge_02_no_https_fallback_disclosed)
{
    const std::string uri = LoadVectors()["resource_vectors"][1]["uri"].get_str();

    const std::vector<std::string> paths = {
        "/health",
        "/open?uri=" + uri,
        "/open?uri=not-a-resource",
        "/" + uri.substr(6),
        "/wallet/dump",
        "/not-a-token",
    };
    for (const std::string& path : paths) {
        modelnet::BrowserBridgeResponse br;
        BOOST_REQUIRE(modelnet::HandleBridgeGet(path, br));
        UniValue obj;
        BOOST_REQUIRE(obj.read(br.body));
        BOOST_CHECK_EQUAL(obj["native_fallback"].get_bool(), false);
        BOOST_CHECK(!br.body.empty());
        BOOST_CHECK(br.http_status == 200 || br.http_status >= 400);
    }
}

BOOST_AUTO_TEST_CASE(v11_bridge_03_upstream_pq1)
{
    const std::string uri = LoadVectors()["resource_vectors"][2]["uri"].get_str();
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));

    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    const std::string upstream = obj["upstream"].get_str();
    BOOST_CHECK(upstream.find("PQ1") != std::string::npos);
    BOOST_CHECK_EQUAL(obj["native_fallback"].get_bool(), false);

    // The bridge itself is a local decoder: it declares no native trust root.
    BOOST_CHECK_EQUAL(obj["bind_default"].get_str(), "127.0.0.1");
}

BOOST_AUTO_TEST_CASE(v11_bridge_04_token_longer_than_dns_label)
{
    const UniValue vec = LoadVectors();
    const UniValue& row = vec["resource_vectors"][3];
    const std::string token = row["token"].get_str();

    // A single label carrying the whole 85-character token would exceed the
    // 63-octet DNS label limit, so it cannot be a host name.
    BOOST_CHECK_EQUAL(token.size(), 85u);
    BOOST_CHECK_GT(token.size(), 63u);

    std::string host;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SplitBridgeHost(row["uri"].get_str(), "bridge.example.org", host, err), err);
    BOOST_CHECK_EQUAL(host, row["split_bridge_hostname"].get_str());
    // No single label carries the whole token.
    const size_t first_dot = host.find('.');
    BOOST_REQUIRE(first_dot != std::string::npos);
    BOOST_CHECK_LT(first_dot, token.size());
}

BOOST_AUTO_TEST_CASE(v11_bridge_05_42_43_split_exact)
{
    const UniValue vec = LoadVectors();
    for (const auto& row : vec["resource_vectors"].getValues()) {
        const std::string token = row["token"].get_str();
        std::string host;
        std::string err;
        BOOST_REQUIRE_MESSAGE(
            modelnet::SplitBridgeHost(row["uri"].get_str(), "bridge.example.org", host, err), err);
        BOOST_CHECK_EQUAL(host, row["split_bridge_hostname"].get_str());

        // The 42/43 split reconstructs the exact token without truncation.
        const std::string suffix = ".bridge.example.org";
        BOOST_REQUIRE_EQUAL(host.size(), token.size() + 1 + suffix.size());
        const std::string prefix = host.substr(0, host.size() - suffix.size());
        const size_t dot = prefix.find('.');
        BOOST_REQUIRE(dot != std::string::npos);
        BOOST_CHECK_EQUAL(dot, 42u);
        const std::string reconstructed = prefix.substr(0, dot) + prefix.substr(dot + 1);
        BOOST_CHECK_EQUAL(reconstructed, token);
        BOOST_CHECK_EQUAL(reconstructed.size(), 85u);
    }
}

BOOST_AUTO_TEST_CASE(v11_bridge_06_certificate_depth)
{
    const std::string uri = LoadVectors()["resource_vectors"][4]["uri"].get_str();
    std::string host;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SplitBridgeHost(uri, "bridge.example.org", host, err), err);

    // Prefix before the configured suffix has two labels, so a one-label
    // wildcard certificate (*.bridge.example.org) would not cover the host.
    const std::string suffix = "bridge.example.org";
    const size_t at = host.find("." + suffix);
    BOOST_REQUIRE(at != std::string::npos);
    const std::string prefix = host.substr(0, at);
    size_t labels = 1;
    for (char c : prefix) {
        if (c == '.') ++labels;
    }
    BOOST_CHECK_EQUAL(labels, 2u);
    BOOST_CHECK(labels != 1); // wildcard depth one is not enough
}

BOOST_AUTO_TEST_CASE(v11_bridge_07_no_implicit_download)
{
    const std::string uri = LoadVectors()["resource_vectors"][5]["uri"].get_str();

    // Opening a link is a preview, not a download, and a mutating download
    // request is refused without an explicit separate operator enable.
    modelnet::BrowserBridgeResponse open;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, open));
    UniValue obj;
    BOOST_REQUIRE(obj.read(open.body));
    BOOST_CHECK(!obj.exists("download"));
    BOOST_CHECK(!obj.exists("download_enabled"));

    modelnet::BrowserBridgeResponse post;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/download", "", post));
    BOOST_CHECK_EQUAL(post.http_status, 405);

    // There is no byte-serving route on the browser edge.
    modelnet::BrowserBridgeResponse pieces;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/transfers/" + uri.substr(6) + "/pieces/0/0", pieces));
    BOOST_CHECK_EQUAL(pieces.http_status, 400);
}

BOOST_AUTO_TEST_CASE(v11_bridge_08_wallet_private_unreachable)
{
    modelnet::BrowserBridgeResponse br;

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/wallet/dump", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/sign", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/api", "{\"method\":\"walletpassphrase\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/api", "{\"method\":\"sendtoaddress\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/dump/private", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);

    for (const std::string& body : {std::string{"{\"method\":\"dumpprivkey\"}"},
                                    std::string{"{\"method\":\"importprivkey\"}"}}) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/api", body, br));
        BOOST_CHECK_EQUAL(br.http_status, 405);
    }

    // Every refusal still discloses the weaker browser edge.
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_CHECK_EQUAL(obj["wallet"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(v11_bridge_09_no_arbitrary_proxy)
{
    modelnet::BrowserBridgeResponse br;

    // Only manifest file indices/resources are ever addressed; an arbitrary
    // URL or IP is not proxyable through the bridge.
    const std::vector<std::string> refused = {
        "/https://evil.example/x",
        "/10.0.0.1:8333",
        "/open?uri=https%3A%2F%2Fevil.example%2Fx",
        "/open?uri=203.0.113.5",
    };
    for (const std::string& path : refused) {
        BOOST_REQUIRE(modelnet::HandleBridgeGet(path, br));
        BOOST_CHECK_EQUAL(br.http_status, 400);
        BOOST_CHECK(br.canonical_btx.empty());
    }

    // Any mutating request is refused outright.
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("PUT", "/open", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
}

BOOST_AUTO_TEST_CASE(v11_bridge_11_json_only_isolation)
{
    const std::string uri = LoadVectors()["resource_vectors"][6]["uri"].get_str();

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));
    BOOST_CHECK_EQUAL(br.content_type, "application/json");
    BOOST_REQUIRE(!br.body.empty());
    BOOST_CHECK_EQUAL(br.body.front(), '{');

    // Model text and files are never emitted with a cacheable text content type.
    BOOST_CHECK_EQUAL(br.content_type.find("text/"), std::string::npos);
    BOOST_CHECK_EQUAL(br.content_type.find("html"), std::string::npos);

    modelnet::BrowserBridgeResponse health;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", health));
    BOOST_CHECK_EQUAL(health.content_type, "application/json");

    modelnet::BrowserBridgeResponse missing;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/not-a-token", missing));
    BOOST_CHECK_EQUAL(missing.content_type, "application/json");
}

BOOST_AUTO_TEST_CASE(v11_bridge_12_browser_not_native_pq)
{
    const std::string uri = LoadVectors()["resource_vectors"][7]["uri"].get_str();
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));

    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    // Browser-only output never claims native end-to-end PQ.
    BOOST_CHECK_EQUAL(obj["pq_end_to_end"].get_bool(), false);
    BOOST_CHECK_EQUAL(obj["native_fallback"].get_bool(), false);

    // Native helper capabilities disclose the same boundary.
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["browser_bridge"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["remote_inference"].get_bool(), false);
}

// ---------------------------------------------------------------------------
// Sections 2 and 10 - local use, profile and consent
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_local_01_open_uri_preview_only)
{
    const std::string uri = LoadVectors()["resource_vectors"][8]["uri"].get_str();
    const fs::path tmp = m_path_root / "v11-local-01";
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "openbtxuri");
    UniValue params(UniValue::VARR);
    params.push_back(uri);
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);

    // Opening a URI previews only: no execution, no network, no wallet.
    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["network"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["wallet"].get_bool(), false);
    BOOST_REQUIRE(result["proposed_actions"].isArray());
    BOOST_CHECK(!result["proposed_actions"].getValues().empty());
    BOOST_CHECK_EQUAL(result["uri"].get_str(), uri);
}

BOOST_AUTO_TEST_CASE(v11_local_02_export_verified_path)
{
    std::string err;
    const fs::path tmp = m_path_root / "v11-local-02";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);

    std::vector<unsigned char> stub(10, 0);
    WriteLE64(stub.data(), 2);
    stub[8] = '{';
    stub[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(stub.data()), static_cast<std::streamsize>(stub.size()));
    }

    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), /*pin=*/true, imported, err), err);

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "exportmodelpath");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);

    // The verified local path is exported for a user-installed runtime; the
    // helper never starts an inference runtime itself.
    BOOST_CHECK(!result["store_root"].get_str().empty());
    BOOST_CHECK(!result["source_path"].get_str().empty());
    BOOST_CHECK_EQUAL(result["inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_started"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["runtime_exec"].get_bool(), false);
    BOOST_CHECK(result["note"].get_str().find("never starts a runtime") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(v11_local_03_unsupported_no_remote_inference)
{
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["cuda_qualification"].get_bool(), true);

    // An unsafe/unsupported model produces an explicit static result.
    const std::vector<unsigned char> pickle{0x80, 0x04, 0x01};
    modelnet::QualReport report;
    const modelnet::QualResult pickle_result =
        modelnet::QualifyBytes("model.pkl", pickle, report);
    BOOST_CHECK(pickle_result == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);

    // An unsupported container is an explicit rejection, never a remote retry.
    const std::vector<unsigned char> junk{'n', 'o', 'p', 'e'};
    modelnet::QualReport junk_report;
    const modelnet::QualResult junk_result = modelnet::QualifyBytes("unknown.bin", junk, junk_report);
    BOOST_CHECK(junk_result == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);

    // A missing/unsupported local artifact is an explicit local result.
    modelnet::QualReport missing_report;
    const modelnet::QualResult missing_result =
        modelnet::QualifyFile(fs::PathToString(m_path_root / "missing-artifact.safetensors"), missing_report);
    BOOST_CHECK(missing_result == modelnet::QualResult::INVALID_MODEL);

    // There is no remote-inference RPC to fall back to.
    const fs::path tmp = m_path_root / "v11-local-03";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "infermodel");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code;
    std::string err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(v11_local_04_models_before_finance)
{
    const fs::path tmp = m_path_root / "v11-local-04";
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodelnetworkinfo");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err), err);

    // The researcher profile starts in free mode with zero automatic spend and
    // never requires a monetary wallet.
    BOOST_CHECK_EQUAL(result["retrieval_default"].get_str(), "FREE_ONLY");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_REQUIRE(result["capabilities"].isObject());
    BOOST_CHECK_EQUAL(result["capabilities"]["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!result.exists("wallet_required"));

    // Identity-only store works without a monetary wallet.
    modelnet::IdentityStore store;
    BOOST_CHECK(!store.RequiresWallet());
    BOOST_CHECK_EQUAL(store.AutomaticSpendAtoms(), 0);
    BOOST_CHECK(!store.RotationCopiesReciprocity());
}

BOOST_AUTO_TEST_CASE(v11_local_05_storage_consent)
{
    // A fresh install stores no payload until an affirmative budget is given.
    modelnet::FirstRunConsent consent;
    BOOST_CHECK(!modelnet::AllowPayloadStorage(consent));

    consent.storage_bytes = uint64_t{1} << 30;
    consent.preserve_rare = true;
    consent.seed = modelnet::SeedMode::AUTO;
    BOOST_CHECK(modelnet::AllowPayloadStorage(consent));

    const fs::path path = m_path_root / "v11-local-05" / "firstrun.json";
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SaveFirstRunConsent(path, consent, err), err);

    modelnet::FirstRunConsent loaded;
    BOOST_REQUIRE_MESSAGE(modelnet::LoadFirstRunConsent(path, loaded, err), err);
    BOOST_CHECK_EQUAL(loaded.storage_bytes, consent.storage_bytes);
    BOOST_CHECK_EQUAL(static_cast<int>(loaded.seed), static_cast<int>(consent.seed));
    BOOST_CHECK_EQUAL(loaded.preserve_rare, consent.preserve_rare);
    BOOST_CHECK(modelnet::AllowPayloadStorageFile(path));

    // Upload/disk budgets are explicit values, not inferred.
    uint64_t parsed = 0;
    BOOST_REQUIRE(modelnet::ParseStorageBudget("80GiB", parsed, err));
    BOOST_CHECK_EQUAL(parsed, uint64_t{80} << 30);
    BOOST_CHECK(!modelnet::ParseStorageBudget("", parsed, err));
    BOOST_CHECK(!modelnet::ParseStorageBudget("not-a-budget", parsed, err));
}

// ---------------------------------------------------------------------------
// Section 13 - documentation vectors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(v11_doc_02_documented_vectors_identical)
{
    const UniValue vec = LoadVectors();
    BOOST_REQUIRE(vec["resource_vectors"].isArray());
    BOOST_REQUIRE_EQUAL(vec["resource_vectors"].size(), 9u);

    // Every complete documented vector parses identically and re-encodes to the
    // documented canonical URI.
    for (const auto& row : vec["resource_vectors"].getValues()) {
        modelnet::Resource out;
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::DecodeResource(row["uri"].get_str(), out, err), row["uri"].get_str());
        BOOST_CHECK_EQUAL(out.Uri(), row["uri"].get_str());
        BOOST_CHECK_EQUAL(out.digest.Hex(), row["digest"].get_str());

        std::string reencoded;
        BOOST_REQUIRE_MESSAGE(modelnet::EncodeResource(out.kind, out.digest, reencoded, err), err);
        BOOST_CHECK_EQUAL(reencoded, row["uri"].get_str());

        std::string bridge_path;
        BOOST_REQUIRE_MESSAGE(modelnet::BridgePath(row["uri"].get_str(), "https://bridge.example.org",
                                                   bridge_path, err), err);
        BOOST_CHECK_EQUAL(bridge_path, row["bridge_path"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(v11_doc_03_inference_removed)
{
    // Inference is removed from the effective roadmap: it is not advertised and
    // there is no inference endpoint.
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["cuda_qualification"].get_bool(), true);
    BOOST_CHECK(caps["http"].isArray());
    for (const auto& entry : caps["http"].getValues()) {
        const std::string s = entry.get_str();
        BOOST_CHECK(s.find("inference") == std::string::npos);
        BOOST_CHECK(s.find("infer") == std::string::npos);
    }

    const fs::path tmp = m_path_root / "v11-doc-03";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "runinference");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code;
    std::string err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
}

BOOST_AUTO_TEST_CASE(v11_doc_04_bridge_scoped_optional)
{
    // The optional browser bridge is explicitly scoped as a disclosed-weaker
    // edge, not a native trust root.
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["browser_bridge"].get_bool(), false);

    const std::string uri = LoadVectors()["resource_vectors"][0]["uri"].get_str();
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_CHECK_EQUAL(obj["pq_end_to_end"].get_bool(), false);
    BOOST_CHECK_EQUAL(obj["native_fallback"].get_bool(), false);
    BOOST_CHECK_EQUAL(obj["wallet"].get_bool(), false);
    BOOST_CHECK(obj["note"].get_str().find("not the identity authority") != std::string::npos);

    modelnet::BrowserBridgeResponse health;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", health));
    UniValue health_obj;
    BOOST_REQUIRE(health_obj.read(health.body));
    BOOST_CHECK_EQUAL(health_obj["profile"].get_str(), "D09");
    BOOST_CHECK_EQUAL(health_obj["catalog_browser_bridge"].get_bool(), false);
    BOOST_CHECK_EQUAL(health_obj["bind_default"].get_str(), "127.0.0.1");
}

BOOST_AUTO_TEST_SUITE_END()
