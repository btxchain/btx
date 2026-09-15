// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11 matrix id -> BOOST_AUTO_TEST_CASE
// V11-URI-07     uri_mixed_case_bech32_rejected
// V11-URI-08     uri_query_and_fragment_rejected
// V11-URI-03     uri_wrong_hrp_rejected
// V11-URI-02     uri_truncated_payload_rejected
// V11-URI-10     uri_decode_token_vs_uri
// V11-RESOLVE-02 resolve_incomplete_local_catalog
// V11-RESOLVE-08 resolve_incomplete_local_catalog
// V11-URI-14     uri_14_short_display_copy_is_full_canonical

#include <bech32.h>
#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/resource_uri.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cctype>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_uri_resolve_tests, BasicTestingSetup)

namespace {

UniValue LoadVectors()
{
    std::vector<fs::path> candidates;
    const fs::path here = fs::PathFromString(std::string{__FILE__});
    candidates.push_back(here.parent_path().parent_path().parent_path() / "testdata" / "modelnet" / "vectors.json");
    candidates.push_back(here.parent_path() / "data" / "modelnet_v11_vectors.json");
#ifdef MODELNET_V11_VECTORS_PATH
    candidates.push_back(fs::PathFromString(MODELNET_V11_VECTORS_PATH));
#endif
    for (const auto& p : candidates) {
        std::ifstream in{p};
        if (!in) continue;
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        UniValue v;
        if (v.read(raw) && v.isObject() && v.exists("resource_vectors")) {
            return v;
        }
    }
    BOOST_FAIL("no testdata/modelnet/vectors.json or modelnet_v11_vectors.json");
    return {};
}

std::string MixFirstAlpha(std::string s)
{
    for (char& c : s) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            return s;
        }
    }
    return s;
}

std::string Bech32Payload(const std::string& encoded)
{
    const auto sep = encoded.find('1');
    BOOST_REQUIRE(sep != std::string::npos);
    BOOST_REQUIRE(sep + 1 < encoded.size());
    return encoded.substr(sep + 1);
}

UniValue ParseBridge(const modelnet::BrowserBridgeResponse& br)
{
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_REQUIRE(obj.isObject());
    return obj;
}

void WriteTinySafetensors(const fs::path& src)
{
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    std::ofstream out(src / "model.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    BOOST_REQUIRE(out.good());
}

} // namespace

BOOST_AUTO_TEST_CASE(uri_mixed_case_bech32_rejected)
{
    const UniValue vectors = LoadVectors();
    modelnet::Resource r;
    std::string err;
    for (const auto& v : vectors["resource_vectors"].getValues()) {
        const std::string uri = v["uri"].get_str();
        const std::string token = v["token"].get_str();
        BOOST_REQUIRE_EQUAL(token.size(), 85U);
        const std::string mixed_token = MixFirstAlpha(token);
        BOOST_REQUIRE(mixed_token != token);
        BOOST_CHECK(!modelnet::DecodeResource(mixed_token, r, err));
        BOOST_CHECK(!modelnet::DecodeResource("btx://" + mixed_token, r, err));
        BOOST_CHECK(!modelnet::DecodeResource("btx:" + mixed_token, r, err));
        std::string mixed_uri = uri;
        for (size_t i = 6; i < mixed_uri.size(); ++i) {
            if (std::isalpha(static_cast<unsigned char>(mixed_uri[i]))) {
                mixed_uri[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(mixed_uri[i])));
                break;
            }
        }
        BOOST_CHECK(!modelnet::DecodeResource(mixed_uri, r, err));

        std::string upper = uri;
        for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        BOOST_REQUIRE(modelnet::DecodeResource(upper, r, err));
        BOOST_CHECK_EQUAL(r.Uri(), uri);
    }
}

BOOST_AUTO_TEST_CASE(uri_query_and_fragment_rejected)
{
    const UniValue vectors = LoadVectors();
    const std::string uri = vectors["resource_vectors"][0]["uri"].get_str();
    const std::string token = vectors["resource_vectors"][0]["token"].get_str();
    modelnet::Resource r;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeResource(uri + "?pay=1", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "?x=1&y=2", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "#run", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "#", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(token + "?pay=1", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(token + "#run", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "?pay=1#run", r, err));

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri + "?pay=1", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri + "#run", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
}

BOOST_AUTO_TEST_CASE(uri_wrong_hrp_rejected)
{
    const UniValue vectors = LoadVectors();
    const auto decoded = bech32::Decode(vectors["resource_vectors"][0]["internal_bech32m"].get_str(),
                                        bech32::CharLimit::BECH32);
    BOOST_REQUIRE(decoded.encoding == bech32::Encoding::BECH32M);
    BOOST_REQUIRE_EQUAL(decoded.hrp, "btx");

    modelnet::Resource r;
    std::string err;
    for (const char* hrp : {"bc", "tb", "bcrt", "btc"}) {
        const std::string encoded = bech32::Encode(bech32::Encoding::BECH32M, hrp, decoded.data);
        BOOST_REQUIRE(!encoded.empty());
        const std::string payload = Bech32Payload(encoded);
        BOOST_CHECK_EQUAL(payload.size(), 85U);
        BOOST_CHECK(!modelnet::DecodeResource(payload, r, err));
        BOOST_CHECK(!modelnet::DecodeResource("btx://" + payload, r, err));
        BOOST_CHECK(!modelnet::DecodeResource(encoded, r, err));
        BOOST_CHECK(!modelnet::DecodeResource("btx://" + encoded, r, err));
    }

    const std::string token = vectors["resource_vectors"][0]["token"].get_str();
    BOOST_CHECK(!modelnet::DecodeResource("btc://" + token, r, err));

    const std::string legacy = bech32::Encode(bech32::Encoding::BECH32, "btx", decoded.data);
    BOOST_REQUIRE(!legacy.empty());
    const std::string legacy_token = Bech32Payload(legacy);
    BOOST_CHECK_EQUAL(legacy_token.size(), 85U);
    BOOST_CHECK(!modelnet::DecodeResource(legacy_token, r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + legacy_token, r, err));
}

BOOST_AUTO_TEST_CASE(uri_truncated_payload_rejected)
{
    const UniValue vectors = LoadVectors();
    const std::string uri = vectors["resource_vectors"][0]["uri"].get_str();
    const std::string token = vectors["resource_vectors"][0]["token"].get_str();
    const std::string internal = vectors["resource_vectors"][0]["internal_bech32m"].get_str();
    modelnet::Resource r;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeResource(uri.substr(0, uri.size() - 1), r, err));
    BOOST_CHECK(!modelnet::DecodeResource(token.substr(0, 84), r, err));
    BOOST_CHECK(!modelnet::DecodeResource(token.substr(0, 40), r, err));
    BOOST_CHECK(!modelnet::DecodeResource(internal.substr(0, internal.size() - 1), r, err));
    BOOST_CHECK(!modelnet::DecodeResource(std::string{}, r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(std::string(modelnet::MAX_URI_INPUT + 1, 'q'), r, err));

    const auto decoded = bech32::Decode(internal, bech32::CharLimit::BECH32);
    BOOST_REQUIRE(decoded.encoding == bech32::Encoding::BECH32M);
    BOOST_REQUIRE(decoded.data.size() > 2);
    auto short_data = decoded.data;
    short_data.pop_back();
    const std::string short_enc = bech32::Encode(bech32::Encoding::BECH32M, "btx", short_data);
    BOOST_REQUIRE(!short_enc.empty());
    BOOST_CHECK(!modelnet::DecodeResource(short_enc, r, err));
    BOOST_CHECK(!modelnet::DecodeResource(Bech32Payload(short_enc), r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://" + Bech32Payload(short_enc), r, err));

    const std::string tiny = bech32::Encode(bech32::Encoding::BECH32M, "btx", {modelnet::RESOURCE_VERSION});
    BOOST_REQUIRE(!tiny.empty());
    BOOST_CHECK(!modelnet::DecodeResource(tiny, r, err));
    BOOST_CHECK(!modelnet::DecodeResource(Bech32Payload(tiny), r, err));
}

BOOST_AUTO_TEST_CASE(uri_decode_token_vs_uri)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["resource_vectors"].getValues()) {
        const std::string uri = v["uri"].get_str();
        const std::string token = v["token"].get_str();
        BOOST_CHECK_EQUAL(token, uri.substr(6));
        BOOST_CHECK_EQUAL(uri.size(), 91U);
        BOOST_CHECK_EQUAL(token.size(), 85U);
        BOOST_CHECK_EQUAL(v["internal_bech32m"].get_str().size(), 89U);

        modelnet::Resource from_uri, from_token, from_colon, from_slash;
        std::string err;
        BOOST_REQUIRE(modelnet::DecodeResource(uri, from_uri, err));
        BOOST_REQUIRE(modelnet::DecodeResource(token, from_token, err));
        BOOST_REQUIRE(modelnet::DecodeResource("btx:" + token, from_colon, err));
        BOOST_REQUIRE(modelnet::DecodeResource(uri + "/", from_slash, err));
        BOOST_CHECK(from_uri.kind == from_token.kind);
        BOOST_CHECK(from_uri.digest == from_token.digest);
        BOOST_CHECK(from_uri.digest == from_colon.digest);
        BOOST_CHECK(from_uri.digest == from_slash.digest);
        BOOST_CHECK_EQUAL(from_uri.Uri(), uri);
        BOOST_CHECK_EQUAL(from_token.Uri(), uri);
        BOOST_CHECK_EQUAL(from_colon.Uri(), uri);
        BOOST_CHECK_EQUAL(from_slash.Uri(), uri);
        BOOST_CHECK_EQUAL(from_uri.digest.Hex(), v["digest"].get_str());
        BOOST_CHECK_EQUAL(static_cast<int>(from_uri.kind), v["kind"].getInt<int>());
    }
}

BOOST_AUTO_TEST_CASE(resolve_incomplete_local_catalog)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modelnet-uri-resolve";
    modelnet::ModelCatalog cat{tmp, /*quota*/ 8 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "resolveresource");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["coverage"].get_str(), "incomplete");
    BOOST_CHECK_EQUAL(result["local_count"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(result["remote_count"].getInt<int>(), 0);
    BOOST_REQUIRE(result.exists("models"));
    BOOST_CHECK_EQUAL(result["models"].size(), 0);

    WriteTinySafetensors(tmp / "src");
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(tmp / "src"), /*pin=*/true, imported, err), err);

    UniValue listed;
    BOOST_REQUIRE(cat.List(listed));
    BOOST_CHECK_EQUAL(listed["local_count"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(listed["coverage"].get_str(), "incomplete");

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["coverage"].get_str(), "incomplete");
    BOOST_CHECK_EQUAL(result["remote_count"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(result["local_count"].getInt<int>(), listed["local_count"].getInt<int>());
    BOOST_REQUIRE(result.exists("models"));
    BOOST_CHECK_EQUAL(result["models"].size(), 1);
    BOOST_CHECK_EQUAL(result["models"][0]["model_id"].get_str(), imported.model_id.Hex());
    BOOST_CHECK_EQUAL(result["models"][0]["artifact_id"].get_str(), imported.artifact_id.Hex());

    UniValue typed(UniValue::VOBJ);
    typed.pushKV("method", "resolveresource");
    UniValue params(UniValue::VARR);
    UniValue query(UniValue::VOBJ);
    query.pushKV("digest48", imported.model_id.Hex());
    params.push_back(query);
    typed.pushKV("params", params);
    UniValue typed_result;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, typed, typed_result, code, err));
    BOOST_CHECK_EQUAL(typed_result["coverage"].get_str(), "incomplete");
    BOOST_CHECK_EQUAL(typed_result["local_count"].getInt<int>(), 1);
}

BOOST_AUTO_TEST_CASE(decode_object_matches_decode_resource)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["resource_vectors"].getValues()) {
        const std::string uri = v["uri"].get_str();
        const std::string token = v["token"].get_str();
        modelnet::Resource r;
        std::string err;
        BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
        BOOST_REQUIRE(modelnet::DecodeResource(token, r, err));

        modelnet::BrowserBridgeResponse br;
        BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + token, br));
        BOOST_CHECK_EQUAL(br.http_status, 200);
        const UniValue obj = ParseBridge(br);
        BOOST_CHECK_EQUAL(obj["canonical"].get_str(), r.Uri());
        BOOST_CHECK_EQUAL(obj["open_in_btx"].get_str(), r.Uri());
        BOOST_CHECK_EQUAL(obj["digest"].get_str(), r.digest.Hex());
        BOOST_CHECK_EQUAL(obj["kind"].get_str(), modelnet::ResourceKindName(r.kind));
        BOOST_CHECK_EQUAL(obj["kind"].get_str(), v["name"].get_str());
        BOOST_CHECK_EQUAL(obj["digest"].get_str(), v["digest"].get_str());
        BOOST_CHECK_EQUAL(br.canonical_btx, uri);

        BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br));
        BOOST_CHECK_EQUAL(br.http_status, 200);
        const UniValue via_open = ParseBridge(br);
        BOOST_CHECK_EQUAL(via_open["kind"].get_str(), obj["kind"].get_str());
        BOOST_CHECK_EQUAL(via_open["digest"].get_str(), obj["digest"].get_str());
        BOOST_CHECK_EQUAL(via_open["canonical"].get_str(), uri);
    }

    modelnet::Digest48 d{};
    for (size_t i = 0; i < d.data.size(); ++i) d.data[i] = static_cast<unsigned char>(i + 3);
    std::string model_uri, artifact_uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, d, model_uri, err));
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::ARTIFACT, d, artifact_uri, err));
    BOOST_CHECK(model_uri != artifact_uri);

    modelnet::Resource model_r, artifact_r;
    BOOST_REQUIRE(modelnet::DecodeResource(model_uri, model_r, err));
    BOOST_REQUIRE(modelnet::DecodeResource(artifact_uri, artifact_r, err));
    BOOST_CHECK(model_r.kind == modelnet::ResourceKind::MODEL);
    BOOST_CHECK(artifact_r.kind == modelnet::ResourceKind::ARTIFACT);
    BOOST_CHECK(model_r.digest == artifact_r.digest);

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + model_uri.substr(6), br));
    BOOST_CHECK_EQUAL(ParseBridge(br)["kind"].get_str(), "MODEL");
    BOOST_CHECK_EQUAL(ParseBridge(br)["digest"].get_str(), d.Hex());
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + artifact_uri.substr(6), br));
    BOOST_CHECK_EQUAL(ParseBridge(br)["kind"].get_str(), "ARTIFACT");
    BOOST_CHECK_EQUAL(ParseBridge(br)["digest"].get_str(), d.Hex());
    BOOST_CHECK(ParseBridge(br)["canonical"].get_str() != model_uri);

    const std::string truncated = vectors["resource_vectors"][0]["token"].get_str().substr(0, 80);
    BOOST_CHECK(!modelnet::DecodeResource(truncated, model_r, err));
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + truncated, br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
}

BOOST_AUTO_TEST_CASE(uri_14_short_display_copy_is_full_canonical)
{
    modelnet::Digest48 d{};
    d.data[0] = 0x7e;
    std::string uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, d, uri, err));
    const std::string display = modelnet::ShortDisplayUri(uri);
    const std::string copy = modelnet::CopyUri(uri);
    BOOST_CHECK(!display.empty());
    BOOST_CHECK(display != uri);
    BOOST_CHECK(display.find("...") != std::string::npos);
    BOOST_CHECK(display.size() < uri.size());
    BOOST_CHECK_EQUAL(copy, uri);
    BOOST_CHECK_EQUAL(modelnet::CopyUri(copy), uri);
    modelnet::Resource r;
    BOOST_CHECK(!modelnet::DecodeResource(display, r, err));
    BOOST_CHECK(modelnet::CopyUri(display).empty());
    BOOST_CHECK(modelnet::ShortDisplayUri("not-a-uri").empty());
}

BOOST_AUTO_TEST_SUITE_END()
