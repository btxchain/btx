// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bridge.h>
#include <modelnet/http_bridge.h>
#include <modelnet/resource_uri.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_bridge_tests, BasicTestingSetup)

static UniValue LoadVectors()
{
    std::ifstream in{MODELNET_V11_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    return v;
}

static std::string FirstVectorUri()
{
    return LoadVectors()["resource_vectors"][0]["uri"].get_str();
}

static bool IEquals(std::string_view a, std::string_view b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/** Mixed-case disclosure fields: accept pq_end_to_end or PQ_End_To_End etc. */
static bool HasBoolCI(const UniValue& obj, std::string_view name, bool expected)
{
    BOOST_REQUIRE(obj.isObject());
    for (const auto& key : obj.getKeys()) {
        if (!IEquals(key, name)) continue;
        const UniValue& v = obj[key];
        return v.isBool() && v.get_bool() == expected;
    }
    return false;
}

static UniValue ParseBody(const modelnet::BrowserBridgeResponse& br)
{
    BOOST_CHECK_EQUAL(br.content_type, "application/json");
    UniValue obj;
    BOOST_REQUIRE(obj.read(br.body));
    BOOST_REQUIRE(obj.isObject());
    return obj;
}

static void CheckDisclosure(const UniValue& obj)
{
    BOOST_CHECK(HasBoolCI(obj, "pq_end_to_end", false));
    BOOST_CHECK(HasBoolCI(obj, "native_fallback", false));
    BOOST_CHECK(HasBoolCI(obj, "wallet", false));
}

static void CheckNativeFallbackNotTrue(const modelnet::BrowserBridgeResponse& br)
{
    const UniValue obj = ParseBody(br);
    BOOST_CHECK(HasBoolCI(obj, "native_fallback", false));
    BOOST_CHECK(!HasBoolCI(obj, "native_fallback", true));
    std::string lower = br.body;
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    BOOST_CHECK(lower.find("\"native_fallback\":true") == std::string::npos);
    BOOST_CHECK(lower.find("\"native_fallback\": true") == std::string::npos);
}

static void CheckNeverPqEndToEndTrue(const modelnet::BrowserBridgeResponse& br)
{
    BOOST_REQUIRE(!br.body.empty());
    const UniValue obj = ParseBody(br);
    BOOST_CHECK(HasBoolCI(obj, "pq_end_to_end", false));
    BOOST_CHECK(!HasBoolCI(obj, "pq_end_to_end", true));
    std::string lower = br.body;
    for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    BOOST_CHECK(lower.find("\"pq_end_to_end\":true") == std::string::npos);
    BOOST_CHECK(lower.find("\"pq_end_to_end\": true") == std::string::npos);
}

static void CheckJsonPreviewNotModelBytes(const modelnet::BrowserBridgeResponse& br)
{
    BOOST_CHECK_EQUAL(br.content_type, "application/json");
    BOOST_CHECK(br.content_type.find("octet-stream") == std::string::npos);
    BOOST_REQUIRE(!br.body.empty());
    BOOST_CHECK_EQUAL(br.body.front(), '{');
    CheckDisclosure(ParseBody(br));
}

class EnvRestore
{
public:
    explicit EnvRestore(std::string key) : m_key(std::move(key))
    {
        if (const char* v = std::getenv(m_key.c_str())) {
            m_prev = std::string{v};
        }
    }
    ~EnvRestore()
    {
        if (m_prev) {
            setenv(m_key.c_str(), m_prev->c_str(), 1);
        } else {
            unsetenv(m_key.c_str());
        }
    }
    void Set(const char* v) { setenv(m_key.c_str(), v, 1); }
    void Unset() { unsetenv(m_key.c_str()); }

private:
    std::string m_key;
    std::optional<std::string> m_prev;
};

BOOST_AUTO_TEST_CASE(api_v1_search_readonly_json)
{
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/api/v1/search?q=test", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.ok);
    UniValue obj = ParseBody(br);
    CheckDisclosure(obj);
    BOOST_CHECK_EQUAL(obj["schema_version"].getInt<int>(), 2);
    BOOST_CHECK(HasBoolCI(obj, "authoritative", false));
    BOOST_CHECK(HasBoolCI(obj, "global_complete", false));
    BOOST_REQUIRE(obj.exists("results"));
    BOOST_CHECK(obj["results"].isArray());
    BOOST_CHECK_EQUAL(obj["results"].size(), 0U);

    const std::string uri = FirstVectorUri();
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/api/v1/search?q=" + uri, br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    obj = ParseBody(br);
    CheckDisclosure(obj);
    BOOST_REQUIRE(obj["results"].isArray());
    BOOST_CHECK_EQUAL(obj["results"].size(), 1U);
    BOOST_CHECK_EQUAL(obj["results"][0]["canonical"].get_str(), uri);
}

BOOST_AUTO_TEST_CASE(api_v1_models_hex_id_non_btx_is_400)
{
    const std::string uri = FirstVectorUri();
    modelnet::BrowserBridgeResponse decoded;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, decoded));
    const std::string hex_id = ParseBody(decoded)["digest"].get_str();

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/api/v1/models/" + hex_id, br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));
}

BOOST_AUTO_TEST_CASE(malformed_uri_is_400)
{
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/not-a-token", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=not-a-token", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
}

BOOST_AUTO_TEST_CASE(valid_uri_returns_canonical)
{
    const std::string uri = FirstVectorUri();
    const std::string token = uri.substr(6);

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + token, br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.ok);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
    UniValue obj = ParseBody(br);
    BOOST_CHECK_EQUAL(obj["canonical"].get_str(), uri);
    CheckDisclosure(obj);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + uri, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
    obj = ParseBody(br);
    BOOST_CHECK_EQUAL(obj["canonical"].get_str(), uri);
    BOOST_CHECK_EQUAL(obj["open_in_btx"].get_str(), uri);
    CheckDisclosure(obj);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + token, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
}

BOOST_AUTO_TEST_CASE(wallet_paths_refused)
{
    modelnet::BrowserBridgeResponse br;
    const char* get_paths[] = {"/wallet", "/sign", "/dump", "/Wallet", "/dumpwallet", "/signraw"};
    for (const char* p : get_paths) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", p, "", br));
        BOOST_CHECK_MESSAGE(br.http_status == 403 || br.http_status == 404,
                            std::string("GET ") + p + " status=" + std::to_string(br.http_status));
        BOOST_CHECK(!br.ok);
        CheckDisclosure(ParseBody(br));
    }

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/wallet", "{}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/open", "{\"method\":\"dumpwallet\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("PUT", "/sign", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("DELETE", "/dump", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
}

BOOST_AUTO_TEST_CASE(mixed_case_disclosure_fields_present)
{
    const std::string uri = FirstVectorUri();
    modelnet::BrowserBridgeResponse br;

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GeT", "/HeAlTh", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/OPEN?URI=" + uri, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
    const UniValue obj = ParseBody(br);
    CheckDisclosure(obj);
    BOOST_CHECK(HasBoolCI(obj, "PQ_END_TO_END", false));
    BOOST_CHECK(HasBoolCI(obj, "Native_Fallback", false));
    BOOST_CHECK(HasBoolCI(obj, "Wallet", false));
}

// Remaining V11-BRIDGE IDs (01/03/05/08–09/12 covered by prior cases or other suites):
// V11-BRIDGE-02  native_pq_failure_does_not_set_native_fallback
// V11-BRIDGE-04  overlong_hostname_token_rejected
// V11-BRIDGE-06  wildcard_cert_depth_is_zero
// V11-BRIDGE-07  public_download_default_false_never_fetches
// V11-BRIDGE-08  get_wallet_403_post_sign_405_dump_403
// V11-BRIDGE-09  rejects_http_file_and_arbitrary_ips
// V11-BRIDGE-10  byte_range_maps_to_pieces_json_only
// V11-BRIDGE-11  cache_key_uses_full_canonical_uri
// V11-BRIDGE-12  body_never_claims_pq_end_to_end_true

BOOST_AUTO_TEST_CASE(native_pq_failure_does_not_set_native_fallback)
{
    const std::string uri = FirstVectorUri();
    auto& native = modelnet::GetModelBridge();
    const auto prev = native.SnapshotStatus();
    struct RestoreNative {
        modelnet::ModelStatus prev;
        ~RestoreNative()
        {
            modelnet::GetModelBridge().SetHelperReady(prev.helper_ready, prev.pq1_ready, prev.helper_error);
        }
    } restore{prev};
    native.SetHelperReady(false, false, "pq1 handshake failed");
    BOOST_CHECK(!native.SnapshotStatus().pq1_ready);
    BOOST_CHECK(!native.SnapshotStatus().helper_ready);

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/health", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckNativeFallbackNotTrue(br);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + uri, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckNativeFallbackNotTrue(br);
    BOOST_CHECK(br.canonical_btx.find("https://") == std::string::npos);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/not-a-token", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    CheckNativeFallbackNotTrue(br);

    std::string dummy, err;
    BOOST_CHECK(!modelnet::BridgePath(uri, "http://bridge.example.org", dummy, err));
    BOOST_CHECK(!modelnet::BridgePath(uri, "http://127.0.0.1", dummy, err));
    BOOST_CHECK(!modelnet::BridgePath(uri, "http://8.8.8.8", dummy, err));
}

BOOST_AUTO_TEST_CASE(overlong_hostname_token_rejected)
{
    const std::string uri = FirstVectorUri();
    const std::string token = uri.substr(6);
    BOOST_REQUIRE_EQUAL(token.size(), 85U);
    BOOST_CHECK(token.size() > 63U); // DNS label limit; single-label full token is overlong

    modelnet::BrowserBridgeResponse br;
    modelnet::Resource r;
    std::string err;
    BOOST_CHECK(!modelnet::DecodeResource(token + "x", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(std::string(modelnet::MAX_URI_INPUT + 1, 'q'), r, err));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + uri + "x", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/" + token + "extra", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=https://" + token, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_CHECK(!br.ok);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "https://" + token + ".example.org/", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));

    const std::string label64(64, 'a');
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=https://" + label64, "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + std::string(modelnet::MAX_URI_INPUT + 1, 'q'), "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
}

BOOST_AUTO_TEST_CASE(get_wallet_403_post_sign_405_dump_403)
{
    modelnet::BrowserBridgeResponse br;

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/wallet", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/sign", "{}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/dump", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_CHECK(!br.ok);
    CheckDisclosure(ParseBody(br));
}

BOOST_AUTO_TEST_CASE(rejects_http_file_and_arbitrary_ips)
{
    modelnet::BrowserBridgeResponse br;
    const char* banned[] = {
        "http://127.0.0.1",
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "file://",
        "file:///",
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "http://8.8.8.8",
        "http://8.8.8.8/secret",
        "http://1.2.3.4",
        "https://203.0.113.1/f/0",
        "http://[::1]/",
        "/open?uri=http://127.0.0.1",
        "/open?uri=file://",
        "/open?uri=file:///etc/passwd",
        "/open?uri=http://8.8.8.8/",
        "/open?uri=1.2.3.4",
        "/open?uri=https://198.51.100.10/manifest",
    };
    for (const char* p : banned) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", p, "", br));
        BOOST_CHECK_MESSAGE(br.http_status != 200,
                            std::string("GET ") + p + " status=" + std::to_string(br.http_status));
        BOOST_CHECK(!br.ok);
        BOOST_CHECK(br.canonical_btx.empty());
        CheckDisclosure(ParseBody(br));
        BOOST_CHECK(br.http_status == 400 || br.http_status == 403 || br.http_status == 404);
    }

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=http://127.0.0.1", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=file://", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
}

BOOST_AUTO_TEST_CASE(body_never_claims_pq_end_to_end_true)
{
    const std::string uri = FirstVectorUri();
    const std::string token = uri.substr(6);
    modelnet::BrowserBridgeResponse br;

    const std::vector<std::pair<std::string, std::string>> reqs = {
        {"GET", "/health"},
        {"HEAD", "/health"},
        {"GET", "/open?uri=" + uri},
        {"GET", "/open?uri=" + token},
        {"GET", "/" + token},
        {"GET", "/open"},
        {"GET", "/not-a-token"},
        {"GET", "/wallet"},
        {"POST", "/sign"},
        {"GET", "/dump"},
        {"POST", "/open"},
        {"GET", "http://127.0.0.1"},
        {"GET", "file://"},
        {"GET", "/open?uri=http://8.8.8.8"},
        {"GET", "/open?uri=" + std::string(86, 'q')},
        {"PUT", "/health"},
    };
    for (const auto& [method, path] : reqs) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest(method, path, "", br));
        CheckNeverPqEndToEndTrue(br);
        CheckDisclosure(ParseBody(br));
    }
}

BOOST_AUTO_TEST_CASE(wildcard_cert_depth_is_zero)
{
    BOOST_CHECK_EQUAL(modelnet::BridgeTlsMaxWildcardDepth(), 0);

    EnvRestore env{"BTX_BRIDGE_PUBLIC_DOWNLOAD"};
    env.Unset();

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    const UniValue obj = ParseBody(br);
    CheckDisclosure(obj);
    BOOST_REQUIRE(obj.exists("wildcard_dns_depth"));
    BOOST_CHECK(obj["wildcard_dns_depth"].isNum());
    BOOST_CHECK_EQUAL(obj["wildcard_dns_depth"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(obj["wildcard_dns_depth"].getInt<int>(), modelnet::BridgeTlsMaxWildcardDepth());
    BOOST_CHECK_EQUAL(obj["bind_default"].get_str(), "127.0.0.1");
    BOOST_CHECK(HasBoolCI(obj, "catalog_browser_bridge", false));

    bool saw_csp = false;
    bool saw_nosniff = false;
    for (const auto& h : br.headers) {
        if (h.first == "Content-Security-Policy" && h.second.find("default-src 'none'") != std::string::npos) {
            saw_csp = true;
        }
        if (h.first == "X-Content-Type-Options" && h.second == "nosniff") saw_nosniff = true;
    }
    BOOST_CHECK(saw_csp);
    BOOST_CHECK(saw_nosniff);
}

BOOST_AUTO_TEST_CASE(dns_split_42_43_labels_and_join)
{
    const std::string uri = FirstVectorUri();
    const std::string token = uri.substr(6);
    BOOST_REQUIRE_EQUAL(token.size(), 85U);
    BOOST_CHECK(token.size() > 63U);

    std::string left, right;
    BOOST_REQUIRE(modelnet::DnsSplit42_43(token, left, right));
    BOOST_CHECK_EQUAL(left.size(), 42U);
    BOOST_CHECK_EQUAL(right.size(), 43U);
    BOOST_CHECK_EQUAL(left + right, token);
    BOOST_CHECK_LT(left.size(), 63U);
    BOOST_CHECK_LE(right.size(), 63U);

    const std::string host = modelnet::DnsSplitJoin(left, right, "split.example");
    BOOST_CHECK_EQUAL(host, left + "." + right + ".split.example");

    std::string left_uri, right_uri;
    BOOST_REQUIRE(modelnet::DnsSplit42_43(uri, left_uri, right_uri));
    BOOST_CHECK_EQUAL(left, left_uri);
    BOOST_CHECK_EQUAL(right, right_uri);

    std::string split_host, err;
    BOOST_REQUIRE(modelnet::SplitBridgeHost(uri, "bridge.example.org", split_host, err));
    BOOST_CHECK_EQUAL(split_host, modelnet::DnsSplitJoin(left, right, "bridge.example.org"));
    BOOST_CHECK_EQUAL(modelnet::DnsSplitJoin(left, right, ".bridge.example.org."), split_host);

    std::string bad_left, bad_right;
    BOOST_CHECK(!modelnet::DnsSplit42_43(token + "x", bad_left, bad_right));
    BOOST_CHECK(!modelnet::DnsSplit42_43(token.substr(0, 84), bad_left, bad_right));
    BOOST_CHECK(!modelnet::DnsSplit42_43("", bad_left, bad_right));
    BOOST_CHECK(modelnet::DnsSplitJoin(left, right, "").empty());
    BOOST_CHECK(modelnet::DnsSplitJoin("short", right, "split.example").empty());
}

BOOST_AUTO_TEST_CASE(byte_range_maps_to_pieces_json_only)
{
    uint32_t first = 99;
    uint32_t count = 99;
    BOOST_REQUIRE(modelnet::BridgeRangeToPieces(0, modelnet::PIECE_SIZE - 1, modelnet::PIECE_SIZE, first, count));
    BOOST_CHECK_EQUAL(first, 0u);
    BOOST_CHECK_EQUAL(count, 1u);

    BOOST_REQUIRE(modelnet::BridgeRangeToPieces(0, modelnet::PIECE_SIZE, modelnet::PIECE_SIZE, first, count));
    BOOST_CHECK_EQUAL(first, 0u);
    BOOST_CHECK_EQUAL(count, 2u);

    BOOST_REQUIRE(modelnet::BridgeRangeToPieces(modelnet::PIECE_SIZE, 2 * modelnet::PIECE_SIZE - 1,
                                                modelnet::PIECE_SIZE, first, count));
    BOOST_CHECK_EQUAL(first, 1u);
    BOOST_CHECK_EQUAL(count, 1u);

    first = 7;
    count = 7;
    BOOST_CHECK(!modelnet::BridgeRangeToPieces(10, 9, modelnet::PIECE_SIZE, first, count));
    BOOST_CHECK(!modelnet::BridgeRangeToPieces(0, 100, 0, first, count));

    const std::string uri = FirstVectorUri();
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri + "&Range=bytes=0-100", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
    CheckJsonPreviewNotModelBytes(br);

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br, "Range: bytes=0-4194303\r\n"));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckJsonPreviewNotModelBytes(br);

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/open?uri=" + uri, "", br,
                                                "Range: bytes=0-" + std::to_string(modelnet::PIECE_SIZE - 1)));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckJsonPreviewNotModelBytes(br);

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + uri.substr(6) + "?range=bytes=0-1", br, "Range: bytes=0-1"));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    CheckJsonPreviewNotModelBytes(br);
}

BOOST_AUTO_TEST_CASE(cache_key_uses_full_canonical_uri)
{
    const UniValue vec = LoadVectors();
    const std::string uri_a = vec["resource_vectors"][0]["uri"].get_str();
    const std::string uri_b = vec["resource_vectors"][1]["uri"].get_str();
    BOOST_REQUIRE(uri_a != uri_b);
    BOOST_REQUIRE_GT(uri_a.size(), 42U);

    const std::string key_a0 = modelnet::BridgeCacheKey(uri_a, 0);
    const std::string key_a1 = modelnet::BridgeCacheKey(uri_a, 1);
    const std::string key_b0 = modelnet::BridgeCacheKey(uri_b, 0);

    BOOST_CHECK(key_a0.find(uri_a) != std::string::npos);
    BOOST_CHECK(key_b0.find(uri_b) != std::string::npos);
    BOOST_CHECK(key_a0 != key_b0);
    BOOST_CHECK(key_a0 != key_a1);

    // Tokens that share a 42-char DNS-split prefix must still not collide.
    const std::string prefix42(42, 'q');
    const std::string u1 = "btx://" + prefix42 + std::string(43, 'a');
    const std::string u2 = "btx://" + prefix42 + std::string(43, 'b');
    BOOST_CHECK(modelnet::BridgeCacheKey(u1, 0) != modelnet::BridgeCacheKey(u2, 0));
    BOOST_CHECK(modelnet::BridgeCacheKey(u1, 0).find(u1) != std::string::npos);
    BOOST_CHECK(modelnet::BridgeCacheKey(u1, 0).find(std::string(43, 'a')) != std::string::npos);

    // HandleBridgeGet stays stateless: two GETs are JSON previews, not a byte cache.
    modelnet::BrowserBridgeResponse first;
    modelnet::BrowserBridgeResponse second;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri_a, first));
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri_a, second));
    CheckJsonPreviewNotModelBytes(first);
    CheckJsonPreviewNotModelBytes(second);
    BOOST_CHECK_EQUAL(first.body, second.body);
}

BOOST_AUTO_TEST_CASE(public_download_default_false_never_fetches)
{
    EnvRestore env{"BTX_BRIDGE_PUBLIC_DOWNLOAD"};
    env.Unset();
    BOOST_CHECK(!modelnet::BridgePublicDownloadEnabled());

    modelnet::BrowserBridgeResponse health;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", health));
    UniValue obj = ParseBody(health);
    CheckDisclosure(obj);
    BOOST_REQUIRE(obj.exists("public_download"));
    BOOST_CHECK(obj["public_download"].isBool());
    BOOST_CHECK_EQUAL(obj["public_download"].get_bool(), false);
    BOOST_CHECK_EQUAL(obj["bind_default"].get_str(), "127.0.0.1");

    env.Set("true");
    BOOST_CHECK(!modelnet::BridgePublicDownloadEnabled());
    env.Set("1");
    BOOST_CHECK(modelnet::BridgePublicDownloadEnabled());

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", health));
    obj = ParseBody(health);
    BOOST_CHECK_EQUAL(obj["public_download"].get_bool(), true);
    CheckDisclosure(obj);

    const std::string uri = FirstVectorUri();
    modelnet::BrowserBridgeResponse open;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, open, "Range: bytes=0-100"));
    BOOST_CHECK_EQUAL(open.http_status, 200);
    CheckJsonPreviewNotModelBytes(open);
    BOOST_CHECK(!ParseBody(open).exists("download"));
    BOOST_CHECK(!ParseBody(open).exists("download_enabled"));

    env.Unset();
    BOOST_CHECK(!modelnet::BridgePublicDownloadEnabled());
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/health", health));
    BOOST_CHECK_EQUAL(ParseBody(health)["public_download"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(link_only_html_landing)
{
    const std::string uri = FirstVectorUri();
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri + "&format=html", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.content_type.find("text/html") != std::string::npos);
    BOOST_CHECK(br.body.find("LINK_ONLY") != std::string::npos);
    BOOST_CHECK(br.body.find("Open in BTX") != std::string::npos);
    BOOST_CHECK(br.body.find(uri) != std::string::npos);
    BOOST_CHECK(br.body.find("NOT NATIVE END-TO-END PQ") != std::string::npos);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);

    BOOST_REQUIRE(modelnet::HandleBridgeGet("/open?uri=" + uri, br, "Accept: text/html\r\n"));
    BOOST_CHECK(br.content_type.find("text/html") != std::string::npos);
    BOOST_CHECK(br.body.find("Open in BTX") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(public_download_verified_chunks_before_emission)
{
    EnvRestore env{"BTX_BRIDGE_PUBLIC_DOWNLOAD"};
    env.Unset();
    const std::string uri = FirstVectorUri();
    const std::string token = uri.substr(6);
    const std::string file_path = "/" + token + "/f/0";
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet(file_path, br));
    BOOST_CHECK_EQUAL(br.http_status, 403);

    const unsigned char verified[] = {1, 2, 3, 4, 5, 6, 7, 8};
    BOOST_REQUIRE(modelnet::HandleBridgePublicFile(file_path, "Range: bytes=0-3\r\n",
                                                  Span<const unsigned char>{verified, sizeof(verified)}, br));
    BOOST_CHECK_EQUAL(br.http_status, 403);

    env.Set("1");
    BOOST_REQUIRE(modelnet::HandleBridgeGet(file_path, br));
    BOOST_CHECK_EQUAL(br.http_status, 409);
    BOOST_CHECK_EQUAL(br.content_type, "application/json");

    BOOST_REQUIRE(modelnet::HandleBridgePublicFile(file_path, "", Span<const unsigned char>{}, br));
    BOOST_CHECK_EQUAL(br.http_status, 409);

    BOOST_REQUIRE(modelnet::HandleBridgePublicFile(file_path, "Range: bytes=2-5\r\n",
                                                  Span<const unsigned char>{verified, sizeof(verified)}, br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.content_type, "application/octet-stream");
    BOOST_CHECK_EQUAL(br.body.size(), 4U);
    BOOST_CHECK_EQUAL(static_cast<unsigned char>(br.body[0]), 3);
    bool saw_nosniff = false, saw_csp = false, saw_attach = false, saw_web = false;
    for (const auto& h : br.headers) {
        if (h.first == "X-Content-Type-Options" && h.second == "nosniff") saw_nosniff = true;
        if (h.first == "Content-Security-Policy") saw_csp = true;
        if (h.first == "Content-Disposition" && h.second == "attachment") saw_attach = true;
        if (h.first == "X-BTX-Web-Compatibility") saw_web = true;
    }
    BOOST_CHECK(saw_nosniff);
    BOOST_CHECK(saw_csp);
    BOOST_CHECK(saw_attach);
    BOOST_CHECK(saw_web);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);
}

BOOST_AUTO_TEST_SUITE_END()
