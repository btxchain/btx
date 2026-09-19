// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/http_bridge.h>
#include <modelnet/helper.h>

#include <common/url.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace modelnet {
namespace {

constexpr const char* BRIDGE_NOTE =
    "HTTP bridge is not the identity authority; verify native hash. "
    "Browser edge is not end-to-end PQ. Upstream to BTX remains PQ1 or unix RPC.";

constexpr const char* PUBLIC_DOWNLOAD_ENV = "BTX_BRIDGE_PUBLIC_DOWNLOAD";
constexpr const char* BRIDGE_RPC_ENV = "BTX_BRIDGE_RPC_SOCKET";

bool BridgeReadRpc(const std::string& method, const UniValue& params, UniValue& result)
{
    const char* sock = std::getenv(BRIDGE_RPC_ENV);
    if (sock == nullptr || sock[0] == '\0') return false;
    std::string err;
    return CallUnixRpc(fs::PathFromString(sock), method, params, result, err);
}

constexpr const char* WEB_COMPAT =
    "WEB COMPATIBILITY - NOT NATIVE END-TO-END PQ";

constexpr const char* API_V1_RPC_NOTE =
    "Browser bridge has no catalog. Use btx-modeld unix RPC "
    "(searchmodels, getmodeldirectoryentry, getmodeldirectory, getnetworkmodelstats, ...).";

std::string TrimCopy(std::string s);
std::string PathOnly(const std::string& path);
std::string QueryParam(const std::string& path, const std::string& key);

bool HeaderHas(const std::string& headers, const std::string& name, const std::string& needle)
{
    size_t i = 0;
    while (i < headers.size()) {
        size_t line_end = headers.find('\n', i);
        if (line_end == std::string::npos) line_end = headers.size();
        std::string line = headers.substr(i, line_end - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        const std::string hname = ToLower(TrimCopy(colon == std::string::npos ? line : line.substr(0, colon)));
        const std::string hval = colon == std::string::npos ? std::string{} : ToLower(TrimCopy(line.substr(colon + 1)));
        if (hname == ToLower(name) && hval.find(ToLower(needle)) != std::string::npos) return true;
        i = line_end + 1;
    }
    return false;
}

bool WantsHtml(const std::string& path, const std::string& headers)
{
    if (QueryParam(path, "format") == "html") return true;
    return HeaderHas(headers, "accept", "text/html");
}

bool ParseInclusiveRange(const std::string& path, const std::string& headers,
                          uint64_t size, uint64_t& first, uint64_t& last)
{
    first = 0;
    last = size ? size - 1 : 0;
    std::string spec = QueryParam(path, "range");
    if (spec.empty()) {
        size_t i = 0;
        while (i < headers.size()) {
            size_t line_end = headers.find('\n', i);
            if (line_end == std::string::npos) line_end = headers.size();
            std::string line = headers.substr(i, line_end - i);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const auto colon = line.find(':');
            const std::string name = ToLower(TrimCopy(colon == std::string::npos ? line : line.substr(0, colon)));
            if (name == "range") {
                spec = colon == std::string::npos ? std::string{} : TrimCopy(line.substr(colon + 1));
                break;
            }
            i = line_end + 1;
        }
    }
    if (spec.empty() || size == 0) return true;
    if (spec.rfind("bytes=", 0) == 0) spec = spec.substr(6);
    const auto dash = spec.find('-');
    if (dash == std::string::npos) return false;
    const uint64_t a = spec.substr(0, dash).empty() ? 0 : std::strtoull(spec.c_str(), nullptr, 10);
    const uint64_t b = spec.substr(dash + 1).empty() ? size - 1 : std::strtoull(spec.c_str() + dash + 1, nullptr, 10);
    if (a > last || a > b) return false;
    first = a;
    last = std::min(b, size - 1);
    return first <= last;
}

bool SplitTokenFile(const std::string& path, std::string& token, uint32_t& file_index)
{
    std::string p = PathOnly(path);
    if (!p.empty() && p.front() == '/') p.erase(0, 1);
    const auto fpos = p.find("/f/");
    if (fpos == std::string::npos) return false;
    token = p.substr(0, fpos);
    file_index = static_cast<uint32_t>(std::strtoul(p.c_str() + fpos + 3, nullptr, 10));
    return !token.empty();
}

std::string LinkOnlyHtml(const Resource& r)
{
    const std::string uri = r.Uri();
    return std::string("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
        + "<title>Open in BTX</title>"
        + "<meta name=\"btx-web-compatibility\" content=\"" + WEB_COMPAT + "\">"
        + "</head><body>"
        + "<p>LINK_ONLY</p>"
        + "<p><a href=\"" + uri + "\">Open in BTX</a></p>"
        + "<p><code>" + uri + "</code></p>"
        + "<p>" + WEB_COMPAT + "</p>"
        + "<p>Browser edge is not native end-to-end PQ. Upstream remains PQ1.</p>"
        + "</body></html>";
}

bool FillHtml(BrowserBridgeResponse& out, const Resource& r)
{
    out.ok = true;
    out.http_status = 200;
    out.content_type = "text/html; charset=utf-8";
    out.canonical_btx = r.Uri();
    out.body = LinkOnlyHtml(r);
    out.headers.emplace_back("X-BTX-Web-Compatibility", WEB_COMPAT);
    out.headers.emplace_back("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
    out.headers.emplace_back("X-Content-Type-Options", "nosniff");
    return true;
}

void PushDisclosure(UniValue& obj)
{
    // Disclosed-weaker profile (D09). These three names are canonical; tests
    // also accept mixed-case spellings of the same keys.
    obj.pushKV("pq_end_to_end", false);
    obj.pushKV("native_fallback", false);
    obj.pushKV("wallet", false);
}

bool FillJson(BrowserBridgeResponse& out, int status, UniValue obj, bool ok, std::string canonical = {})
{
    PushDisclosure(obj);
    out.ok = ok;
    out.http_status = status;
    out.content_type = "application/json";
    out.body = obj.write();
    out.canonical_btx = std::move(canonical);
    out.headers.emplace_back("X-Content-Type-Options", "nosniff");
    out.headers.emplace_back("Content-Security-Policy", "default-src 'none'");
    out.headers.emplace_back("X-BTX-Web-Compatibility", WEB_COMPAT);
    return true;
}

std::string PathOnly(const std::string& path)
{
    std::string p = path;
    const auto q = p.find('?');
    if (q != std::string::npos) p.resize(q);
    const auto h = p.find('#');
    if (h != std::string::npos) p.resize(h);
    return p;
}

std::string NormalizedRoute(const std::string& path)
{
    std::string p = ToLower(PathOnly(path));
    if (p.empty()) return "/";
    if (p.front() != '/') p.insert(p.begin(), '/');
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    return p;
}

std::string QueryParam(const std::string& path, const std::string& key)
{
    const auto qpos = path.find('?');
    if (qpos == std::string::npos) return {};
    const std::string query = path.substr(qpos + 1);
    const std::string want = ToLower(key);
    size_t start = 0;
    while (start < query.size()) {
        size_t amp = query.find('&', start);
        if (amp == std::string::npos) amp = query.size();
        const std::string pair = query.substr(start, amp - start);
        const auto eq = pair.find('=');
        const std::string k = ToLower(UrlDecode(eq == std::string::npos ? pair : pair.substr(0, eq)));
        const std::string v = eq == std::string::npos ? std::string{} : UrlDecode(pair.substr(eq + 1));
        if (k == want) return v;
        start = amp + 1;
    }
    return {};
}

bool SegmentLooksWallet(std::string_view seg)
{
    return seg.starts_with("wallet") || seg.starts_with("sign") || seg.starts_with("dump");
}

bool WalletLikePath(const std::string& path)
{
    const std::string p = NormalizedRoute(path);
    if (p.find("preparebounty") != std::string::npos) return true;
    if (p.find("signbounty") != std::string::npos) return true;
    if (p.find("submitbounty") != std::string::npos) return true;
    if (p.find("createagentmandate") != std::string::npos) return true;
    if (p.find("revokeagentmandate") != std::string::npos) return true;
    if (p.find("getagentmandate") != std::string::npos) return true;
    if (p.find("reservemandate") != std::string::npos) return true;
    if (p.find("createsubscriptionmandate") != std::string::npos) return true;
    if (p.find("revokesubscriptionmandate") != std::string::npos) return true;
    if (p.find("getsubscriptionmandate") != std::string::npos) return true;
    if (p.find("getsubscriptionactivity") != std::string::npos) return true;
    if (p.find("reservesubscriptionmandate") != std::string::npos) return true;
    if (p.find("observebountychain") != std::string::npos) return true;
    if (p.find("reorgbountychain") != std::string::npos) return true;
    if (p.find("bountyevaluation") != std::string::npos) return true;
    if (p.find("proposebounty") != std::string::npos) return true;
    if (p.find("approvebounty") != std::string::npos) return true;
    if (p.find("importbounty") != std::string::npos) return true;
    if (p.find("createbountydraft") != std::string::npos) return true;
    if (p.find("listbountydrafts") != std::string::npos) return true;
    if (p.find("getbountydraft") != std::string::npos) return true;
    if (p.find("updatebountydraft") != std::string::npos) return true;
    if (p.find("deletebountydraft") != std::string::npos) return true;
    if (p.find("validatebountyterms") != std::string::npos) return true;
    if (p.find("publishbounty") != std::string::npos) return true;
    size_t i = 0;
    while (i < p.size()) {
        if (p[i] == '/') {
            ++i;
            continue;
        }
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        if (SegmentLooksWallet(std::string_view{p.data() + i, j - i})) return true;
        i = j;
    }
    return false;
}

bool MethodLooksWallet(const std::string& method)
{
    const std::string m = ToLower(method);
    if (m.empty()) return false;
    if (m.find("wallet") != std::string::npos) return true;
    if (m.find("dump") != std::string::npos) return true;
    if (m.find("sign") != std::string::npos) return true;
    if (m.find("importpriv") != std::string::npos) return true;
    if (m.starts_with("send")) return true;
    if (m.find("backupwallet") != std::string::npos) return true;
    if (m.find("encryptwallet") != std::string::npos) return true;
    if (m.find("listunspent") != std::string::npos) return true;
    if (m.find("preparebounty") != std::string::npos) return true;
    if (m.find("signbounty") != std::string::npos) return true;
    if (m.find("submitbounty") != std::string::npos) return true;
    if (m.find("createagentmandate") != std::string::npos) return true;
    if (m.find("revokeagentmandate") != std::string::npos) return true;
    if (m.find("getagentmandate") != std::string::npos) return true;
    if (m.find("reservemandate") != std::string::npos) return true;
    if (m.find("createsubscriptionmandate") != std::string::npos) return true;
    if (m.find("revokesubscriptionmandate") != std::string::npos) return true;
    if (m.find("getsubscriptionmandate") != std::string::npos) return true;
    if (m.find("getsubscriptionactivity") != std::string::npos) return true;
    if (m.find("reservesubscriptionmandate") != std::string::npos) return true;
    if (m.find("observebountychain") != std::string::npos) return true;
    if (m.find("reorgbountychain") != std::string::npos) return true;
    if (m.find("bountyevaluation") != std::string::npos) return true;
    if (m.find("proposebounty") != std::string::npos) return true;
    if (m.find("approvebounty") != std::string::npos) return true;
    if (m.find("importbountyrecovery") != std::string::npos) return true;
    if (m.find("createbountydraft") != std::string::npos) return true;
    if (m.find("listbountydrafts") != std::string::npos) return true;
    if (m.find("getbountydraft") != std::string::npos) return true;
    if (m.find("updatebountydraft") != std::string::npos) return true;
    if (m.find("deletebountydraft") != std::string::npos) return true;
    if (m.find("validatebountyterms") != std::string::npos) return true;
    if (m.find("publishbounty") != std::string::npos) return true;
    return false;
}

bool WalletLikeBody(const std::string& body)
{
    if (body.empty()) return false;
    UniValue j;
    if (j.read(body) && j.isObject() && j.exists("method") && j["method"].isStr()) {
        if (MethodLooksWallet(j["method"].get_str())) return true;
    }
    const std::string b = ToLower(body);
    static const char* kNeedles[] = {
        "dumpprivkey",
        "dumpwallet",
        "signrawtransaction",
        "walletpassphrase",
        "importprivkey",
        "sendtoaddress",
    };
    for (const char* n : kNeedles) {
        if (b.find(n) != std::string::npos) return true;
    }
    return false;
}

bool IsSafeMethod(const std::string& method)
{
    const std::string m = ToUpper(method);
    return m == "GET" || m == "HEAD";
}

std::string TrimCopy(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    return s;
}

/** True if a Range query or header is present. Never applied to body bytes. */
bool RequestHasRange(const std::string& path, const std::string& headers)
{
    if (!QueryParam(path, "range").empty()) return true;
    size_t i = 0;
    while (i < headers.size()) {
        size_t line_end = headers.find('\n', i);
        if (line_end == std::string::npos) line_end = headers.size();
        std::string line = headers.substr(i, line_end - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        const std::string name = ToLower(TrimCopy(colon == std::string::npos ? line : line.substr(0, colon)));
        if (name == "range") return true;
        i = line_end + 1;
    }
    return false;
}

UniValue DecodeObject(const Resource& r)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("canonical", r.Uri());
    obj.pushKV("kind", ResourceKindName(r.kind));
    obj.pushKV("digest", r.digest.Hex());
    obj.pushKV("open_in_btx", r.Uri());
    obj.pushKV("note", BRIDGE_NOTE);
    obj.pushKV("bind_default", "127.0.0.1");
    obj.pushKV("upstream", "PQ1 or unix RPC getmodel/listmodels; never native-client TLS fallback");
    return obj;
}

UniValue ApiV1Shell()
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("schema_version", 2);
    obj.pushKV("authoritative", false);
    obj.pushKV("coverage", "incomplete");
    obj.pushKV("global_complete", false);
    obj.pushKV("coverage_note",
               "Observed providers and indexed records only; not a global directory.");
    obj.pushKV("note", API_V1_RPC_NOTE);
    return obj;
}

bool TryAppendDecodeResult(UniValue& results, const std::string& text)
{
    if (text.empty()) return false;
    Resource r;
    std::string err;
    if (!DecodeResource(text, r, err) && !DecodeResource("btx://" + text, r, err)) {
        return false;
    }
    results.push_back(DecodeObject(r));
    return true;
}

bool RouteIsApiV1(const std::string& route)
{
    if (route.size() < 7 || route.compare(0, 7, "/api/v1") != 0) return false;
    return route.size() == 7 || route[7] == '/';
}

/**
 * Optional read-only /api/v1 JSON (no catalog, no unix RPC from this TU).
 * Returns true when route is under /api/v1 (including 404 for unknown paths).
 */
bool HandleApiV1Get(const std::string& path, BrowserBridgeResponse& out)
{
    const std::string route = NormalizedRoute(path);
    if (!RouteIsApiV1(route)) return false;

    auto finish = [&](UniValue obj, int status, bool ok, std::string canonical = {}) {
        return FillJson(out, status, std::move(obj), ok, std::move(canonical));
    };

    if (route == "/api/v1/search") {
        const std::string q = QueryParam(path, "q");
        UniValue params(UniValue::VARR);
        UniValue req(UniValue::VOBJ);
        req.pushKV("text", q);
        params.push_back(std::move(req));
        UniValue rpc;
        if (BridgeReadRpc("searchmodels", params, rpc) && rpc.isObject()) {
            UniValue obj = ApiV1Shell();
            obj.pushKV("text", q);
            if (rpc.exists("results")) obj.pushKV("results", rpc["results"]);
            else obj.pushKV("results", UniValue(UniValue::VARR));
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("text", q);
        UniValue results(UniValue::VARR);
        TryAppendDecodeResult(results, q);
        obj.pushKV("results", results);
        obj.pushKV("remote_count", 0);
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/models") {
        UniValue params(UniValue::VARR);
        params.push_back(UniValue(UniValue::VOBJ));
        UniValue rpc;
        if (BridgeReadRpc("getmodeldirectory", params, rpc) && rpc.isObject()) {
            UniValue obj = ApiV1Shell();
            if (rpc.exists("results")) obj.pushKV("results", rpc["results"]);
            else obj.pushKV("results", UniValue(UniValue::VARR));
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("results", UniValue(UniValue::VARR));
        return finish(std::move(obj), 200, true);
    }

    if (route.rfind("/api/v1/models/", 0) == 0) {
        std::string id = route.substr(std::string_view{"/api/v1/models/"}.size());
        const bool economy = id.size() > 8 && id.rfind("/economy") == id.size() - 8;
        if (economy) id.resize(id.size() - 8);
        if (id.empty() || id.find('/') != std::string::npos) {
            UniValue obj = ApiV1Shell();
            obj.pushKV("error", "not found");
            return finish(std::move(obj), 404, false);
        }
        if (economy) {
            UniValue params(UniValue::VARR);
            params.push_back(id);
            UniValue rpc;
            if (BridgeReadRpc("getmodeleconomyentry", params, rpc) && rpc.isObject()) {
                UniValue obj = rpc;
                obj.pushKV("from_helper", true);
                obj.pushKV("wallet", false);
                return finish(std::move(obj), 200, true);
            }
            UniValue obj = ApiV1Shell();
            obj.pushKV("authoritative", false);
            obj.pushKV("native_rpc", "getmodeleconomyentry");
            obj.pushKV("wallet", false);
            obj.pushKV("id", id);
            return finish(std::move(obj), 200, true);
        }
        Resource r;
        std::string err;
        if (DecodeResource(id, r, err) || DecodeResource("btx://" + id, r, err)) {
            UniValue obj = DecodeObject(r);
            obj.pushKV("schema_version", 2);
            obj.pushKV("authoritative", false);
            obj.pushKV("coverage", "incomplete");
            obj.pushKV("global_complete", false);
            obj.pushKV("model_id", r.digest.Hex());
            return finish(std::move(obj), 200, true, r.Uri());
        }
        Digest48 hex_id;
        if (Digest48::FromHex(id, hex_id, err) && !hex_id.IsNull()) {
            UniValue obj = ApiV1Shell();
            obj.pushKV("error", "non-btx id; HTTP bridge decodes btx:// tokens only");
            return finish(std::move(obj), 400, false);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("error", "malformed id");
        return finish(std::move(obj), 400, false);
    }

    if (route == "/api/v1/bounties") {
        const std::string q = QueryParam(path, "q");
        UniValue params(UniValue::VARR);
        UniValue req(UniValue::VOBJ);
        req.pushKV("text", q);
        req.pushKV("scope", "LOCAL");
        params.push_back(std::move(req));
        UniValue rpc;
        if (BridgeReadRpc("searchbounties", params, rpc) && rpc.isObject()) {
            UniValue obj = ApiV1Shell();
            obj.pushKV("results", rpc.exists("results") ? rpc["results"] : UniValue(UniValue::VARR));
            obj.pushKV("wallet", false);
            obj.pushKV("eval", false);
            obj.pushKV("mandate", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("results", UniValue(UniValue::VARR));
        obj.pushKV("wallet", false);
        return finish(std::move(obj), 200, true);
    }

    if (route.rfind("/api/v1/bounties/", 0) == 0) {
        const std::string id = route.substr(std::string_view{"/api/v1/bounties/"}.size());
        if (id.empty() || id.find('/') != std::string::npos) {
            UniValue obj = ApiV1Shell();
            obj.pushKV("error", "not found");
            return finish(std::move(obj), 404, false);
        }
        UniValue params(UniValue::VARR);
        params.push_back(id);
        UniValue rpc;
        if (BridgeReadRpc("getbounty", params, rpc) && rpc.isObject()) {
            rpc.pushKV("wallet", false);
            rpc.pushKV("from_helper", true);
            return finish(std::move(rpc), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("id", id);
        obj.pushKV("wallet", false);
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/publishers") {
        UniValue params(UniValue::VARR);
        UniValue rpc;
        if (BridgeReadRpc("searchpublishers", params, rpc) && rpc.isObject()) {
            UniValue obj = rpc;
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("publishers", UniValue(UniValue::VARR));
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/collections") {
        UniValue params(UniValue::VARR);
        UniValue rpc;
        if (BridgeReadRpc("searchcollections", params, rpc) && rpc.isObject()) {
            UniValue obj = rpc;
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("collections", UniValue(UniValue::VARR));
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/releases") {
        UniValue params(UniValue::VARR);
        UniValue req(UniValue::VOBJ);
        req.pushKV("scope", "NETWORK");
        params.push_back(std::move(req));
        UniValue rpc;
        if (BridgeReadRpc("getrecentreleases", params, rpc) && rpc.isObject()) {
            UniValue obj = rpc;
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("results", UniValue(UniValue::VARR));
        obj.pushKV("native_rpc", "getrecentreleases / getmodelfeed");
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/feed" || route == "/api/v1/feed/new" || route == "/api/v1/feed/releases" ||
        route == "/api/v1/feed/unlocked") {
        UniValue params(UniValue::VARR);
        UniValue req(UniValue::VOBJ);
        std::string mode = "NEWEST";
        if (route == "/api/v1/feed/releases") mode = "NEW_RELEASE_CAMPAIGNS";
        else if (route == "/api/v1/feed/unlocked") mode = "RECENTLY_UNLOCKED";
        req.pushKV("mode", mode);
        params.push_back(std::move(req));
        UniValue rpc;
        if (BridgeReadRpc("getmodelfeed", params, rpc) && rpc.isObject()) {
            UniValue obj = rpc;
            obj.pushKV("from_helper", true);
            obj.pushKV("wallet", false);
            obj.pushKV("funding_writes", false);
            return finish(std::move(obj), 200, true);
        }
        UniValue obj = ApiV1Shell();
        obj.pushKV("items", UniValue(UniValue::VARR));
        obj.pushKV("coverage", "incomplete");
        obj.pushKV("global_complete", false);
        obj.pushKV("authoritative", false);
        obj.pushKV("native_rpc", "getmodelfeed");
        obj.pushKV("funding_writes", false);
        return finish(std::move(obj), 200, true);
    }

    if (route.size() > 16 && route.rfind("/api/v1/models/", 0) == 0 && route.find("/economy") != std::string::npos) {
        UniValue obj = ApiV1Shell();
        obj.pushKV("authoritative", false);
        obj.pushKV("native_rpc", "getmodeleconomyentry");
        obj.pushKV("wallet", false);
        return finish(std::move(obj), 200, true);
    }

    if (route.size() > 18 && route.rfind("/api/v1/releases/", 0) == 0) {
        UniValue obj = ApiV1Shell();
        obj.pushKV("authoritative", false);
        obj.pushKV("native_rpc", "getmodelreleaseeconomics");
        obj.pushKV("wallet", false);
        obj.pushKV("funding_writes", false);
        return finish(std::move(obj), 200, true);
    }

    if (route == "/api/v1/network/stats") {
        UniValue obj = ApiV1Shell();
        obj.pushKV("models_known", 0);
        obj.pushKV("models_local", 0);
        obj.pushKV("search_records_known", 0);
        obj.pushKV("coverage_disclaimer", "this node's observations only");
        return finish(std::move(obj), 200, true);
    }

    UniValue obj = ApiV1Shell();
    obj.pushKV("error", "not found");
    return finish(std::move(obj), 404, false);
}

} // namespace

int BridgeTlsMaxWildcardDepth()
{
    // Native-style: this edge is not a DNS-wildcard identity authority.
    return 0;
}

bool DnsSplit42_43(const std::string& token, std::string& left, std::string& right)
{
    left.clear();
    right.clear();
    std::string payload = token;
    if (payload.size() >= 6 && ToLower(payload.substr(0, 6)) == "btx://") {
        payload.erase(0, 6);
    }
    if (payload.size() != 85) return false;
    left = payload.substr(0, 42);
    right = payload.substr(42);
    return right.size() == 43;
}

std::string DnsSplitJoin(const std::string& left, const std::string& right, const std::string& zone)
{
    if (left.size() != 42 || right.size() != 43) return {};
    std::string z = TrimCopy(zone);
    while (!z.empty() && z.front() == '.') z.erase(z.begin());
    while (!z.empty() && z.back() == '.') z.pop_back();
    if (z.empty()) return {};
    return left + "." + right + "." + z;
}

bool BridgeRangeToPieces(uint64_t first_byte, uint64_t last_byte, uint64_t piece_size,
                         uint32_t& first_piece, uint32_t& piece_count)
{
    if (piece_size == 0 || last_byte < first_byte) return false;
    const uint64_t first64 = first_byte / piece_size;
    const uint64_t last64 = last_byte / piece_size;
    if (first64 > std::numeric_limits<uint32_t>::max()) return false;
    const uint64_t count64 = last64 - first64 + 1;
    if (count64 > std::numeric_limits<uint32_t>::max()) return false;
    first_piece = static_cast<uint32_t>(first64);
    piece_count = static_cast<uint32_t>(count64);
    return true;
}

std::string BridgeCacheKey(const std::string& canonical_uri, uint32_t file_index)
{
    // Full canonical token, not a 42-char DNS split. File index is required so
    // two files of the same URI cannot share a key. No disk cache is implied.
    return canonical_uri + "/f/" + std::to_string(file_index);
}

bool BridgePublicDownloadEnabled()
{
    const char* e = std::getenv(PUBLIC_DOWNLOAD_ENV);
    return e != nullptr && std::string_view{e} == "1";
}

bool HandleBridgeGet(const std::string& path, BrowserBridgeResponse& out,
                     const std::string& headers)
{
    out = {};
    const bool range_hint = RequestHasRange(path, headers);
    (void)range_hint;

    if (WalletLikePath(path)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "wallet paths are not served");
        return FillJson(out, 403, std::move(obj), false);
    }

    std::string file_token;
    uint32_t file_index = 0;
    if (SplitTokenFile(path, file_token, file_index)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", BridgePublicDownloadEnabled() ?
                   "verified chunks required before emission" :
                   "public download disabled");
        obj.pushKV("public_download", BridgePublicDownloadEnabled());
        obj.pushKV("file_index", static_cast<int>(file_index));
        obj.pushKV("web_compatibility", WEB_COMPAT);
        return FillJson(out, BridgePublicDownloadEnabled() ? 409 : 403, std::move(obj), false);
    }

    const std::string route = NormalizedRoute(path);
    if (route == "/health") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("ok", true);
        obj.pushKV("service", "btx-model-browser-bridge");
        obj.pushKV("profile", "D09");
        obj.pushKV("bind_default", "127.0.0.1");
        obj.pushKV("catalog_browser_bridge", false);
        obj.pushKV("wildcard_dns_depth", BridgeTlsMaxWildcardDepth());
        obj.pushKV("public_download", BridgePublicDownloadEnabled());
        obj.pushKV("web_compatibility", WEB_COMPAT);
        obj.pushKV("note", BRIDGE_NOTE);
        return FillJson(out, 200, std::move(obj), true);
    }

    if (route == "/open") {
        const std::string uri = QueryParam(path, "uri");
        Resource r;
        std::string err;
        if (uri.empty() || (!DecodeResource(uri, r, err) && !DecodeResource("btx://" + uri, r, err))) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("error", "malformed URI");
            return FillJson(out, 400, std::move(obj), false);
        }
        if (WantsHtml(path, headers)) return FillHtml(out, r);
        return FillJson(out, 200, DecodeObject(r), true, r.Uri());
    }

    if (HandleApiV1Get(path, out)) return true;

    std::string token = PathOnly(path);
    if (!token.empty() && token.front() == '/') token.erase(0, 1);
    Resource r;
    std::string err;
    if (!DecodeResource(token, r, err) && !DecodeResource("btx://" + token, r, err)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "malformed URI");
        return FillJson(out, 400, std::move(obj), false);
    }
    if (WantsHtml(path, headers)) return FillHtml(out, r);
    return FillJson(out, 200, DecodeObject(r), true, r.Uri());
}

bool HandleBridgePublicFile(const std::string& path, const std::string& headers,
                            Span<const unsigned char> verified,
                            BrowserBridgeResponse& out)
{
    out = {};
    if (!BridgePublicDownloadEnabled()) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "public download disabled");
        obj.pushKV("web_compatibility", WEB_COMPAT);
        return FillJson(out, 403, std::move(obj), false);
    }
    std::string token;
    uint32_t file_index = 0;
    if (!SplitTokenFile(path, token, file_index)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "expected /<token>/f/<index>");
        return FillJson(out, 400, std::move(obj), false);
    }
    Resource r;
    std::string err;
    if (!DecodeResource(token, r, err) && !DecodeResource("btx://" + token, r, err)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "malformed URI");
        return FillJson(out, 400, std::move(obj), false);
    }
    if (verified.empty()) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "verified chunks required before emission");
        obj.pushKV("web_compatibility", WEB_COMPAT);
        return FillJson(out, 409, std::move(obj), false);
    }
    uint64_t first = 0, last = 0;
    if (!ParseInclusiveRange(path, headers, verified.size(), first, last)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "invalid range");
        return FillJson(out, 416, std::move(obj), false);
    }
    uint32_t first_piece = 0, piece_count = 0;
    BridgeRangeToPieces(first, last, modelnet::PIECE_SIZE, first_piece, piece_count);
    const size_t n = static_cast<size_t>(last - first + 1);
    out.ok = true;
    out.http_status = 200;
    out.content_type = "application/octet-stream";
    out.canonical_btx = r.Uri();
    out.body.assign(reinterpret_cast<const char*>(verified.data() + first), n);
    out.headers.emplace_back("Content-Disposition", "attachment");
    out.headers.emplace_back("X-Content-Type-Options", "nosniff");
    out.headers.emplace_back("Content-Security-Policy", "default-src 'none'");
    out.headers.emplace_back("X-BTX-Web-Compatibility", WEB_COMPAT);
    out.headers.emplace_back("X-BTX-Cache-Key", BridgeCacheKey(r.Uri(), file_index));
    out.headers.emplace_back("X-BTX-First-Piece", std::to_string(first_piece));
    out.headers.emplace_back("X-BTX-Piece-Count", std::to_string(piece_count));
    return true;
}

bool HandleBridgeRequest(const std::string& method, const std::string& path,
                         const std::string& body, BrowserBridgeResponse& out,
                         const std::string& headers)
{
    out = {};
    const bool mutating = !IsSafeMethod(method);
    const bool wallet_path = WalletLikePath(path);
    const bool wallet_body = mutating && WalletLikeBody(body);

    if (mutating && (wallet_path || wallet_body)) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "method not allowed");
        obj.pushKV("allow", "GET, HEAD");
        return FillJson(out, 405, std::move(obj), false);
    }
    if (wallet_path) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "wallet paths are not served");
        return FillJson(out, 403, std::move(obj), false);
    }
    if (mutating) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("error", "method not allowed");
        obj.pushKV("allow", "GET, HEAD");
        return FillJson(out, 405, std::move(obj), false);
    }
    return HandleBridgeGet(path, out, headers);
}

} // namespace modelnet
