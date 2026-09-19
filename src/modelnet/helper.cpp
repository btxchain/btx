// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/helper.h>

#include <crypto/sha256.h>
#include <modelnet/community.h>
#include <modelnet/crypto.h>
#include <modelnet/free_grant.h>
#include <modelnet/funding.h>
#include <modelnet/identity.h>
#include <modelnet/model_nat.h>
#include <modelnet/piece_picker.h>
#include <modelnet/transfer_session.h>
#include <modelnet/verified_manifest.h>
#include <modelnet/package_bundle.h>
#include <modelnet/import_plan.h>
#include <modelnet/hello_caps.h>
#include <modelnet/capability.h>
#include <modelnet/hcp.h>
#include <modelnet/subpiece.h>
#include <modelnet/provider_exchange.h>
#include <modelnet/provider_route.h>
#include <modelnet/reachability.h>
#include <modelnet/relay_reserve.h>
#include <modelnet/search.h>
#include <modelnet/bounty.h>
#include <modelnet/policy.h>
#include <modelnet/auto_storage.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/records.h>
#include <modelnet/qualification.h>
#include <modelnet/release.h>
#include <modelnet/economy.h>
#include <modelnet/feed.h>
#include <modelnet/file_stream.h>
#include <modelnet/profile.h>
#include <modelnet/model_watch.h>
#include <modelnet/event_journal.h>
#include <modelnet/subscription_mandate.h>
#include <modelnet/s3_store.h>
#include <modelnet/cloud_layout.h>
#include <modelnet/direct_seed.h>
#include <modelnet/resource_uri.h>
#include <modelnet/router.h>
#include <modelnet/store.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <random.h>
#include <span.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

namespace modelnet {
namespace {

constexpr size_t MAX_HTTP_HEADERS = PQ1_HTTP_HEADER_CAP;
constexpr size_t MAX_RPC_BODY = 256 * 1024;
/** Ordinary unix RPC replies: 120s. Long methods keep 24h. */
constexpr int UNIX_RPC_REPLY_MS = 120 * 1000;
constexpr int UNIX_RPC_LONG_REPLY_MS = 24 * 60 * 60 * 1000;
constexpr size_t MAX_PIECE_HTTP = MAX_HTTP_HEADERS + PIECE_SIZE + 4096;
constexpr uint64_t PQ1_RECONNECT_BYTES = 8ULL << 30;

std::string TrimCopy(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.pop_back();
    return s;
}

std::string HeaderGet(const NativeResponse& resp, const std::string& name)
{
    const std::string want = ToLower(name);
    for (const auto& h : resp.headers) {
        if (ToLower(h.first) == want) return h.second;
    }
    return {};
}

std::string RequestHeader(const NativeRequest& req, const std::string& name)
{
    const std::string want = ToLower(name);
    for (const auto& h : req.headers) {
        if (ToLower(h.first) == want) return h.second;
    }
    return {};
}

std::string JsonError(const std::string& code, const std::string& message)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("error_code", code);
    o.pushKV("message", message);
    return o.write();
}

int64_t NowEpochMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void NoteRetrieveBytes(RetrieveProgress* progress, uint64_t bytes)
{
    if (!progress) return;
    const uint64_t prev = progress->bytes_committed.exchange(bytes);
    if (bytes != prev) {
        progress->last_commit_ms.store(static_cast<uint64_t>(NowEpochMs()));
    }
}

/** Single-quote for std::system. Unquoted $BTX_OPENSSL must not reach the shell. */
std::string QuoteShellArg(const std::string& arg)
{
    std::string out = "'";
    for (char c : arg) {
        if (c == '\'') out += "'\"'\"'";
        else out += c;
    }
    out += "'";
    return out;
}

int AddrConnectPreference(const sockaddr* sa)
{
    if (!sa) return 3;
    if (sa->sa_family == AF_INET) {
        const uint32_t a = ntohl(reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.s_addr);
        if ((a & 0xff000000u) == 0x7f000000u) return 0; // 127.0.0.0/8
        if ((a & 0xff000000u) == 0x0a000000u) return 1; // 10.0.0.0/8
        if ((a & 0xfff00000u) == 0xac100000u) return 1; // 172.16.0.0/12
        if ((a & 0xffff0000u) == 0xc0a80000u) return 1; // 192.168.0.0/16
        return 2;
    }
    if (sa->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
        const uint8_t* b = sin6->sin6_addr.s6_addr;
        static const uint8_t loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        if (std::memcmp(b, loop, 16) == 0) return 0;
        if ((b[0] & 0xfe) == 0xfc) return 1; // fc00::/7 ULA
        bool mapped = true;
        for (int i = 0; i < 10; ++i) {
            if (b[i] != 0) mapped = false;
        }
        if (mapped && b[10] == 0xff && b[11] == 0xff) {
            sockaddr_in v4{};
            v4.sin_family = AF_INET;
            std::memcpy(&v4.sin_addr, b + 12, 4);
            return AddrConnectPreference(reinterpret_cast<const sockaddr*>(&v4));
        }
        return 2;
    }
    return 3;
}

bool SplitHostPort(const std::string& in, std::string& host, uint16_t& port)
{
    if (SplitListenBind(in, host, port)) {
        if (host.empty()) host = "0.0.0.0";
        return true;
    }
    return false;
}

void SetListenOpts(int fd)
{
    SetPq1SocketOpts(fd, /*nonblock=*/true);
}

constexpr uint32_t EXT_VERSION = 257;
constexpr uint32_t FEAT_RESOURCE_RESOLVE = 1u;
constexpr uint32_t FEAT_FREE_GRANT = 2u;
constexpr uint32_t FEAT_SERVICE_RECEIPT = 4u;
constexpr uint32_t FEAT_RESEARCH_IDENTITY = 8u;
constexpr uint32_t FEAT_COLLECTIONS_ALIAS = 16u;
constexpr uint32_t FEAT_POLICY_BUNDLE = 32u;
constexpr uint32_t FEAT_PRESERVATION_CIRCLE = 64u;
constexpr uint32_t EXT_FEATURES = FEAT_RESOURCE_RESOLVE | FEAT_FREE_GRANT | FEAT_SERVICE_RECEIPT |
                                  FEAT_RESEARCH_IDENTITY | FEAT_COLLECTIONS_ALIAS | FEAT_POLICY_BUNDLE |
                                  FEAT_PRESERVATION_CIRCLE;
std::mutex g_ext_mu;

fs::path HelperDir(const ModelCatalog& cat)
{
    return cat.Store().Root().parent_path();
}

bool ReadJsonFile(const fs::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (!out.read(ss.str())) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    if (!out.isObject() && !out.isArray()) out = UniValue(UniValue::VOBJ);
    return true;
}

bool WriteJsonFile(const fs::path& path, const UniValue& obj, std::string& err)
{
    fs::create_directories(path.parent_path());
    std::ofstream out(path);
    if (!out) {
        err = "write " + fs::PathToString(path);
        return false;
    }
    out << obj.write() << "\n";
    return true;
}

RouterCache& RecordsFor(const ModelCatalog& cat)
{
    static std::mutex mu;
    static std::map<std::string, RouterCache> caches;
    static std::map<std::string, bool> loaded;
    const std::string key = fs::PathToString(HelperDir(cat));
    std::lock_guard<std::mutex> lock(mu);
    RouterCache& cache = caches[key];
    if (!loaded[key]) {
        loaded[key] = true;
        UniValue arr;
        ReadJsonFile(HelperDir(cat) / "records.json", arr);
        if (arr.isArray()) {
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            for (const auto& rec : arr.getValues()) {
                if (!rec.isObject() || !rec.exists("record_id")) continue;
                SignedRecordHint h;
                std::string e;
                if (!Digest48::FromHex(rec["record_id"].get_str(), h.record_id, e)) continue;
                h.kind = rec.exists("kind") ? static_cast<uint8_t>(rec["kind"].getInt<int>()) : 0;
                h.expiry = rec.exists("expiry") ? rec["expiry"].getInt<int64_t>() : 0;
                h.provider_id = rec.exists("provider_id") ? rec["provider_id"].get_str() : "";
                if (rec.exists("payload_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["payload_hex"].get_str())) h.payload = *bytes;
                }
                if (rec.exists("sig_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["sig_hex"].get_str())) h.signature = *bytes;
                }
                if (rec.exists("pubkey_hex")) {
                    if (auto bytes = TryParseHex<unsigned char>(rec["pubkey_hex"].get_str())) h.pubkey = *bytes;
                }
                h.signed_ok = rec.exists("signed_ok") && rec["signed_ok"].get_bool();
                cache.Insert(h, now, e);
            }
        }
    }
    return cache;
}

bool PersistRecords(const ModelCatalog& cat, RouterCache& cache)
{
    UniValue arr(UniValue::VARR);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    for (const auto& h : cache.All(now)) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("record_id", h.record_id.Hex());
        o.pushKV("kind", h.kind);
        o.pushKV("expiry", h.expiry);
        o.pushKV("provider_id", h.provider_id);
        o.pushKV("payload_hex", HexStr(h.payload));
        if (!h.signature.empty()) o.pushKV("sig_hex", HexStr(h.signature));
        if (!h.pubkey.empty()) o.pushKV("pubkey_hex", HexStr(h.pubkey));
        o.pushKV("signed_ok", h.signed_ok);
        arr.push_back(o);
    }
    std::string err;
    return WriteJsonFile(HelperDir(cat) / "records.json", arr, err);
}

UniValue HintJson(const SignedRecordHint& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("record_id", h.record_id.Hex());
    o.pushKV("kind", h.kind);
    o.pushKV("expiry", h.expiry);
    o.pushKV("provider_id", h.provider_id);
    o.pushKV("payload_hex", HexStr(h.payload));
    o.pushKV("signed_ok", h.signed_ok);
    return o;
}

NegativeResolveCache& NegCache()
{
    static NegativeResolveCache c;
    return c;
}

bool LoadOrCreateResearchIdentity(const fs::path& dir, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk,
                                  Digest48& id, std::string& err)
{
    UniValue store;
    ReadJsonFile(dir / "research_identity.json", store);
    if (store.exists("pk_hex") && store.exists("sk_hex")) {
        auto pkb = TryParseHex<unsigned char>(store["pk_hex"].get_str());
        auto skb = TryParseHex<unsigned char>(store["sk_hex"].get_str());
        if (pkb && skb) {
            pk = *pkb;
            sk = *skb;
            id = ResearchIdentityId(pk);
            return true;
        }
    }
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    id = ResearchIdentityId(pk);
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    store.pushKV("id", id.Hex());
    return WriteJsonFile(dir / "research_identity.json", store, err);
}

bool WritePublisherIdentityFiles(const fs::path& dir, const std::vector<unsigned char>& pk,
                                  const std::vector<unsigned char>& sk, const std::string& label,
                                  Digest48& publisher_id, std::string& err)
{
    publisher_id = PublisherId(pk);
    UniValue store;
    ReadJsonFile(dir / "identities.json", store);
    UniValue arr = store.exists("identities") ? store["identities"] : UniValue(UniValue::VARR);
    UniValue id(UniValue::VOBJ);
    id.pushKV("id", publisher_id.Hex());
    id.pushKV("label", label);
    id.pushKV("pubkey_hex", HexStr(pk));
    id.pushKV("class", "RESEARCH_PUBLISHER");
    id.pushKV("trusted", false);
    arr.push_back(id);
    store.pushKV("identities", arr);
    if (!WriteJsonFile(dir / "identities.json", store, err)) return false;
    const fs::path skpath = dir / "tls" / fs::PathFromString("identity-" + publisher_id.Hex().substr(0, 16) + ".sk");
    fs::create_directories(skpath.parent_path());
    std::ofstream skf(skpath, std::ios::binary);
    if (!skf) {
        err = "identity secret write";
        return false;
    }
    skf.write(reinterpret_cast<const char*>(sk.data()), static_cast<std::streamsize>(sk.size()));
    return true;
}

bool LoadPublisherSecret(const fs::path& dir, const std::string& hexid, std::vector<unsigned char>& sk)
{
    const fs::path skpath = dir / "tls" / fs::PathFromString("identity-" + hexid.substr(0, 16) + ".sk");
    std::ifstream skf(fs::PathToString(skpath), std::ios::binary);
    if (!skf) return false;
    sk.assign((std::istreambuf_iterator<char>(skf)), std::istreambuf_iterator<char>());
    return !sk.empty();
}

bool EnsureDefaultPublisherIdentity(const fs::path& dir, std::vector<unsigned char>& pk,
                                       std::vector<unsigned char>& sk, Digest48& publisher_id, std::string& err)
{
    UniValue store;
    ReadJsonFile(dir / "identities.json", store);
    if (store.exists("identities") && store["identities"].isArray() && !store["identities"].getValues().empty()) {
        const UniValue& idj = store["identities"].getValues().front();
        if (idj.exists("pubkey_hex") && idj.exists("id")) {
            pk = ParseHex(idj["pubkey_hex"].get_str());
            const std::string hexid = idj["id"].get_str();
            if (LoadPublisherSecret(dir, hexid, sk) && pk.size() == MLDSA44_PK) {
                publisher_id = PublisherId(pk);
                return true;
            }
        }
    }
    Digest48 research_id;
    if (!LoadOrCreateResearchIdentity(dir, pk, sk, research_id, err)) return false;
    if (pk.size() != MLDSA44_PK) {
        err = "identity size";
        return false;
    }
    return WritePublisherIdentityFiles(dir, pk, sk, "local publisher", publisher_id, err);
}

bool SignSearchRecordWithDefaultIdentity(const fs::path& dir, ModelSearchRecord& rec, std::string& err)
{
    std::vector<unsigned char> pk, sk;
    Digest48 publisher_id;
    if (!EnsureDefaultPublisherIdentity(dir, pk, sk, publisher_id, err)) return false;
    rec.pubkey = pk;
    if (rec.publisher_display_name.empty()) rec.publisher_display_name = "local publisher";
    if (!SignSearchRecord(rec, Span<const unsigned char>{sk.data(), sk.size()}, err)) {
        rec.pubkey.clear();
        return false;
    }
    rec.signed_ok = true;
    return true;
}

std::string InferQuantizationFromLabel(const std::string& label)
{
    const std::string lower = ToLower(label);
    static const std::pair<const char*, const char*> toks[] = {
        {"iq4_xs", "IQ4_XS"}, {"iq4_nl", "IQ4_NL"}, {"iq3_xxs", "IQ3_XXS"}, {"iq2_xxs", "IQ2_XXS"},
        {"q4_k_m", "Q4_K_M"}, {"q5_k_m", "Q5_K_M"}, {"q3_k_m", "Q3_K_M"}, {"q4_k_s", "Q4_K_S"},
        {"q5_k_s", "Q5_K_S"}, {"q6_k", "Q6_K"}, {"q2_k", "Q2_K"}, {"q8_0", "Q8_0"},
        {"q5_0", "Q5_0"}, {"q4_0", "Q4_0"}, {"bf16", "BF16"}, {"fp8", "FP8"},
        {"f16", "F16"}, {"f32", "F32"},
    };
    for (const auto& t : toks) {
        if (lower.find(t.first) != std::string::npos) return t.second;
    }
    return {};
}

std::string InferFamilyFromLabel(const std::string& label)
{
    const std::string lower = ToLower(label);
    static const char* fams[] = {"qwen3", "qwen2", "qwen", "glm", "llama", "mistral", "gemma",
                                  "phi", "deepseek", "granite"};
    for (const char* f : fams) {
        if (lower.find(f) != std::string::npos) return f;
    }
    return {};
}

ModelSearchRecord DraftSearchFromCatalog(const CatalogEntry& e)
{
    ModelSearchRecord rec;
    rec.model_id = e.model_id;
    rec.artifact_id = e.artifact_id;
    rec.canonical_name = e.label;
    rec.display_name = e.label;
    rec.record_version = 2;
    rec.release_state = "PUBLIC";
    uint64_t bytes = 0;
    bool saw_gguf = false, saw_st = false;
    for (const auto& f : e.core.files) {
        bytes += f.size;
        const auto lower = ToLower(f.path);
        if (lower.ends_with(".gguf")) saw_gguf = true;
        if (lower.ends_with(".safetensors")) saw_st = true;
    }
    rec.size_bytes = bytes;
    rec.file_count = static_cast<int>(e.core.files.size());
    if (saw_gguf && !saw_st) rec.format = "gguf";
    else if (saw_st) rec.format = "safetensors";
    rec.quantization = InferQuantizationFromLabel(e.label);
    rec.family = InferFamilyFromLabel(e.label);
    rec.architecture = rec.family;
    if (!rec.format.empty()) rec.tags.push_back(rec.format);
    if (!rec.family.empty()) rec.tags.push_back(rec.family);
    if (!rec.quantization.empty()) rec.tags.push_back(rec.quantization);
    rec.short_description = "Imported locally as " + e.label +
                            (rec.format.empty() ? std::string() : " (" + rec.format + ").");
    return rec;
}

bool AcceptSignedAnnounce(const UniValue& body, int64_t now, SignedRecordHint& h, std::string& err)
{
    if (!body.exists("kind") || !body.exists("payload_hex") || !body.exists("sig_hex") || !body.exists("pubkey_hex")) {
        err = "unsigned announce rejected";
        return false;
    }
    h.kind = static_cast<uint8_t>(body["kind"].getInt<int>());
    const auto payload = TryParseHex<unsigned char>(body["payload_hex"].get_str());
    const auto sig = TryParseHex<unsigned char>(body["sig_hex"].get_str());
    const auto pk = TryParseHex<unsigned char>(body["pubkey_hex"].get_str());
    if (!payload || !sig || !pk) {
        err = "announce hex";
        return false;
    }
    UniValue decoded;
    Digest48 rid;
    if (!VerifyTypedRecord(h.kind, *payload, *sig, *pk, now, decoded, rid, err)) return false;
    if (body.exists("record_id")) {
        Digest48 claimed;
        if (!Digest48::FromHex(body["record_id"].get_str(), claimed, err) || claimed != rid) {
            err = "record_id does not match typed object";
            return false;
        }
    }
    h.record_id = rid;
    h.payload = *payload;
    h.signature = *sig;
    h.pubkey = *pk;
    h.signed_ok = true;
    h.expiry = decoded.exists("expires_at") ? decoded["expires_at"].getInt<int64_t>() : 0;
    h.provider_id = body.exists("provider_id") ? body["provider_id"].get_str() : decoded["signer_id"].get_str();
    return true;
}

uint8_t RecordKindForResourceKind(uint8_t resource_kind)
{
    switch (resource_kind) {
    case static_cast<uint8_t>(ResourceKind::COLLECTION): return RECORD_COLLECTION;
    case static_cast<uint8_t>(ResourceKind::IDENTITY): return RECORD_IDENTITY_CARD;
    case static_cast<uint8_t>(ResourceKind::POLICY_BUNDLE): return RECORD_POLICY_BUNDLE;
    case static_cast<uint8_t>(ResourceKind::CIRCLE): return RECORD_PRESERVATION_CIRCLE;
    case static_cast<uint8_t>(ResourceKind::ALIAS): return RECORD_ALIAS;
    case static_cast<uint8_t>(ResourceKind::PROVIDER): return RECORD_IDENTITY_CARD;
    default: return 0;
    }
}

bool KindFromJson(const UniValue& v, uint8_t& kind, std::string& err)
{
    if (v.isNum()) {
        ResourceKind k;
        if (!ResourceKindFromInt(v.getInt<int>(), k)) {
            err = "unknown kind";
            return false;
        }
        kind = static_cast<uint8_t>(k);
        return true;
    }
    if (v.isStr()) {
        for (int i = 0; i <= 8; ++i) {
            ResourceKind k;
            if (ResourceKindFromInt(i, k) && v.get_str() == ResourceKindName(k)) {
                kind = static_cast<uint8_t>(k);
                return true;
            }
        }
        err = "unknown kind";
        return false;
    }
    err = "kind must be int or name";
    return false;
}

UniValue TypedResolveJson(ModelCatalog& cat, uint8_t kind, std::string digest)
{
    digest = ToLower(digest);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    UniValue ids(UniValue::VARR);
    UniValue record_ids(UniValue::VARR);
    UniValue listed;
    cat.List(listed);
    if (!digest.empty() && listed.exists("models")) {
        for (const auto& m : listed["models"].getValues()) {
            if (kind == static_cast<uint8_t>(ResourceKind::ARTIFACT)) {
                if (m.exists("artifact_id") && m["artifact_id"].get_str() == digest) {
                    ids.push_back(m["artifact_id"].get_str());
                }
            } else if (kind == static_cast<uint8_t>(ResourceKind::MODEL)) {
                if (m.exists("model_id") && m["model_id"].get_str() == digest) {
                    ids.push_back(m["model_id"].get_str());
                }
            }
        }
    }
    Digest48 want;
    std::string derr;
    if (!digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        const uint8_t rec_kind = RecordKindForResourceKind(kind);
        if (rec_kind != 0) {
            for (const auto& h : RecordsFor(cat).LookupExactKind(want, rec_kind, now)) {
                if (!h.signed_ok) continue;
                record_ids.push_back(h.record_id.Hex());
            }
        }
    }
    ResolveQueryPlan plan;
    PlanRouterQueries(cat.Peers(),
                       cat.Peers().size() >= 2 ? std::vector<std::string>{cat.Peers().back()} : std::vector<std::string>{},
                       plan);
    const bool incomplete_hit = ids.empty() && record_ids.empty();
    if (incomplete_hit && !digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        NegCache().RememberIncomplete(kind, want, now);
    }
    UniValue ores(UniValue::VOBJ);
    ores.pushKV("schema_version", 2);
    ores.pushKV("coverage", "incomplete");
    ores.pushKV("does_not_exist", false);
    ores.pushKV("kind", kind);
    ores.pushKV("digest", digest);
    ores.pushKV("observation_time", now);
    ores.pushKV("ids", ids);
    ores.pushKV("record_ids", record_ids);
    ores.pushKV("local_count", listed.exists("local_count") ? listed["local_count"] : 0);
    ores.pushKV("remote_count", 0);
    if (digest.empty() && listed.exists("models")) ores.pushKV("models", listed["models"]);
    ores.pushKV("max_routers", MAX_ROUTER_CONTACTS);
    ores.pushKV("max_concurrent_queries", plan.max_concurrent);
    ores.pushKV("router_contacts", static_cast<int>(plan.contacts.size()));
    ores.pushKV("reserved_independent", plan.reserved_independent);
    if (!digest.empty() && Digest48::FromHex(digest, want, derr)) {
        std::lock_guard<std::mutex> lock(g_ext_mu);
        ores.pushKV("negative_cached", NegCache().HasIncomplete(kind, want, now));
    }
    return ores;
}

Digest48 CommunityLocalId(const std::string& hex)
{
    Digest48 mid;
    std::string e;
    if (Digest48::FromHex(hex, mid, e)) return mid;
    return DomainHash("BTX/LocalCommunity/v1", Span<const unsigned char>{
                         reinterpret_cast<const unsigned char*>(hex.data()), hex.size()});
}

void RememberStoppedPreservation(UniValue& store, const std::string& id)
{
    UniValue stopped = store.exists("stopped_preservation") ? store["stopped_preservation"] : UniValue(UniValue::VARR);
    bool have = false;
    for (const auto& x : stopped.getValues()) {
        if (x.isStr() && x.get_str() == id) have = true;
    }
    if (!have) stopped.push_back(id);
    store.pushKV("stopped_preservation", stopped);
}

bool IssueAndStoreRecord(ModelCatalog& cat, uint8_t kind, const UniValue& extra, int64_t ttl_s, SignedRecordHint& h, std::string& err)
{
    std::vector<unsigned char> pk, sk;
    Digest48 signer;
    if (!LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, signer, err)) return false;
    UniValue body(UniValue::VOBJ);
    const uint8_t role = (kind == RECORD_FREE_GRANT || kind == RECORD_SERVICE_RECEIPT) ? 0 : 1;
    FillRecordCommon(body, role, signer, static_cast<int64_t>(std::time(nullptr)), ttl_s);
    if (extra.isObject()) {
        for (const auto& k : extra.getKeys()) body.pushKV(k, extra[k]);
    }
    std::vector<unsigned char> payload, sig;
    Digest48 rid;
    if (!SignTypedRecord(kind, body, sk, payload, sig, rid, err)) return false;
    h = {};
    h.kind = kind;
    h.record_id = rid;
    h.payload = std::move(payload);
    h.signature = std::move(sig);
    h.pubkey = pk;
    h.signed_ok = true;
    h.expiry = body["expires_at"].getInt<int64_t>();
    h.provider_id = signer.Hex();
    std::lock_guard<std::mutex> lock(g_ext_mu);
    if (!RecordsFor(cat).Insert(h, static_cast<int64_t>(std::time(nullptr)), err)) return false;
    PersistRecords(cat, RecordsFor(cat));
    return true;
}

bool JsonBody(const NativeRequest& req, size_t cap, UniValue& body, NativeResponse& resp)
{
    if (req.body.size() > cap) {
        resp.status = 400;
        resp.body = JsonError("TOO_LARGE", "request exceeds bound");
        return false;
    }
    if (req.body.empty()) {
        body = UniValue(UniValue::VOBJ);
        return true;
    }
    if (!body.read(req.body) || !body.isObject()) {
        resp.status = 400;
        resp.body = JsonError("BAD_JSON", "object body required");
        return false;
    }
    return true;
}

int ListenTcp(const std::string& bind, std::string& err)
{
    std::string host;
    uint16_t port = 0;
    if (!SplitHostPort(bind, host, port)) {
        err = "invalid -modelbind";
        return -1;
    }
    const bool v6 = host.find(':') != std::string::npos;
    const int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "socket";
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (v6) {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (host == "::" || host == "::0") {
            addr.sin6_addr = in6addr_any;
        } else if (inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr) != 1) {
            err = "bind host";
            close(fd);
            return -1;
        }
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
            err = "bind/listen failed";
            close(fd);
            return -1;
        }
    } else {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (host == "0.0.0.0") {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            err = "bind host";
            close(fd);
            return -1;
        }
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
            err = "bind/listen failed";
            close(fd);
            return -1;
        }
    }
    SetListenOpts(fd);
    return fd;
}

int ListenUnix(fs::path& path, std::string& err)
{
    std::string p = fs::PathToString(path);
    if (p.size() >= sizeof(sockaddr_un::sun_path)) {
        unsigned char digest[32];
        CSHA256()
            .Write(UCharCast(p.data()), p.size())
            .Finalize(digest);
        p = strprintf("/tmp/btx-md-%s.sock", HexStr(std::vector<unsigned char>(digest, digest + 8)));
        path = fs::PathFromString(p);
    }
    ::unlink(p.c_str());
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "unix socket";
        return -1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (p.size() >= sizeof(addr.sun_path)) {
        err = "unix path too long";
        close(fd);
        return -1;
    }
    std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        err = "unix bind/listen failed";
        close(fd);
        return -1;
    }
    return fd;
}

std::string RecvUntil(int fd, size_t cap, std::atomic<bool>* stop, int timeout_ms = PQ1_IDLE_MS)
{
    std::string out;
    char buf[4096];
    while (out.size() < cap) {
        if (stop && stop->load()) break;
        std::string werr;
        if (!WaitFd(fd, false, timeout_ms, stop, werr)) break;
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EAGAIN) continue;
            break;
        }
        out.append(buf, static_cast<size_t>(n));
        if (out.find('\n') != std::string::npos) break;
        if (out.find("\r\n\r\n") != std::string::npos) break;
    }
    return out;
}

bool ParseHttpResponse(const std::string& raw, NativeResponse& resp, std::string& err)
{
    const auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        err = "truncated http";
        return false;
    }
    resp.headers.clear();
    std::istringstream hs(raw.substr(0, pos));
    std::string version;
    hs >> version >> resp.status;
    std::string line;
    std::getline(hs, line);
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = TrimCopy(line.substr(0, colon));
        auto val = TrimCopy(line.substr(colon + 1));
        if (ToLower(key) == "content-type") resp.content_type = val;
        resp.headers.emplace_back(std::move(key), std::move(val));
    }
    resp.body = raw.substr(pos + 4);
    resp.raw.assign(resp.body.begin(), resp.body.end());
    resp.binary = resp.content_type.find("octet-stream") != std::string::npos;
    auto cl = raw.find("Content-Length:");
    if (cl == std::string::npos) cl = raw.find("content-length:");
    if (cl != std::string::npos && cl < pos) {
        const size_t want = std::strtoul(raw.c_str() + cl + 15, nullptr, 10);
        if (resp.body.size() < want) {
            err = "truncated http";
            return false;
        }
        if (resp.body.size() > want) resp.body.resize(want);
    }
    return true;
}

struct Pq1Session {
    Pq1Context* pq{nullptr};
    SSL* ssl{nullptr};
    int fd{-1};
    uint64_t transferred{0};
    std::string host;
    uint16_t port{0};
    fs::path pinfile;
    std::atomic<bool>* stop{nullptr};
    int handshake_ms{PQ1_HANDSHAKE_MS};
    int io_ms{PQ1_IDLE_MS};
    bool outbound_held{false};
    std::vector<std::pair<std::string, std::string>> piece_headers;

    ~Pq1Session() { Close(); }

    void CloseTransport()
    {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        transferred = 0;
    }

    void Close()
    {
        CloseTransport();
        if (outbound_held) {
            GlobalConnLimits().ReleaseOutbound();
            outbound_held = false;
        }
    }

    bool Connect(Pq1Context& ctx, const std::string& h, uint16_t p, std::string& err)
    {
        Close();
        pq = &ctx;
        host = h;
        port = p;
        if (!ctx.Ready()) {
            err = "PQ1 not ready";
            return false;
        }
        if (!GlobalConnLimits().TryOutbound()) {
            err = "outbound connection ceiling";
            return false;
        }
        outbound_held = true;
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_UNSPEC;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
            err = "resolve failed";
            Close();
            return false;
        }
        struct Candidate {
            int family{AF_UNSPEC};
            int socktype{0};
            int protocol{0};
            sockaddr_storage ss{};
            socklen_t len{0};
            int pref{3};
        };
        std::vector<Candidate> cands;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            if (!ai->ai_addr) continue;
            if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
            if (ai->ai_addrlen == 0 || ai->ai_addrlen > sizeof(sockaddr_storage)) continue;
            Candidate c;
            c.family = ai->ai_family;
            c.socktype = ai->ai_socktype;
            c.protocol = ai->ai_protocol;
            c.len = ai->ai_addrlen;
            std::memcpy(&c.ss, ai->ai_addr, ai->ai_addrlen);
            c.pref = AddrConnectPreference(ai->ai_addr);
            cands.push_back(c);
        }
        freeaddrinfo(res);
        if (cands.empty()) {
            err = "resolve failed";
            Close();
            return false;
        }
        std::stable_sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
            return a.pref < b.pref;
        });

        const std::string endpoint = host + ":" + std::to_string(port);
        std::string last_try_err = "connect failed";
        for (const auto& c : cands) {
            if (stop && stop->load()) {
                err = "stopped";
                Close();
                return false;
            }
            CloseTransport();
            fd = ::socket(c.family, c.socktype, c.protocol);
            if (fd < 0) {
                last_try_err = "socket";
                continue;
            }
            SetPq1SocketOpts(fd, true);
            const int cr = connect(fd, reinterpret_cast<const sockaddr*>(&c.ss), c.len);
            if (cr != 0 && errno != EINPROGRESS) {
                last_try_err = "connect failed";
                continue;
            }
            std::string werr;
            if (!WaitFd(fd, true, handshake_ms, stop, werr)) {
                last_try_err = werr.empty() ? "connect failed" : werr;
                continue;
            }
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
            if (soerr != 0) {
                last_try_err = "connect failed";
                continue;
            }
            ssl = SSL_new(static_cast<SSL_CTX*>(ctx.SslCtx()));
            if (!ssl) {
                err = "SSL_new";
                Close();
                return false;
            }
            SSL_set_fd(ssl, fd);
            SSL_set_connect_state(ssl);
            std::string herr;
            if (!SslHandshake(ssl, fd, /*accept=*/false, handshake_ms, stop, herr)) {
                last_try_err = herr.empty() ? "PQ1 handshake failed" : herr;
                continue;
            }
            NegotiatedPq1 n;
            InspectNegotiated(ssl, n);
            if (!IsStrictPq1(n)) {
                last_try_err = "negotiated parameters are not strict PQ1";
                continue;
            }
            Digest48 pin;
            std::string pinerr;
            if (!ExtractPeerTransportPin(ssl, pin, pinerr)) {
                last_try_err = pinerr.empty() ? "no peer certificate" : pinerr;
                continue;
            }
            if (!pinfile.empty() && !CheckOrStorePin(pinfile, endpoint, pin, pinerr)) {
                err = pinerr.empty() ? "peer cert pin mismatch (TOFU)" : pinerr;
                Close();
                return false;
            }
            return true;
        }
        err = last_try_err;
        Close();
        return false;
    }

    bool Ensure(std::string& err)
    {
        if (ssl && transferred >= PQ1_RECONNECT_BYTES) Close();
        if (ssl) return true;
        if (!pq) {
            err = "PQ1 session has no context";
            return false;
        }
        return Connect(*pq, host, port, err);
    }

    bool Request(const NativeRequest& req, NativeResponse& resp, std::string& err)
    {
        if (!Ensure(err)) return false;
        std::string wire = req.method + " " + req.path + " HTTP/1.1\r\nHost: " + host + "\r\n";
        for (const auto& h : req.headers) {
            if (!h.first.empty()) wire += h.first + ": " + h.second + "\r\n";
        }
        wire += "Content-Length: " + std::to_string(req.body.size()) + "\r\nConnection: keep-alive\r\n\r\n";
        wire += req.body;
        const bool piece_http = req.path.find("/pieces/") != std::string::npos;
        const bool file_stream_get = IsFullFileStreamGet(req.method, req.path);
        const int wto = (piece_http || file_stream_get) ? PQ1_TRANSFER_MS : io_ms;
        if (!SslWriteAll(ssl, fd, wire, wto, stop, err)) {
            if (err.empty()) err = "write failed";
            Close();
            return false;
        }
        const size_t cap = piece_http ? MAX_PIECE_HTTP
                         : (file_stream_get ? FULL_FILE_STREAM_HTTP_READ_CAP : MAX_RPC_BODY + 8192);
        std::string rerr;
        const std::string raw = SslReadHttp(ssl, fd, cap, wto, stop, &rerr);
        if (file_stream_get) {
            uint64_t clen = 0;
            if (!FullFileStreamAcceptContentLength(raw, clen, err)) {
                if (err == "truncated http" && !rerr.empty()) err = rerr;
                Close();
                return false;
            }
        }
        if (!ParseHttpResponse(raw, resp, err)) {
            if (err.empty() || err == "truncated http") {
                if (!rerr.empty()) err = rerr;
            }
            Close();
            return false;
        }
        transferred += raw.size();
        return true;
    }
};

bool QueryExtPeer(Pq1Context& pq, const fs::path& pinfile, const std::string& endpoint, const std::string& ext_path,
                  const UniValue& query_body, UniValue& out, bool& timed_out, std::string& err)
{
    timed_out = false;
    std::string host;
    uint16_t port = 0;
    if (!SplitHostPort(endpoint, host, port)) {
        err = "endpoint";
        return false;
    }
    Pq1Session sess;
    sess.pinfile = pinfile;
    sess.handshake_ms = SEARCH_PEER_TIMEOUT_MS;
    sess.io_ms = SEARCH_PEER_TIMEOUT_MS;
    if (!sess.Connect(pq, host, port, err)) {
        timed_out = true;
        return false;
    }
    NativeRequest req;
    NativeResponse resp;
    req.method = "POST";
    req.path = std::string(MODEL_HTTP_ROOT) + ext_path;
    req.body = query_body.write();
    if (!sess.Request(req, resp, err) || resp.status != 200) {
        timed_out = true;
        if (err.empty()) err = "ext peer http";
        return false;
    }
    if (!out.read(resp.body) || !out.isObject()) {
        err = "ext peer json";
        return false;
    }
    return true;
}

bool QuerySearchPeer(Pq1Context& pq, const fs::path& pinfile, const std::string& endpoint,
                     const UniValue& query_body, UniValue& out, bool& timed_out, std::string& err)
{
    return QueryExtPeer(pq, pinfile, endpoint, "ext/search", query_body, out, timed_out, err);
}

std::string FirstBtxToken(const std::string& s)
{
    const auto pos = s.find("btx://");
    if (pos == std::string::npos) return {};
    size_t end = pos + 6;
    while (end < s.size() && !std::isspace(static_cast<unsigned char>(s[end])) &&
           s[end] != ',' && s[end] != '"' && s[end] != '\'' && s[end] != '}' &&
           s[end] != ']' && s[end] != ')' && s[end] != ';') ++end;
    return s.substr(pos, end - pos);
}

Digest48 IdFromUser(const std::string& s, std::string& err)
{
    const std::string token = FirstBtxToken(s);
    const std::string& use = token.empty() ? s : token;
    Resource r;
    std::string decode_err;
    if (DecodeResource(use, r, decode_err)) {
        err.clear();
        return r.digest;
    }
    Digest48 id;
    Digest48::FromHex(use, id, err);
    return id;
}

} // namespace

bool ParseHttpRequest(const std::string& raw, NativeRequest& req, std::string& err)
{
    req = {};
    const auto pos = raw.find("\r\n\r\n");
    if (pos == std::string::npos) {
        err = "truncated http";
        return false;
    }
    if (pos > MAX_HTTP_HEADERS) {
        err = "headers too large";
        return false;
    }
    std::istringstream hs(raw.substr(0, pos));
    std::string ver;
    hs >> req.method >> req.path >> ver;
    if (req.method.empty() || req.path.empty()) {
        err = "bad request line";
        return false;
    }
    std::string line;
    std::getline(hs, line);
    while (std::getline(hs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        req.headers.emplace_back(TrimCopy(line.substr(0, colon)), TrimCopy(line.substr(colon + 1)));
    }
    req.body = raw.substr(pos + 4);
    auto cl = raw.find("Content-Length:");
    if (cl == std::string::npos) cl = raw.find("content-length:");
    if (cl != std::string::npos && cl < pos) {
        const size_t v = std::strtoul(raw.c_str() + cl + 15, nullptr, 10);
        if (v > MAX_RPC_BODY && req.method != "GET") {
            err = "body too large";
            return false;
        }
        if (req.body.size() > v) req.body.resize(v);
    }
    return true;
}

std::string FormatHttpResponse(const NativeResponse& resp)
{
    const bool headers_only = resp.stream_verified_file && resp.body.empty() && resp.status == 200;
    const uint64_t clen = headers_only ? resp.stream_file_size : static_cast<uint64_t>(resp.body.size());
    std::ostringstream o;
    o << "HTTP/1.1 " << resp.status << (resp.status == 200 ? " OK" : " ERR") << "\r\n";
    o << "Content-Type: " << resp.content_type << "\r\n";
    o << "Content-Length: " << clen << "\r\n";
    for (const auto& h : resp.headers) {
        o << h.first << ": " << h.second << "\r\n";
    }
    o << "Connection: keep-alive\r\n\r\n";
    if (!headers_only) o << resp.body;
    return o.str();
}

struct SwarmRuntime {
    ProviderExchange pex;
    std::mutex pex_mu;
    ModelMapResult nat;
    std::string bind;
    bool relay{false};
    bool host{false};
    std::atomic<uint64_t> bytes_served_while_partial{0};
    std::atomic<uint64_t> pex_received{0};
    std::atomic<uint64_t> pex_accepted{0};
    std::atomic<int> partial_seeded_pieces{0};
    std::atomic<int> duplicate_endgame_requests{0};
    std::atomic<int> active_piece_requests{0};
    std::atomic<bool> current_endgame{false};
    int min_rarity{0};
    int rare_1{0};
    int rare_2{0};
    int providers_known{0};
    ReachabilityTracker reach;
    RelayTable relays;
    RoutingTable routes;
    ProviderCache providers;
    NetworkEpoch net_epoch;
    std::mutex conn_mu;
    std::atomic<int> hole_punch_attempts{0};
    std::atomic<int> hole_punch_successes{0};
    std::atomic<uint64_t> relay_bytes{0};
    std::atomic<uint64_t> direct_bytes{0};
    std::atomic<int> last_provider_lookup{0};
    std::atomic<int> provider_records_found{0};
    std::mutex snap_mu;
    UniValue last_swarm_json;
};
static SwarmRuntime g_swarm;

int64_t ConnNowMs()
{
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

static SearchIndex g_search_idx;
static SearchRuntime g_search_rt;
static std::mutex g_search_mu;
static std::map<std::string, std::vector<ProviderObservation>> g_search_obs;
static QueryDedupe g_search_dedupe;
static bool g_search_bound{false};
static FeedStore g_feed;
static CampaignIndex g_campaigns;
static std::map<std::string, FundingObservation> g_chain_obs;
static bool g_feed_loaded{false};
static fs::path g_econ_dir;
static std::unique_ptr<S3PieceStore> g_cloud;
static CloudStoreConfig g_cloud_cfg;
static DirectSeedAdmissionState g_direct_seed_admit;
static fs::path g_cloud_dir;
static std::mutex g_cloud_mu;

void PublishCatalogToCloud(const CatalogEntry& e, UniValue& result);
bool TryHydrateFromCloud(ModelCatalog& cat, CatalogEntry& e, UniValue& result, std::string& err);
void EnsureCloudLoaded(ModelCatalog& cat);
void LiveObserveCampaign(const ReleaseCampaign& c, FeedEventType t);
void LiveObserveFeed(const FeedEvent& fe);

bool AllowModelSeedBytes(const ModelCatalog& cat, size_t n);

void EnsureSearchBound()
{
    if (!g_search_bound) {
        g_search_rt.Bind(&g_search_idx);
        g_search_bound = true;
    }
}

void EnsureEconomy(ModelCatalog& cat)
{
    EnsureSearchBound();
    const fs::path dir = HelperDir(cat);
    if (g_feed_loaded && dir == g_econ_dir) return;
    g_campaigns.Clear();
    g_chain_obs.clear();
    g_feed = FeedStore();
    g_econ_dir = dir;
    g_feed_loaded = true;
    g_feed.SetPath(dir / "feed.json");
    std::string err;
    {
        std::lock_guard<std::mutex> lock(g_search_mu);
        g_search_idx.Clear();
        (void)g_search_idx.Load(dir / "search-index.json", ConnNowMs(), err);
    }
    (void)g_feed.Load(ConnNowMs(), err);
    std::vector<ReleaseCampaign> local;
    if (LoadCampaigns(dir, local, err)) {
        for (const auto& c : local) g_campaigns.Put(c, err);
    }
}

void PersistEconomy(ModelCatalog& cat)
{
    std::string err;
    (void)g_search_idx.Save(HelperDir(cat) / "search-index.json", err);
    (void)g_feed.Save(err);
    (void)SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
}

bool ReadCatalogBytes(ModelCatalog& cat, const CatalogEntry& e, std::vector<unsigned char>& out, std::string& err)
{
    if (e.core.files.empty()) {
        err = "no files";
        return false;
    }
    const auto& f = e.core.files[0];
    if (!ReleaseWrapAllowed(f.size)) {
        err = "release wrap exceeds 64 MiB; wrap is bounded";
        return false;
    }
    const uint32_t n = f.size == 0 ? 1u : static_cast<uint32_t>((f.size + PIECE_SIZE - 1) / PIECE_SIZE);
    out.clear();
    out.reserve(static_cast<size_t>(f.size));
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<unsigned char> piece;
        std::vector<Digest48> proof;
        uint64_t fs = 0;
        if (!cat.GetVerifiedPiece(e.artifact_id, 0, i, piece, proof, fs, err)) return false;
        if (out.size() + piece.size() > RELEASE_WRAP_MAX_BYTES) {
            err = "release wrap exceeds 64 MiB; wrap is bounded";
            out.clear();
            return false;
        }
        out.insert(out.end(), piece.begin(), piece.end());
    }
    if (out.size() > f.size) out.resize(f.size);
    return true;
}

FundingObservation ObservationFromHit(const SearchHit& h, const ReleaseCampaign* campaign, ModelCatalog* cat)
{
    FundingObservation f;
    f.funding_source = "OBSERVED_NETWORK_STATE";
    f.ciphertext_providers_observed = h.health.providers_observed;
    if (campaign) {
        auto it = g_chain_obs.find(campaign->release_id.Hex());
        if (it != g_chain_obs.end() && it->second.confirmed_known &&
            it->second.funding_source == "CHAIN_OBSERVATION") {
            f = it->second;
            f.ciphertext_providers_observed = std::max(f.ciphertext_providers_observed, h.health.providers_observed);
        } else {
            f.confirmed_known = false;
            f.confirmed_funded_atoms = 0;
            if (campaign->refund_height > 0) f.refund_status = RefundStatus::NOT_MATURE;
        }
        if (cat) {
            CatalogEntry local;
            Digest48 cid = campaign->ciphertext_artifact_id.IsNull() ? campaign->artifact_id : campaign->ciphertext_artifact_id;
            if (!cid.IsNull() && (cat->Find(cid, local) || cat->Find(campaign->model_id, local))) {
                f.ciphertext_providers_observed = std::max(f.ciphertext_providers_observed, 1);
            }
        }
    }
    return f;
}

ModelEconomyEntry EconomyForHit(const SearchHit& h, ModelCatalog* cat = nullptr)
{
    const ReleaseCampaign* c = g_campaigns.GetByModel(h.rec.model_id);
    if (!c && !h.rec.release_id.empty()) c = g_campaigns.GetByReleaseHex(h.rec.release_id);
    return ComposeEconomyEntry(h, c, ObservationFromHit(h, c, cat));
}

UniValue EconomyCard(const SearchHit& h)
{
    return EconomySearchCard(EconomyForHit(h));
}

void AfterIndexPut(const ModelSearchRecord& rec, int64_t now_ms)
{
    g_feed.NoteSearchRecord(rec, now_ms);
    g_campaigns.IngestFromSearchRecord(rec);
    if (BoundModelEventJournal()) {
        ObserveResult ores;
        std::string jerr;
        (void)JournalObserveSearchRecord(rec, ores, jerr);
    }
}

std::vector<ModelEconomyEntry> EconomyHits(std::vector<SearchHit> hits, const SearchQuery& q, ModelCatalog* cat = nullptr)
{
    std::vector<ModelEconomyEntry> out;
    for (auto& h : hits) {
        auto e = EconomyForHit(h, cat);
        if (!MatchesEconomyFilters(e, q.filters)) continue;
        out.push_back(std::move(e));
    }
    SortEconomyEntries(out, q.sort);
    return out;
}

void IngestCatalogIntoSearch(ModelCatalog& cat)
{
    UniValue listed;
    cat.List(listed);
    if (!listed.exists("models") || !listed["models"].isArray()) return;
    for (const auto& m : listed["models"].getValues()) {
        ModelSearchRecord r;
        std::string err;
        if (m.exists("model_id")) Digest48::FromHex(m["model_id"].get_str(), r.model_id, err);
        if (m.exists("artifact_id")) Digest48::FromHex(m["artifact_id"].get_str(), r.artifact_id, err);
        if (m.exists("uri")) r.btx_uri = m["uri"].get_str();
        if (m.exists("label")) {
            r.canonical_name = m["label"].get_str();
            r.display_name = r.canonical_name;
        }
        if (m.exists("bytes")) r.size_bytes = m["bytes"].getInt<int64_t>();
        r.signed_ok = false;
        err.clear();
        if (const auto* existing = g_search_idx.Get(r.model_id)) {
            if (existing->signed_ok || SearchRecordHasAuthoredMetadata(*existing)) {
                // Published or authored metadata wins over catalog filenames.
            } else {
                (void)g_search_idx.Put(r, ConnNowMs(), err);
            }
        } else {
            (void)g_search_idx.Put(r, ConnNowMs(), err);
        }
        if (m.exists("seeded") && m["seeded"].get_bool()) {
            auto& vec = g_search_obs[r.model_id.Hex()];
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                                     [](const ProviderObservation& o) { return o.provider_id == "local"; }),
                      vec.end());
            ProviderObservation o;
            o.provider_id = "local";
            o.endpoint = "local";
            o.complete = !(m.exists("incomplete") && m["incomplete"].get_bool());
            o.last_seen_ms = ConnNowMs();
            vec.push_back(o);
        }
    }
}

bool HandleNativeRequest(ModelCatalog& cat, const NativeRequest& req, NativeResponse& resp)
{
    resp = {};
    resp.content_type = "application/json";
    const std::string root{MODEL_HTTP_ROOT};
    if (req.path.find("btxcapability") != std::string::npos || req.path.find("capability") != std::string::npos ||
        req.path.find("btxlock") != std::string::npos || req.path.find("tensormap") != std::string::npos ||
        req.path.find("hcp") != std::string::npos) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("error", "method not allowed");
        o.pushKV("allow", "GET, HEAD");
        o.pushKV("public_runtime_rpc", false);
        o.pushKV("automatic_spend_atoms", 0);
        resp.status = 405;
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "hello") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("protocol", 2);
        o.pushKV("suite", "pq1");
        o.pushKV("group", "MLKEM768");
        o.pushKV("cipher", "TLS_AES_256_GCM_SHA384");
        o.pushKV("sigalg", "mldsa44");
        o.pushKV("automatic_spend_atoms", 0);
        o.pushKV("full_file_stream_v1", true);
        o.pushKV("capability", FULL_FILE_STREAM_V1);
        o.pushKV("capabilities", HelloCapabilityArrayMaybeIntersect(UniValue(UniValue::VOBJ)));
        o.pushKV("subpiece_v1", true);
        o.pushKV("quic", false);
        FileStreamCaps caps;
        caps.random_piece_access = true;
        caps.sequential_file_stream = true;
        o.pushKV("delivery", FileStreamCapsJson(caps));
        o.pushKV("note", "A BTX node already has compute. BTX gives it models and money.");
        resp.body = o.write();
        resp.status = 200;
        return true;
    }
    const std::string man = root + "manifests/";
    if (req.method == "GET" && req.path.rfind(man, 0) == 0) {
        Digest48 id;
        std::string err;
        UniValue manij;
        if (!Digest48::FromHex(req.path.substr(man.size()), id, err) || !cat.GetManifest(id, manij, err)) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", err);
            return true;
        }
        CatalogEntry served;
        if (!cat.Find(id, served) || !served.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "not seeded");
            return true;
        }
        if (!manij.exists("complete")) {
            manij.pushKV("complete", served.seeded && !served.incomplete);
        }
        resp.body = manij.write();
        resp.status = 200;
        return true;
    }
    const std::string pieces_pfx = root + "transfers/";
    if (req.method == "GET" && req.path.rfind(pieces_pfx, 0) == 0) {
        std::string rest = req.path.substr(pieces_pfx.size());
        const auto p1 = rest.find("/pieces/");
        if (p1 == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "expected /pieces/");
            return true;
        }
        const std::string xfer = rest.substr(0, p1);
        const std::string fp = rest.substr(p1 + 8);
        const auto slash = fp.find('/');
        if (slash == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "file/piece");
            return true;
        }
        const uint32_t file_index = static_cast<uint32_t>(std::strtoul(fp.c_str(), nullptr, 10));
        const uint32_t piece_index = static_cast<uint32_t>(std::strtoul(fp.c_str() + slash + 1, nullptr, 10));
        CatalogEntry entry;
        std::string err;
        Digest48 artifact;
        bool found = Digest48::FromHex(xfer, artifact, err) && cat.Find(artifact, entry);
        if (!found) {
            UniValue listed;
            cat.List(listed);
            if (listed.exists("models") && !listed["models"].getValues().empty()) {
                found = Digest48::FromHex(listed["models"][0]["artifact_id"].get_str(), artifact, err) &&
                        cat.Find(artifact, entry);
            }
        }
        if (!found) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "no artifact");
            return true;
        }
        if (!entry.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "not seeded");
            return true;
        }
        const std::string gp = RequestHeader(req, "X-BTX-Grant-Payload");
        const std::string gs = RequestHeader(req, "X-BTX-Grant-Sig");
        const std::string gpk = RequestHeader(req, "X-BTX-Grant-Pubkey");
        if (gp.empty() || gs.empty() || gpk.empty()) {
            resp.status = 403;
            resp.body = JsonError("ENTITLEMENT", "FreeGrant required");
            return true;
        }
        {
            const auto payload = TryParseHex<unsigned char>(gp);
            const auto sig = TryParseHex<unsigned char>(gs);
            const auto pk = TryParseHex<unsigned char>(gpk);
            UniValue gbody;
            std::string gerr;
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (!payload || !sig || !pk ||
                !VerifyFreeGrant(*payload, *sig, *pk, now, {}, gbody, gerr)) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", gerr.empty() ? "invalid FreeGrant" : gerr);
                return true;
            }
            const std::string grant_art = gbody.exists("artifact_id") ? gbody["artifact_id"].get_str() : "";
            const std::string grant_model = gbody.exists("model_id") ? gbody["model_id"].get_str() : "";
            if (grant_art != entry.artifact_id.Hex() && grant_model != entry.model_id.Hex()) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "grant object mismatch");
                return true;
            }
            const uint32_t gfile = gbody.exists("file_index") ? gbody["file_index"].getInt<uint32_t>() : 0;
            const uint32_t first = gbody.exists("first_piece") ? gbody["first_piece"].getInt<uint32_t>() : 0;
            const uint32_t count = gbody.exists("piece_count") ? gbody["piece_count"].getInt<uint32_t>() : 0;
            if (gfile != file_index || count == 0 || piece_index < first || piece_index >= first + count) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "piece not in grant range");
                return true;
            }
        }
        std::vector<unsigned char> bytes;
        std::vector<Digest48> proof;
        uint64_t file_size = 0;
        if (!cat.GetVerifiedPiece(entry.artifact_id, file_index, piece_index, bytes, proof, file_size, err)) {
            resp.status = 404;
            resp.body = JsonError("MISSING_PIECE", err);
            return true;
        }
        if (!AllowModelSeedBytes(cat, bytes.size())) {
            resp.status = 429;
            resp.body = JsonError("RESOURCE_GOVERNOR", "background upload budget exhausted");
            resp.headers.emplace_back("Retry-After", "1");
            return true;
        }
        uint64_t upload_slot = 0;
        std::string upload_err;
        if (!TryAdmitModelUpload(gpk, "", bytes.size(), upload_slot, upload_err)) {
            resp.status = 429;
            resp.body = JsonError("UPLOAD_SCHEDULER", upload_err.empty() ? "upload slots full" : upload_err);
            resp.headers.emplace_back("Retry-After", "1");
            return true;
        }
        struct UploadSlotRelease {
            uint64_t id{0};
            ~UploadSlotRelease() { ReleaseModelUpload(id); }
        } upload_guard{upload_slot};
        std::string proof_csv;
        for (size_t i = 0; i < proof.size(); ++i) {
            if (i) proof_csv += ",";
            proof_csv += proof[i].Hex();
        }
        const std::string pieces_root = file_index < entry.core.files.size() ? entry.core.files[file_index].pieces_root.Hex() : "";
        resp.status = 200;
        resp.binary = true;
        resp.content_type = "application/octet-stream";
        resp.body.assign(bytes.begin(), bytes.end());
        resp.headers.emplace_back("X-BTX-Artifact-Id", entry.artifact_id.Hex());
        resp.headers.emplace_back("X-BTX-File-Index", std::to_string(file_index));
        resp.headers.emplace_back("X-BTX-Piece-Index", std::to_string(piece_index));
        resp.headers.emplace_back("X-BTX-File-Size", std::to_string(file_size));
        resp.headers.emplace_back("X-BTX-Pieces-Root", pieces_root);
        const std::string sp_off = RequestHeader(req, "X-BTX-Subpiece-Offset");
        const std::string sp_len = RequestHeader(req, "X-BTX-Subpiece-Length");
        if (!sp_off.empty() || !sp_len.empty()) {
            SubpieceRequest spreq;
            spreq.artifact_id = entry.artifact_id.Hex();
            spreq.file_index = file_index;
            spreq.piece_index = piece_index;
            spreq.offset = std::strtoull(sp_off.c_str(), nullptr, 10);
            spreq.length = sp_len.empty() ? SUBPIECE_SIZE : std::strtoull(sp_len.c_str(), nullptr, 10);
            std::string sperr;
            if (!ValidateSubpieceRequest(spreq, file_size, sperr)) {
                resp.status = 400;
                resp.body = JsonError("SUBPIECE", sperr);
                resp.binary = false;
                resp.content_type = "application/json";
                return true;
            }
            if (spreq.offset + spreq.length > bytes.size()) {
                resp.status = 400;
                resp.body = JsonError("SUBPIECE", "subpiece out of piece");
                resp.binary = false;
                resp.content_type = "application/json";
                return true;
            }
            resp.body.assign(bytes.begin() + static_cast<std::ptrdiff_t>(spreq.offset),
                             bytes.begin() + static_cast<std::ptrdiff_t>(spreq.offset + spreq.length));
            resp.headers.emplace_back("X-BTX-Capability", SUBPIECE_V1);
            resp.headers.emplace_back("X-BTX-Subpiece-Offset", std::to_string(spreq.offset));
            resp.headers.emplace_back("X-BTX-Subpiece-Length", std::to_string(spreq.length));
            // Subpieces are delivery slices. Proof is advertised only for a full piece.
        } else {
            resp.headers.emplace_back("X-BTX-Proof", proof_csv);
        }
        if (entry.incomplete || !entry.bytes_verified) {
            g_swarm.bytes_served_while_partial.fetch_add(resp.body.size());
            g_swarm.partial_seeded_pieces.fetch_add(1);
        }
        {
            std::string nerr;
            (void)cat.NoteUsefulBytes(entry.artifact_id, static_cast<int64_t>(resp.body.size()), 0, nerr);
        }
        return true;
    }
    const std::string files_pfx = root + "files/";
    if (req.method == "GET" && req.path.rfind(files_pfx, 0) == 0) {
        const std::string rest = req.path.substr(files_pfx.size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "expected /files/{artifact}/{file}");
            return true;
        }
        std::string err;
        Digest48 artifact;
        if (!Digest48::FromHex(rest.substr(0, slash), artifact, err)) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", err);
            return true;
        }
        const uint32_t file_index = static_cast<uint32_t>(std::strtoul(rest.c_str() + slash + 1, nullptr, 10));
        CatalogEntry entry;
        if (!cat.Find(artifact, entry) || !entry.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "not seeded");
            return true;
        }
        if (file_index >= entry.core.files.size()) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "no file");
            return true;
        }
        const uint64_t file_size = entry.core.files[file_index].size;
        const uint32_t n_pieces = file_size == 0 ? 1u : static_cast<uint32_t>((file_size + PIECE_SIZE - 1) / PIECE_SIZE);
        const std::string gp = RequestHeader(req, "X-BTX-Grant-Payload");
        const std::string gs = RequestHeader(req, "X-BTX-Grant-Sig");
        const std::string gpk = RequestHeader(req, "X-BTX-Grant-Pubkey");
        if (gp.empty() || gs.empty() || gpk.empty()) {
            resp.status = 403;
            resp.body = JsonError("ENTITLEMENT", "FreeGrant required");
            return true;
        }
        {
            const auto payload = TryParseHex<unsigned char>(gp);
            const auto sig = TryParseHex<unsigned char>(gs);
            const auto pk = TryParseHex<unsigned char>(gpk);
            UniValue gbody;
            std::string gerr;
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (!payload || !sig || !pk ||
                !VerifyFreeGrant(*payload, *sig, *pk, now, {}, gbody, gerr)) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", gerr.empty() ? "invalid FreeGrant" : gerr);
                return true;
            }
            const std::string grant_art = gbody.exists("artifact_id") ? gbody["artifact_id"].get_str() : "";
            const std::string grant_model = gbody.exists("model_id") ? gbody["model_id"].get_str() : "";
            if (grant_art != entry.artifact_id.Hex() && grant_model != entry.model_id.Hex()) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "grant object mismatch");
                return true;
            }
            const uint32_t gfile = gbody.exists("file_index") ? gbody["file_index"].getInt<uint32_t>() : 0;
            const uint32_t first = gbody.exists("first_piece") ? gbody["first_piece"].getInt<uint32_t>() : 0;
            const uint32_t count = gbody.exists("piece_count") ? gbody["piece_count"].getInt<uint32_t>() : 0;
            if (gfile != file_index || first != 0 || count < n_pieces) {
                resp.status = 403;
                resp.body = JsonError("ENTITLEMENT", "grant does not cover whole file stream");
                return true;
            }
        }
        if (file_size == 0) {
            resp.status = 200;
            resp.binary = true;
            resp.content_type = "application/octet-stream";
            resp.stream_verified_file = true;
            resp.stream_artifact = entry.artifact_id;
            resp.stream_file_index = file_index;
            resp.stream_n_pieces = 0;
            resp.stream_file_size = 0;
            resp.headers.emplace_back("X-BTX-Artifact-Id", entry.artifact_id.Hex());
            resp.headers.emplace_back("X-BTX-File-Index", std::to_string(file_index));
            resp.headers.emplace_back("X-BTX-File-Size", "0");
            resp.headers.emplace_back("X-BTX-Pieces-Root", entry.core.files[file_index].pieces_root.Hex());
            resp.headers.emplace_back("X-BTX-Capability", FULL_FILE_STREAM_V1);
            return true;
        }
        std::string peer = RequestHeader(req, "X-BTX-From");
        if (peer.empty()) peer = "pq1-peer";
        std::string ng = RequestHeader(req, "X-BTX-Netgroup");
        if (ng.empty()) ng = "pq1";
        std::string serr;
        if (!GlobalOriginStampede().Allow(peer, ng, ConnNowMs(), serr)) {
            resp.status = 429;
            resp.body = JsonError("ORIGIN_STAMPEDE", serr);
            return true;
        }
        resp.status = 200;
        resp.binary = true;
        resp.content_type = "application/octet-stream";
        resp.stream_verified_file = true;
        resp.stream_artifact = entry.artifact_id;
        resp.stream_file_index = file_index;
        resp.stream_n_pieces = n_pieces;
        resp.stream_file_size = file_size;
        resp.headers.emplace_back("X-BTX-Artifact-Id", entry.artifact_id.Hex());
        resp.headers.emplace_back("X-BTX-File-Index", std::to_string(file_index));
        resp.headers.emplace_back("X-BTX-File-Size", std::to_string(file_size));
        resp.headers.emplace_back("X-BTX-Pieces-Root", entry.core.files[file_index].pieces_root.Hex());
        resp.headers.emplace_back("X-BTX-Capability", FULL_FILE_STREAM_V1);
        GlobalOriginStampede().NoteSuccess(peer);
        return true;
    }
    if (req.path == root + "availability" && req.method == "POST") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        UniValue listed;
        cat.List(listed);
        UniValue pub(UniValue::VOBJ);
        pub.pushKV("schema_version", 2);
        pub.pushKV("coverage", "incomplete");
        UniValue models(UniValue::VARR);
        if (listed.exists("models")) {
            for (const auto& m : listed["models"].getValues()) {
                bool any = false;
                if (m.exists("files") && m["files"].isArray()) {
                    for (const auto& f : m["files"].getValues()) {
                        if (f.exists("piece_count") && f["piece_count"].getInt<int>() > 0) any = true;
                    }
                }
                if (!any && (!m.exists("seeded") || !m["seeded"].get_bool())) continue;
                UniValue one = m;
                if (one.exists("files") && one["files"].isArray()) {
                    UniValue files(UniValue::VARR);
                    for (const auto& f : one["files"].getValues()) {
                        UniValue ff = f;
                        if (f.exists("ranges")) {
                            std::vector<PieceRange> rs;
                            std::string rerr;
                            if (ParsePieceRangesJson(f["ranges"], rs, rerr)) {
                                ff.pushKV("range_pairs", PieceRangesToPairsJson(rs));
                            }
                        }
                        files.push_back(ff);
                    }
                    one.pushKV("files", files);
                }
                if (!one.exists("observed_sources") || one["observed_sources"].getInt<int>() == 0) {
                    one.pushKV("observed_sources", 1);
                }
                const bool complete = one.exists("complete") && one["complete"].get_bool();
                one.pushKV("complete", complete);
                if (!complete) {
                    one.pushKV("partial", true);
                }
                models.push_back(one);
            }
        }
        pub.pushKV("models", models);
        pub.pushKV("local_count", static_cast<int>(models.size()));
        o.pushKV("local", pub);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/pex" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "pex body");
            return true;
        }
        std::string err;
        std::vector<ProviderHint> accepted;
        const int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        std::string from = RequestHeader(req, "X-BTX-From");
        if (from.empty()) from = "peer";
        {
            std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
            if (!g_swarm.pex.Ingest(from, body, now, accepted, err)) {
                resp.status = 400;
                resp.body = JsonError("PEX_REJECT", err);
                return true;
            }
            g_swarm.pex_received.store(g_swarm.pex.Stats().received);
            g_swarm.pex_accepted.store(g_swarm.pex.Stats().accepted);
            g_swarm.providers_known = static_cast<int>(g_swarm.pex.Recent(now).size());
        }
        for (const auto& h : accepted) cat.AddPeer(h.endpoint);
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("accepted", static_cast<int>(accepted.size()));
        o.pushKV("authoritative", false);
        o.pushKV("note", "hints only; PQ1 still required");
        {
            std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
            UniValue adv = g_swarm.pex.Advertise(now, PEX_MAX_RECORDS_PER_MESSAGE);
            if (adv.exists("providers")) o.pushKV("providers", adv["providers"]);
        }
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/rendezvous" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "rendezvous body");
            return true;
        }
        std::string err;
        const std::string endpoint = body.exists("endpoint") ? body["endpoint"].get_str() : "";
        const std::string expected = body.exists("expected_service_id") ? body["expected_service_id"].get_str() : "";
        const std::string presented = body.exists("service_id") ? body["service_id"].get_str() : "";
        if (!ValidateRendezvous(endpoint, expected, presented, err)) {
            resp.status = 403;
            resp.body = JsonError("RENDEZVOUS_REJECT", err);
            return true;
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("ok", true);
        o.pushKV("pq1_required", true);
        o.pushKV("classical_fallback", false);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/relay/connect" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "relay body");
            return true;
        }
        RelayConnectRequest rr;
        rr.endpoint = (body.exists("endpoint") && body["endpoint"].isStr()) ? body["endpoint"].get_str() : "";
        rr.expected_service_id = body.exists("expected_service_id") && body["expected_service_id"].isStr()
                                     ? body["expected_service_id"].get_str() : "";
        rr.presented_service_id = body.exists("service_id") && body["service_id"].isStr()
                                        ? body["service_id"].get_str() : "";
        std::string err;
        if (!ValidateRelayConnect(rr, g_swarm.relay, err)) {
            resp.status = 403;
            resp.body = JsonError("RELAY_REJECT", err);
            return true;
        }
        std::string host;
        uint16_t port = 0;
        if (!SplitListenBind(rr.endpoint, host, port)) {
            resp.status = 400;
            resp.body = JsonError("BAD_ENDPOINT", "host:port");
            return true;
        }
        if (S3HostBlockedAsMetadata(host)) {
            resp.status = 403;
            resp.body = JsonError("RELAY_REJECT", "relay dial target blocked");
            return true;
        }
        resp.status = 200;
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("ok", true);
        o.pushKV("inner_pq1", true);
        o.pushKV("relay_impersonation", false);
        resp.body = o.write();
        resp.splice_tcp = true;
        resp.splice_host = host;
        resp.splice_port = port;
        return true;
    }
    if (req.path == root + "ext/autonat/probe" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "probe body");
            return true;
        }
        DialbackRequest dr;
        dr.request_id = body.exists("request_id") ? body["request_id"].get_str() : "";
        dr.candidate = body.exists("candidate") ? body["candidate"].get_str() : "";
        dr.requester = body.exists("requester") ? body["requester"].get_str() : "peer";
        dr.requester_netgroup = body.exists("requester_netgroup") ? body["requester_netgroup"].get_str() : "";
        dr.now_ms = ConnNowMs();
        std::string err;
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        if (!g_swarm.reach.AdmitProbe(dr, err)) {
            resp.status = 400;
            resp.body = JsonError("PROBE_REJECT", err);
            return true;
        }
        g_swarm.reach.FinishProbe();
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("ok", true);
        o.pushKV("would_dial", true);
        o.pushKV("pq1_required", true);
        o.pushKV("scanner", false);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/autonat/report" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "report body");
            return true;
        }
        DialbackReport r;
        r.request_id = body.exists("request_id") ? body["request_id"].get_str() : "";
        r.observer_id = body.exists("observer_id") ? body["observer_id"].get_str() : "";
        r.observer_netgroup = body.exists("observer_netgroup") ? body["observer_netgroup"].get_str() : "";
        r.observed_endpoint = body.exists("observed_endpoint") ? body["observed_endpoint"].get_str() : "";
        r.ok = body.exists("ok") && body["ok"].get_bool();
        r.at_ms = ConnNowMs();
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        g_swarm.reach.NoteReport(r, r.at_ms);
        resp.body = g_swarm.reach.StatusJson().write();
        return true;
    }
    if (req.path == root + "ext/relay/reserve" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "reserve body");
            return true;
        }
        RelayReservation out;
        std::string err;
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        if (!g_swarm.relays.Reserve(body.exists("service_id") ? body["service_id"].get_str() : "",
                                    body.exists("netgroup") ? body["netgroup"].get_str() : "",
                                    body.exists("relay_endpoint") ? body["relay_endpoint"].get_str() : "",
                                    ConnNowMs(), out, err)) {
            resp.status = 403;
            resp.body = JsonError("RESERVE_REJECT", err);
            return true;
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("reservation_id", out.reservation_id);
        o.pushKV("expiry_ms", out.expiry_ms);
        o.pushKV("byte_ceiling", static_cast<int>(out.byte_ceiling));
        o.pushKV("inner_pq1", true);
        o.pushKV("automatic_spend_atoms", 0);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/holepunch" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "holepunch body");
            return true;
        }
        std::vector<std::string> local, remote;
        if (body.exists("local") && body["local"].isArray()) {
            for (const auto& v : body["local"].getValues()) {
                if (v.isStr()) local.push_back(v.get_str());
            }
        }
        if (body.exists("remote") && body["remote"].isArray()) {
            for (const auto& v : body["remote"].getValues()) {
                if (v.isStr()) remote.push_back(v.get_str());
            }
        }
        PunchPlan plan;
        std::string err;
        const int64_t rtt = body.exists("rtt_ms") ? body["rtt_ms"].getInt<int64_t>() : 40;
        if (!PlanHolePunch(local, remote, ConnNowMs(), rtt, plan, err)) {
            resp.status = 400;
            resp.body = JsonError("PUNCH_REJECT", err);
            return true;
        }
        const bool direct = body.exists("direct") && body["direct"].get_bool();
        const bool pq1 = body.exists("pq1") && body["pq1"].get_bool();
        const bool ident = body.exists("identity") && body["identity"].get_bool();
        g_swarm.hole_punch_attempts.fetch_add(1);
        const PunchResult pr = RecordPunchAttempt(plan, direct, pq1, ident, false);
        if (pr == PunchResult::DIRECT_OK) g_swarm.hole_punch_successes.fetch_add(1);
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("result", pr == PunchResult::DIRECT_OK ? "direct" : (pr == PunchResult::RETAIN_RELAY ? "relay" : "retry"));
        o.pushKV("pq1_required", true);
        o.pushKV("classical_fallback", false);
        o.pushKV("relay_skips_identity", false);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/providers/put" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "provider body");
            return true;
        }
        ProviderRecord rec;
        std::string err;
        if (!ProviderRecordFromJson(body, rec, err)) {
            resp.status = 400;
            resp.body = JsonError("PROVIDER_TYPE", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        if (!g_swarm.providers.Put(rec, ConnNowMs(), err)) {
            resp.status = 403;
            resp.body = JsonError("PROVIDER_REJECT", err);
            return true;
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("ok", true);
        o.pushKV("inference", false);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/providers/get" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "get body");
            return true;
        }
        Digest48 id;
        std::string err;
        if (!body.exists("resource") || !Digest48::FromHex(body["resource"].get_str(), id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        const auto found = g_swarm.providers.Get(id, ConnNowMs());
        g_swarm.last_provider_lookup.store(static_cast<int>(ConnNowMs() / 1000));
        g_swarm.provider_records_found.store(static_cast<int>(found.size()));
        UniValue arr(UniValue::VARR);
        for (const auto& r : found) arr.push_back(ProviderRecordToJson(r));
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("records", arr);
        o.pushKV("authoritative", false);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/search" && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "search body");
            return true;
        }
        if (body.write().size() > SEARCH_QUERY_BYTES_MAX) {
            resp.status = 413;
            resp.body = JsonError("QUERY_TOO_LARGE", "max query bytes");
            return true;
        }
        std::string qid = body.exists("query_id") ? body["query_id"].get_str() : "";
        int ttl = body.exists("ttl") ? body["ttl"].getInt<int>() : SEARCH_TTL_DEFAULT;
        if (ttl > SEARCH_TTL_MAX) ttl = SEARCH_TTL_MAX;
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (!qid.empty() && !g_search_dedupe.Admit(qid)) {
            UniValue o = SearchResponseJson(qid, "local", {}, true);
            o.pushKV("duplicate", true);
            resp.body = o.write();
            return true;
        }
        SearchQuery q;
        std::string err;
        if (!ParseSearchQuery(body, q, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        q.scope = SearchScope::LOCAL;
        const auto hits = g_search_idx.Search(q, ConnNowMs());
        UniValue o = SearchResponseJson(qid.empty() ? NewSearchQueryId() : qid, "local", hits,
                                         static_cast<int>(hits.size()) >= q.limit);
        o.pushKV("ttl_remaining", std::max(0, ttl - 1));
        o.pushKV("forward", ShouldForwardSearch(ttl - 1, 1));
        o.pushKV("authoritative", false);
        o.pushKV("node_model_index", true);
        resp.body = o.write();
        return true;
    }
    if (req.path == root + "ext/feed" && req.method == "POST") {
        EnsureEconomy(cat);
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "feed body");
            return true;
        }
        FeedQuery fq;
        if (body.exists("mode")) ParseFeedMode(body["mode"].get_str(), fq.mode);
        if (body.exists("limit")) fq.limit = body["limit"].getInt<int>();
        if (body.exists("cursor")) fq.cursor = body["cursor"].get_str();
        fq.scope = SearchScope::LOCAL;
        std::lock_guard<std::mutex> lock(g_search_mu);
        std::string next;
        const auto items = g_feed.Query(fq, ConnNowMs(), next);
        std::vector<ModelEconomyEntry> entries;
        UniValue recs(UniValue::VARR);
        for (const auto& ev : items) {
            SearchHit h;
            h.rec = ev.rec;
            if (h.rec.model_id.IsNull()) h.rec.model_id = ev.model_id;
            entries.push_back(EconomyForHit(h));
            recs.push_back(SearchRecordToJson(h.rec));
        }
        FeedCoverage cov;
        UniValue o = FeedPageJson(items, entries, fq, cov, g_feed.Sequence(), next);
        o.pushKV("records", recs);
        o.pushKV("authoritative", false);
        resp.body = o.write();
        return true;
    }
    if ((req.path == root + "quotes" || req.path == std::string(MODEL_HTTP_ROOT) + "quotes") && req.method == "POST") {
        UniValue body;
        if (!body.read(req.body) || !body.isObject()) {
            resp.status = 400;
            resp.body = JsonError("BAD_JSON", "quote body");
            return true;
        }
        Digest48 model_id, artifact_id;
        std::string err;
        if (!body.exists("model_id") || !Digest48::FromHex(body["model_id"].get_str(), model_id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        if (body.exists("artifact_id") && !body["artifact_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["artifact_id"].get_str(), artifact_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", err);
                return true;
            }
        }
        const int64_t price = body.exists("price_atoms") ? body["price_atoms"].getInt<int64_t>() : 0;
        Quote q;
        if (!MakePrepaidQuote(q, model_id, artifact_id, 0, body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0, price, err)) {
            resp.status = 500;
            resp.body = JsonError("QUOTE", err);
            return true;
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        quotes.push_back(q);
        SavePaymentState(dir, quotes, journal, err);
        resp.status = 200;
        resp.body = QuoteToJson(q).write();
        return true;
    }
    if (req.method == "POST" && req.path.find("/payment") != std::string::npos) {
        UniValue body;
        if (!body.read(req.body) || !body.isObject() || !body.exists("txid") || !body.exists("quote_id")) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "quote_id and txid required");
            return true;
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        std::string err;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        const std::string txid = body["txid"].get_str();
        const std::string quote_id = body["quote_id"].get_str();
        if (DuplicatePayment(journal, txid)) {
            resp.status = 409;
            resp.body = JsonError("DUPLICATE_PAYMENT", "txid already recorded; retry does not pay again");
            return true;
        }
        if (txid.size() < 8 || !IsHex(txid)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "txid");
            return true;
        }
        bool known_quote = false;
        for (const auto& q : quotes) {
            if (q.offer_id.Hex() == quote_id) {
                known_quote = true;
                break;
            }
        }
        if (!known_quote) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "unknown quote_id");
            return true;
        }
        if (body.exists("release_reorg_hold") && body["release_reorg_hold"].isBool() &&
            body["release_reorg_hold"].get_bool()) {
            if (!ReleaseReorgHold(journal, txid, err)) {
                resp.status = 409;
                resp.body = JsonError("REORG_HOLD", err);
                return true;
            }
            SavePaymentState(dir, quotes, journal, err);
            UniValue rel(UniValue::VOBJ);
            rel.pushKV("schema_version", 2);
            rel.pushKV("txid", txid);
            rel.pushKV("delivered", true);
            rel.pushKV("held_for_reorg", false);
            resp.body = rel.write();
            return true;
        }
        PaymentJournal e;
        e.quote_id = quote_id;
        e.txid = txid;
        e.accepted = false;
        e.file_index = body.exists("file_index") ? body["file_index"].getInt<uint32_t>() : 0;
        e.first_piece = body.exists("first_piece") ? body["first_piece"].getInt<uint32_t>() : 0;
        e.piece_count = body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0;
        if (e.piece_count > 0 && DuplicateReservedRange(journal, e.file_index, e.first_piece, e.piece_count)) {
            resp.status = 409;
            resp.body = JsonError("DUPLICATE_PAYMENT", "range already reserved; restart does not pay again");
            return true;
        }
        const bool reorg_hold = body.exists("reorg_hold") && body["reorg_hold"].isBool() && body["reorg_hold"].get_bool();
        std::string hold_err;
        (void)ApplyPaymentDelivery(e, reorg_hold, hold_err);
        if (!reorg_hold) {
            e.accepted = false;
            e.delivered = false;
            e.held_for_reorg = false;
        }
        journal.push_back(e);
        SavePaymentState(dir, quotes, journal, err);
        UniValue o(UniValue::VOBJ);
        o.pushKV("schema_version", 2);
        o.pushKV("recorded", true);
        o.pushKV("accepted", e.accepted);
        o.pushKV("delivered", e.delivered);
        o.pushKV("held_for_reorg", e.held_for_reorg);
        o.pushKV("note", "Journal records intent. Chain settlement is 0.34.6 wallet RPCs; helper does not verify the chain.");
        if (reorg_hold) o.pushKV("error", hold_err);
        resp.body = o.write();
        return true;
    }
    if ((req.path == root + "query") && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 512, body, resp)) return true;
        UniValue ids(UniValue::VARR);
        UniValue listed;
        cat.List(listed);
        std::string qerr;
        if (body.exists("root") && body["root"].isStr()) {
            Digest48 id;
            if (Digest48::FromHex(body["root"].get_str(), id, qerr)) {
                CatalogEntry e;
                if (cat.Find(id, e) && e.seeded) ids.push_back(e.model_id.Hex());
                std::lock_guard<std::mutex> lock(g_ext_mu);
                for (const auto& h : RecordsFor(cat).LookupExact(id, static_cast<int64_t>(std::time(nullptr)))) {
                    ids.push_back(h.record_id.Hex());
                }
            }
        } else if (body.exists("text") && body["text"].isStr()) {
            const std::string q = ToLower(body["text"].get_str());
            int limit = 32;
            if (body.exists("limit")) limit = std::min(32, body["limit"].getInt<int>());
            if (listed.exists("models")) {
                for (const auto& m : listed["models"].getValues()) {
                    if (static_cast<int>(ids.size()) >= limit) break;
                    if (!m.exists("seeded") || !m["seeded"].get_bool()) continue;
                    const std::string hay = ToLower(m.write());
                    if (hay.find(q) != std::string::npos) ids.push_back(m["model_id"].get_str());
                }
            }
        }
        UniValue qo(UniValue::VOBJ);
        qo.pushKV("schema_version", 2);
        qo.pushKV("coverage", "incomplete");
        qo.pushKV("ids", ids);
        qo.pushKV("local_count", listed.exists("local_count") ? listed["local_count"] : 0);
        resp.body = qo.write();
        return true;
    }
    if (req.path == root + "records/get" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        UniValue recs(UniValue::VARR);
        std::lock_guard<std::mutex> lock(g_ext_mu);
        auto& cache = RecordsFor(cat);
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        UniValue want = body.exists("ids") ? body["ids"] : UniValue(UniValue::VARR);
        size_t n = 0;
        for (const auto& idv : want.getValues()) {
            if (n >= 16) break;
            Digest48 id;
            std::string e;
            if (!idv.isStr() || !Digest48::FromHex(idv.get_str(), id, e)) continue;
            for (const auto& h : cache.LookupExact(id, now)) {
                recs.push_back(HintJson(h));
                ++n;
            }
        }
        UniValue orec(UniValue::VOBJ);
        orec.pushKV("schema_version", 2);
        orec.pushKV("records", recs);
        resp.body = orec.write();
        return true;
    }
    if (req.path == root + "records/announce" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        SignedRecordHint h;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (!AcceptSignedAnnounce(body, now, h, err)) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_ext_mu);
        if (!RecordsFor(cat).Insert(h, now, err)) {
            resp.status = 400;
            resp.body = JsonError("RECORD", err);
            return true;
        }
        PersistRecords(cat, RecordsFor(cat));
        UniValue oann(UniValue::VOBJ);
        oann.pushKV("schema_version", 2);
        oann.pushKV("accepted", true);
        oann.pushKV("signed", true);
        oann.pushKV("record_id", h.record_id.Hex());
        resp.body = oann.write();
        return true;
    }
    if (req.method == "POST" && req.path.rfind(root + "releases/", 0) == 0) {
        const std::string rest = req.path.substr((root + "releases/").size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos) {
            resp.status = 400;
            resp.body = JsonError("BAD_PATH", "releases/{id}/{pledges|rounds|signatures}");
            return true;
        }
        const std::string idhex = rest.substr(0, slash);
        const std::string action = rest.substr(slash + 1);
        Digest48 id;
        std::string err;
        if (!Digest48::FromHex(idhex, id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", err);
            return true;
        }
        UniValue body;
        const size_t cap = (action == "pledges") ? 16 * 1024 : 512 * 1024;
        if (!JsonBody(req, cap, body, resp)) return true;
        if (action == "pledges") {
            std::vector<ReleaseCampaign> campaigns;
            LoadCampaigns(HelperDir(cat), campaigns, err);
            bool found = false;
            const int64_t atoms = body.exists("amount_atoms") ? body["amount_atoms"].getInt<int64_t>() : 0;
            for (auto& c : campaigns) {
                if (c.release_id == id) {
                    c.pledged_atoms += atoms;
                    found = true;
                    resp.body = CampaignToJson(c).write();
                }
            }
            if (!found) {
                resp.status = 404;
                resp.body = JsonError("NOT_FOUND", "unknown release");
                return true;
            }
            SaveCampaigns(HelperDir(cat), campaigns, err);
            return true;
        }
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "release-coord.json", store);
        if (!store.isObject()) store = UniValue(UniValue::VOBJ);
        UniValue one = store.exists(idhex) ? store[idhex] : UniValue(UniValue::VOBJ);
        if (action == "rounds") {
            one.pushKV("round", body);
            one.pushKV("frozen", true);
        } else if (action == "signatures") {
            UniValue sigs = one.exists("signatures") ? one["signatures"] : UniValue(UniValue::VARR);
            sigs.push_back(body);
            one.pushKV("signatures", sigs);
        } else {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "unknown release action");
            return true;
        }
        store.pushKV(idhex, one);
        WriteJsonFile(HelperDir(cat) / "release-coord.json", store, err);
        UniValue orel(UniValue::VOBJ);
        orel.pushKV("schema_version", 2);
        orel.pushKV("release_id", idhex);
        orel.pushKV("action", action);
        orel.pushKV("note", "coordination only; broadcast funding with btxd; claim via buildhtlcclaim");
        resp.body = orel.write();
        return true;
    }
    if ((req.path == root + "ext/caps") && (req.method == "POST" || req.method == "GET")) {
        UniValue oc(UniValue::VOBJ);
        oc.pushKV("extension_version", static_cast<int>(EXT_VERSION));
        oc.pushKV("features", static_cast<int>(EXT_FEATURES));
        oc.pushKV("max_envelope_bytes", 81920);
        oc.pushKV("schema_version", 2);
        resp.body = oc.write();
        return true;
    }
    if (req.path == root + "ext/resolve" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 512, body, resp)) return true;
        uint8_t kind = static_cast<uint8_t>(ResourceKind::MODEL);
        std::string kerr;
        if (body.exists("kind") && !KindFromJson(body["kind"], kind, kerr)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", kerr);
            return true;
        }
        std::string digest;
        if (body.exists("digest48") && body["digest48"].isStr()) digest = body["digest48"].get_str();
        else if (body.exists("id") && body["id"].isStr()) digest = body["id"].get_str();
        resp.body = TypedResolveJson(cat, kind, digest).write();
        return true;
    }
    if (req.path == root + "ext/objects/get" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 1024, body, resp)) return true;
        UniValue objs(UniValue::VARR);
        std::lock_guard<std::mutex> lock(g_ext_mu);
        auto& cache = RecordsFor(cat);
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        size_t n = 0;
        UniValue want = body.exists("ids") ? body["ids"] : UniValue(UniValue::VARR);
        for (const auto& idv : want.getValues()) {
            if (n >= 8) break;
            Digest48 id;
            std::string e;
            if (!idv.isStr() || !Digest48::FromHex(idv.get_str(), id, e)) continue;
            for (const auto& h : cache.LookupExact(id, now)) {
                objs.push_back(HintJson(h));
                ++n;
            }
        }
        UniValue oobj(UniValue::VOBJ);
        oobj.pushKV("schema_version", 2);
        oobj.pushKV("objects", objs);
        oobj.pushKV("coverage", "incomplete");
        resp.body = oobj.write();
        return true;
    }
    if (req.path == root + "ext/objects/announce" && req.method == "POST") {
        if (req.body.size() > 80 * 1024) {
            resp.status = 400;
            resp.body = JsonError("TOO_LARGE", "envelope exceeds 80 KiB");
            return true;
        }
        UniValue body;
        SignedRecordHint h;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (req.body.empty() || req.body[0] != '{') {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", "unsigned envelope rejected");
            return true;
        }
        if (!JsonBody(req, 80 * 1024, body, resp)) return true;
        if (!AcceptSignedAnnounce(body, now, h, err)) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", err);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_ext_mu);
        if (!RecordsFor(cat).Insert(h, now, err)) {
            resp.status = 400;
            resp.body = JsonError("RECORD", err);
            return true;
        }
        PersistRecords(cat, RecordsFor(cat));
        UniValue oann(UniValue::VOBJ);
        oann.pushKV("schema_version", 2);
        oann.pushKV("accepted", true);
        oann.pushKV("signed", true);
        oann.pushKV("record_id", h.record_id.Hex());
        resp.body = oann.write();
        return true;
    }
    if (req.path == root + "ext/free/grant" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        if (GrantHasPaymentFields(body)) {
            resp.status = 400;
            resp.body = JsonError("PAYMENT_FIELD", "FreeGrant has no payment script, address, amount, fee, or confirmation field");
            return true;
        }
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (body.exists("expires_at")) {
            const int64_t exp = body["expires_at"].getInt<int64_t>();
            if (exp <= now) {
                resp.status = 400;
                resp.body = JsonError("EXPIRED", "grant expired");
                return true;
            }
        }
        Digest48 model_id;
        std::string err;
        if (!body.exists("model_id") || !Digest48::FromHex(body["model_id"].get_str(), model_id, err)) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "model_id");
            return true;
        }
        CatalogEntry e;
        if (!cat.Find(model_id, e) || !e.seeded) {
            resp.status = 404;
            resp.body = JsonError("NOT_FOUND", "no seeded local grant");
            return true;
        }
        const uint32_t file_index = body.exists("file_index") ? body["file_index"].getInt<uint32_t>() : 0;
        if (file_index >= e.core.files.size() && !e.core.files.empty()) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "file_index");
            return true;
        }
        const uint64_t file_size = e.core.files.empty() ? 1 : e.core.files[file_index].size;
        const uint32_t n_pieces = file_size == 0 ? 1u : static_cast<uint32_t>((file_size + PIECE_SIZE - 1) / PIECE_SIZE);
        const uint32_t first_piece = body.exists("first_piece") ? body["first_piece"].getInt<uint32_t>() : 0;
        uint32_t piece_count = body.exists("piece_count") ? body["piece_count"].getInt<uint32_t>() : 0;
        if (piece_count == 0) piece_count = n_pieces > first_piece ? n_pieces - first_piece : 0;
        if (piece_count == 0 || first_piece >= n_pieces || first_piece > n_pieces - piece_count) {
            resp.status = 400;
            resp.body = JsonError("INVALID_PARAMETER", "piece range");
            return true;
        }
        const uint64_t start = uint64_t{first_piece} * PIECE_SIZE;
        const uint64_t end = std::min(file_size == 0 ? uint64_t{1} : file_size, start + uint64_t{piece_count} * PIECE_SIZE);
        const uint64_t maximum_bytes = body.exists("maximum_bytes") ? body["maximum_bytes"].getInt<uint64_t>() : (end > start ? end - start : 1);

        Digest48 buyer_id{};
        if (body.exists("buyer_id") && !body["buyer_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["buyer_id"].get_str(), buyer_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "buyer_id");
                return true;
            }
        }
        Hash32 grant_nonce{};
        if (body.exists("grant_nonce")) {
            if (!Hash32::FromHex(body["grant_nonce"].get_str(), grant_nonce, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "grant_nonce");
                return true;
            }
        } else {
            GetStrongRandBytes(Span<unsigned char>{grant_nonce.data.data(), grant_nonce.data.size()});
        }
        uint64_t sequence = 1;
        if (!ConsumeGrantNonce(HelperDir(cat), grant_nonce.Hex(), sequence, err)) {
            resp.status = err == "replay" ? 409 : 400;
            resp.body = JsonError(err == "replay" ? "REPLAY" : "GRANT", err);
            return true;
        }
        std::vector<unsigned char> pk, sk;
        Digest48 signer_id;
        if (!LoadOrCreateServiceIdentity(HelperDir(cat), pk, sk, signer_id, err)) {
            resp.status = 500;
            resp.body = JsonError("CRYPTO", err);
            return true;
        }
        FreeGrantParams gp;
        gp.sequence = sequence;
        gp.issued_at = now;
        gp.expires_at = now + FREE_GRANT_LIFETIME_S;
        if (body.exists("issued_at")) gp.issued_at = body["issued_at"].getInt<int64_t>();
        if (body.exists("expires_at")) gp.expires_at = body["expires_at"].getInt<int64_t>();
        gp.buyer_id = buyer_id;
        gp.model_id = e.model_id;
        gp.artifact_id = e.artifact_id;
        if (body.exists("artifact_id") && !body["artifact_id"].get_str().empty()) {
            if (!Digest48::FromHex(body["artifact_id"].get_str(), gp.artifact_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "artifact_id");
                return true;
            }
            if (gp.artifact_id != e.artifact_id) {
                resp.status = 400;
                resp.body = JsonError("OBJECT_MISMATCH", "artifact_id");
                return true;
            }
        }
        gp.file_index = file_index;
        gp.first_piece = first_piece;
        gp.piece_count = piece_count;
        gp.maximum_bytes = maximum_bytes;
        gp.grant_nonce = grant_nonce;
        gp.queue_class = body.exists("queue_class") ? static_cast<uint8_t>(body["queue_class"].getInt<uint64_t>()) : 0;
        if (body.exists("transfer_id")) {
            if (!Hash32::FromHex(body["transfer_id"].get_str(), gp.transfer_id, err)) {
                resp.status = 400;
                resp.body = JsonError("INVALID_PARAMETER", "transfer_id");
                return true;
            }
        }
        SignedFreeGrant issued;
        if (!IssueFreeGrant(gp, sk, pk, issued, err)) {
            resp.status = 400;
            resp.body = JsonError("GRANT", err);
            return true;
        }
        if (issued.body["signer_id"].get_str() != signer_id.Hex()) {
            resp.status = 500;
            resp.body = JsonError("CRYPTO", "signer_id");
            return true;
        }
        const bool octet = (body.exists("octet_stream") && body["octet_stream"].get_bool()) ||
                            (body.exists("format") && body["format"].isStr() && body["format"].get_str() == "octet-stream");
        if (octet) {
            std::vector<unsigned char> env;
            if (!EncodeGrantEnvelope(issued, env, err)) {
                resp.status = 500;
                resp.body = JsonError("GRANT", err);
                return true;
            }
            resp.content_type = "application/octet-stream";
            resp.binary = true;
            resp.body.assign(env.begin(), env.end());
            return true;
        }
        resp.body = SignedGrantToJson(issued).write();
        return true;
    }
    if (req.path == root + "ext/receipts" && req.method == "POST") {
        UniValue body;
        if (!JsonBody(req, 16 * 1024, body, resp)) return true;
        std::string err;
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (!body.exists("payload_hex") || !body.exists("sig_hex") || !body.exists("pubkey_hex")) {
            resp.status = 400;
            resp.body = JsonError("UNSIGNED", "ServiceReceipt must be signed");
            return true;
        }
        const auto payload = TryParseHex<unsigned char>(body["payload_hex"].get_str());
        const auto sig = TryParseHex<unsigned char>(body["sig_hex"].get_str());
        const auto pk = TryParseHex<unsigned char>(body["pubkey_hex"].get_str());
        UniValue decoded;
        Digest48 rid;
        if (!payload || !sig || !pk ||
            !VerifyTypedRecord(RECORD_SERVICE_RECEIPT, *payload, *sig, *pk, now, decoded, rid, err)) {
            resp.status = 400;
            resp.body = JsonError("RECEIPT", err.empty() ? "invalid ServiceReceipt" : err);
            return true;
        }
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "receipts.json", store);
        UniValue arr = store.exists("receipts") ? store["receipts"] : UniValue(UniValue::VARR);
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("record_id", rid.Hex());
        rec.pushKV("received_at", now);
        rec.pushKV("payload_hex", body["payload_hex"].get_str());
        rec.pushKV("signed", true);
        arr.push_back(rec);
        store.pushKV("schema_version", 2);
        store.pushKV("receipts", arr);
        WriteJsonFile(HelperDir(cat) / "receipts.json", store, err);
        UniValue orc(UniValue::VOBJ);
        orc.pushKV("schema_version", 2);
        orc.pushKV("recorded", true);
        orc.pushKV("broadcast", false);
        orc.pushKV("record_id", rid.Hex());
        resp.body = orc.write();
        return true;
    }
    resp.status = 404;
    resp.body = JsonError("NOT_FOUND", "unknown /btx-model/2/ path");
    return true;
}

bool NativeHttpRequiresVerifiedPq1()
{
    // HandleNativeRequest is only invoked from HandlePq1Fd after IsStrictPq1.
    // Unix JSON-RPC is a local socket, not a native HTTP endpoint.
    return true;
}

std::vector<std::string> AdvertisedNativeHttpPaths()
{
    std::vector<std::string> out;
    const UniValue caps = CapabilitiesObject();
    if (!caps.exists("http") || !caps["http"].isArray()) return out;
    for (const auto& p : caps["http"].getValues()) {
        if (p.isStr()) out.push_back(p.get_str());
    }
    return out;
}

namespace {

constexpr size_t kKeepTerminalRetrieveJobs = 8;

struct RetrieveJob {
    std::string id;
    Digest48 model_id;
    fs::path modeldir;
    int64_t created_ms{0};
    std::string status{"queued"};
    UniValue result;
    std::string err;
    std::string last_peer;
    std::string last_err;
    mutable std::mutex mu;
    RetrieveProgress progress;
    std::atomic<bool> cancel{false};
    std::thread worker;

    RetrieveJob()
        : created_ms(NowEpochMs())
    {
        progress.last_commit_ms.store(static_cast<uint64_t>(created_ms));
    }
    RetrieveJob(const RetrieveJob&) = delete;
    RetrieveJob& operator=(const RetrieveJob&) = delete;
    ~RetrieveJob()
    {
        cancel.store(true);
        if (worker.joinable()) worker.join();
    }
};

std::mutex g_retrieve_mu;
std::map<std::string, std::shared_ptr<RetrieveJob>> g_retrieve_jobs;
fs::path g_retrieve_jobs_dir;

void SetRetrieveJobsDir(const fs::path& dir)
{
    g_retrieve_jobs_dir = dir;
}

fs::path RetrieveJobsPath()
{
    return g_retrieve_jobs_dir / "retrieve_jobs.json";
}

void PersistRetrieveJobsLocked()
{
    if (g_retrieve_jobs_dir.empty()) return;
    UniValue arr(UniValue::VARR);
    for (auto& kv : g_retrieve_jobs) {
        std::string st, id;
        int64_t created_ms = 0;
        {
            std::lock_guard<std::mutex> lock(kv.second->mu);
            st = kv.second->status;
            id = kv.second->id;
            created_ms = kv.second->created_ms;
        }
        if (st != "queued" && st != "running") continue;
        if (kv.second->model_id.IsNull()) continue;
        UniValue o(UniValue::VOBJ);
        o.pushKV("job_id", id);
        o.pushKV("model_id", kv.second->model_id.Hex());
        o.pushKV("status", "queued");
        o.pushKV("created_ms", created_ms);
        o.pushKV("bytes_committed", kv.second->progress.bytes_committed.load());
        o.pushKV("pieces_committed", kv.second->progress.pieces_committed.load());
        o.pushKV("file_index", static_cast<int>(kv.second->progress.file_index.load()));
        o.pushKV("piece_index", static_cast<int>(kv.second->progress.piece_index.load()));
        arr.push_back(o);
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("schema_version", 1);
    root.pushKV("jobs", arr);
    std::string err;
    (void)WriteJsonFile(RetrieveJobsPath(), root, err);
}

void PersistRetrieveJobs()
{
    std::lock_guard<std::mutex> lock(g_retrieve_mu);
    PersistRetrieveJobsLocked();
}

void LoadRetrieveJobs(ModelCatalog& cat)
{
    SetRetrieveJobsDir(HelperDir(cat));
    UniValue root;
    if (!ReadJsonFile(RetrieveJobsPath(), root) || !root.isObject()) return;
    if (!root.exists("jobs") || !root["jobs"].isArray()) return;
    std::lock_guard<std::mutex> lock(g_retrieve_mu);
    for (const auto& j : root["jobs"].getValues()) {
        if (!j.isObject() || !j.exists("job_id") || !j["job_id"].isStr()) continue;
        const std::string id = j["job_id"].get_str();
        if (id.empty() || g_retrieve_jobs.count(id)) continue;
        if (!j.exists("model_id") || !j["model_id"].isStr()) continue;
        Digest48 mid;
        std::string herr;
        if (!Digest48::FromHex(j["model_id"].get_str(), mid, herr) || mid.IsNull()) continue;
        auto job = std::make_shared<RetrieveJob>();
        job->id = id;
        job->model_id = mid;
        job->modeldir = HelperDir(cat);
        if (j.exists("created_ms") && j["created_ms"].isNum()) {
            job->created_ms = j["created_ms"].getInt<int64_t>();
        }
        {
            std::lock_guard<std::mutex> jlock(job->mu);
            job->status = "queued";
        }
        if (j.exists("bytes_committed") && j["bytes_committed"].isNum()) {
            job->progress.bytes_committed.store(j["bytes_committed"].getInt<uint64_t>());
        }
        if (j.exists("pieces_committed") && j["pieces_committed"].isNum()) {
            job->progress.pieces_committed.store(j["pieces_committed"].getInt<uint64_t>());
        }
        if (j.exists("file_index") && j["file_index"].isNum()) {
            job->progress.file_index.store(static_cast<uint32_t>(j["file_index"].getInt<int>()));
        }
        if (j.exists("piece_index") && j["piece_index"].isNum()) {
            job->progress.piece_index.store(static_cast<uint32_t>(j["piece_index"].getInt<int>()));
        }
        g_retrieve_jobs[id] = job;
    }
}

void LaunchRetrieveWorker(const std::shared_ptr<RetrieveJob>& job, ModelCatalog& cat);

std::string NewRetrieveJobId()
{
    unsigned char b[16];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    return HexStr(Span<const unsigned char>{b, sizeof(b)});
}

/** Drop oldest done/failed jobs, keeping the newest kKeepTerminalRetrieveJobs. Caller holds g_retrieve_mu. */
void PruneRetrieveJobsLocked()
{
    struct Item {
        std::string id;
        int64_t created_ms{0};
        std::shared_ptr<RetrieveJob> job;
    };
    std::vector<Item> terminal;
    for (auto& kv : g_retrieve_jobs) {
        std::string st;
        {
            std::lock_guard<std::mutex> lock(kv.second->mu);
            st = kv.second->status;
        }
        if (st == "done" || st == "failed") {
            terminal.push_back({kv.first, kv.second->created_ms, kv.second});
        }
    }
    if (terminal.size() <= kKeepTerminalRetrieveJobs) return;
    std::sort(terminal.begin(), terminal.end(), [](const Item& a, const Item& b) {
        return RetrieveJobIsNewer(a.created_ms, a.id, b.created_ms, b.id);
    });
    for (size_t i = kKeepTerminalRetrieveJobs; i < terminal.size(); ++i) {
        g_retrieve_jobs.erase(terminal[i].id);
    }
}

UniValue RetrieveJobJson(const RetrieveJob& j)
{
    std::string id, status, err, last_peer, last_err;
    UniValue result;
    int64_t created_ms = 0;
    {
        std::lock_guard<std::mutex> lock(j.mu);
        id = j.id;
        status = j.status;
        err = j.err;
        last_peer = j.last_peer;
        last_err = j.last_err;
        result = j.result;
        created_ms = j.created_ms;
    }
    const uint64_t bytes = j.progress.bytes_committed.load();
    const uint64_t last_commit = j.progress.last_commit_ms.load();
    const int64_t now_ms = NowEpochMs();
    const int64_t elapsed = now_ms > created_ms ? now_ms - created_ms : 0;
    int64_t stalled = 0;
    if (last_commit > 0 && now_ms > static_cast<int64_t>(last_commit)) {
        stalled = now_ms - static_cast<int64_t>(last_commit);
    }

    UniValue o(UniValue::VOBJ);
    o.pushKV("job_id", id);
    o.pushKV("status", status);
    o.pushKV("created_ms", created_ms);
    if (!j.model_id.IsNull()) o.pushKV("model_id", j.model_id.Hex());
    if (result.isObject() && !result.getKeys().empty()) o.pushKV("result", result);
    if (!err.empty()) o.pushKV("error", err);
    o.pushKV("bytes_committed", bytes);
    o.pushKV("pieces_committed", j.progress.pieces_committed.load());
    o.pushKV("file_index", static_cast<int>(j.progress.file_index.load()));
    o.pushKV("piece_index", static_cast<int>(j.progress.piece_index.load()));
    o.pushKV("inflight", j.progress.inflight.load());
    o.pushKV("peer_retries", j.progress.peer_retries.load());
    o.pushKV("stalled_for_ms", stalled);
    if (elapsed > 0) {
        o.pushKV("bytes_per_sec", (bytes * 1000ULL) / static_cast<uint64_t>(elapsed));
    }
    if (!last_peer.empty()) o.pushKV("last_peer", last_peer);
    if (!last_err.empty()) o.pushKV("last_err", last_err);
    return o;
}

std::string EnqueueRetrieve(ModelCatalog& cat, const Digest48& model_id, std::atomic<bool>* stop)
{
    (void)stop;
    auto job = std::make_shared<RetrieveJob>();
    job->id = NewRetrieveJobId();
    job->model_id = model_id;
    job->modeldir = HelperDir(cat);
    {
        std::lock_guard<std::mutex> lock(job->mu);
        job->status = "running";
    }
    {
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        g_retrieve_jobs[job->id] = job;
        PruneRetrieveJobsLocked();
        PersistRetrieveJobsLocked();
    }
    LaunchRetrieveWorker(job, cat);
    return job->id;
}

void LaunchRetrieveWorker(const std::shared_ptr<RetrieveJob>& job, ModelCatalog& cat)
{
    if (!job || job->worker.joinable()) return;
    const Digest48 model_id = job->model_id;
    // DISC-05: re-read catalog peers after a contact dies. Committed pieces
    // stay on disk; RetrieveFreeFromPeer skips them via GetPiece.
    job->worker = std::thread([job, &cat, model_id]() {
        auto failed = [&](const std::string& e) {
            CatalogEntry done;
            if (cat.Find(model_id, done)) cat.EndTransfer(done.artifact_id);
            UniValue r(UniValue::VOBJ);
            r.pushKV("schema_version", 2);
            r.pushKV("status", "failed");
            r.pushKV("error", e);
            {
                std::lock_guard<std::mutex> lock(job->mu);
                job->err = e;
                job->status = "failed";
                job->result = std::move(r);
            }
            PersistRetrieveJobs();
        };
        Pq1Context pq;
        std::string tls_err;
        if (!LoadPq1Identity(pq, cat.Store().Root().parent_path(), tls_err)) {
            failed(tls_err);
            return;
        }
        const fs::path pinfile = cat.Store().Root().parent_path() / "tls" / "pins.json";
        CatalogEntry live;
        if (cat.Find(model_id, live)) cat.BeginTransfer(live.artifact_id);
        std::set<std::string> failed_peers;
        std::string last_err;
        int transient_streak = 0;
        uint64_t last_bytes = 0;
        auto remaining_unfailed = [&]() -> size_t {
            size_t n = 0;
            for (const auto& p : cat.Peers()) {
                if (failed_peers.count(p) == 0) ++n;
            }
            return n;
        };
        while (true) {
            if (job->cancel.load()) {
                failed("cancelled");
                return;
            }
            std::string peer;
            for (const auto& p : cat.Peers()) {
                if (failed_peers.count(p) == 0) {
                    peer = p;
                    break;
                }
            }
            if (peer.empty()) {
                failed(last_err.empty() ? "retrieve failed" : last_err);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(job->mu);
                job->last_peer = peer;
            }
            std::string host;
            uint16_t port = 0;
            if (!SplitHostPort(peer, host, port)) {
                failed_peers.insert(peer);
                last_err = "peer host:port";
                continue;
            }
            std::string rerr;
            try {
                std::vector<std::string> extras;
                for (const auto& p : cat.Peers()) {
                    if (p != peer && failed_peers.count(p) == 0) extras.push_back(p);
                }
                {
                    std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
                    for (const auto& rec : g_swarm.providers.Get(model_id, ConnNowMs())) {
                        for (const auto& ep : rec.endpoints) {
                            if (ep != peer && failed_peers.count(ep) == 0) extras.push_back(ep);
                        }
                    }
                }
                if (RetrieveFreeFromPeer(cat, pq, host, port, model_id, rerr, &job->cancel, pinfile, &job->progress, extras)) {
                    std::string seed_err;
                    cat.ApplyDemandSeed(model_id, seed_err);
                    CatalogEntry got;
                    UniValue r(UniValue::VOBJ);
                    r.pushKV("schema_version", 2);
                    r.pushKV("plan", "FREE");
                    r.pushKV("status", "retrieved");
                    r.pushKV("seeded", cat.Find(model_id, got) && got.seeded);
                    r.pushKV("propagation", "demand");
                    r.pushKV("model_id", model_id.Hex());
                    r.pushKV("failed_contacts", static_cast<int>(failed_peers.size()) + job->progress.peer_failovers.load());
                    r.pushKV("last_peer", peer);
                    r.pushKV("peer_retries", job->progress.peer_retries.load());
                    {
                        std::lock_guard<std::mutex> lock(job->mu);
                        job->result = std::move(r);
                        job->status = "done";
                    }
                    CatalogEntry done;
                    if (cat.Find(model_id, done)) cat.EndTransfer(done.artifact_id);
                    PersistRetrieveJobs();
                    return;
                }
            } catch (const std::exception& e) {
                rerr = std::string("retrieve exception: ") + e.what();
            } catch (...) {
                rerr = "retrieve exception";
            }
            last_err = rerr.empty() ? "retrieve failed" : rerr;
            {
                std::lock_guard<std::mutex> lock(job->mu);
                job->last_err = last_err;
            }
            if (job->cancel.load() || last_err == "stopped" || last_err.find("cancelled") != std::string::npos) {
                failed(last_err == "stopped" ? last_err : "cancelled");
                return;
            }
            const uint64_t now_bytes = job->progress.bytes_committed.load();
            const bool progressed = now_bytes > last_bytes;
            last_bytes = now_bytes;
            const bool transient = IsTransientPq1Error(last_err);
            const bool last_remaining = remaining_unfailed() <= 1;
            // Another healthy contact exists: fail over immediately so a dead
            // introducer cannot starve a live seeder (DISC-05). Keep the 1024-try
            // WAN retry budget only for the last remaining contact.
            if (!last_remaining) {
                failed_peers.insert(peer);
                transient_streak = 0;
                continue;
            }
            if (transient && transient_streak < PQ1_PEER_TRANSIENT_TRIES) {
                job->progress.peer_retries.fetch_add(1);
                ++transient_streak;
                if (!progressed) {
                    int backoff = PQ1_PEER_RETRY_MS << std::min(transient_streak, 4);
                    if (backoff > 15000) backoff = 15000;
                    for (int slept = 0; slept < backoff; slept += 250) {
                        if (job->cancel.load()) {
                            failed("cancelled");
                            return;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(250));
                    }
                } else {
                    transient_streak = 0;
                }
                continue;
            }
            failed_peers.insert(peer);
            transient_streak = 0;
        }
    });
}

void StartRetrieveWorkers(ModelCatalog& cat)
{
    std::vector<std::shared_ptr<RetrieveJob>> pending;
    {
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        for (auto& kv : g_retrieve_jobs) {
            std::string st;
            {
                std::lock_guard<std::mutex> jlock(kv.second->mu);
                st = kv.second->status;
            }
            if ((st == "queued" || st == "running") && !kv.second->worker.joinable()) pending.push_back(kv.second);
        }
    }
    for (auto& job : pending) LaunchRetrieveWorker(job, cat);
}

void JoinRetrieveJobs()
{
    std::vector<std::shared_ptr<RetrieveJob>> copy;
    {
        std::lock_guard<std::mutex> lock(g_retrieve_mu);
        PersistRetrieveJobsLocked();
        g_retrieve_jobs_dir.clear();
        for (auto& kv : g_retrieve_jobs) copy.push_back(kv.second);
        g_retrieve_jobs.clear();
    }
    for (auto& j : copy) {
        j->cancel.store(true);
        if (j->worker.joinable()) j->worker.join();
    }
}

} // namespace

struct HelperRuntimeInfo {
    StorageMode storage_mode{StorageMode::AUTO};
    uint64_t target_bytes{0};
    uint64_t effective_quota{0};
    uint64_t fs_capacity{0};
    uint64_t fs_available{0};
    uint64_t reserve_bytes{0};
    bool demand_seed{true};
    bool preserve_rare{false};
    bool follow_peers{true};
    bool public_host_reachable{false};
    bool advertised_host{false};
    uint64_t upload_bps{0};
    int active_transfers{0};
    std::string watch_dir;
    int64_t last_watch_scan_ms{0};
    int last_watch_imported{0};
    int last_watch_skipped{0};
};
static HelperRuntimeInfo g_runtime;

static bool CatalogHasVerifiedSeededRange(const ModelCatalog& cat);
static void RefreshAdvertisedHost(const ModelCatalog* cat);

struct UlSample {
    int64_t served{0};
    int64_t ms{0};
};
std::mutex g_ul_mu;
std::map<std::string, UlSample> g_ul_last;

UniValue MakeShareObject(const std::string& uri, const ModelSearchRecord& rec)
{
    UniValue s(UniValue::VOBJ);
    const std::string canonical = [&]() {
        const std::string c = CopyUri(uri);
        return c.empty() ? uri : c;
    }();
    s.pushKV("uri", canonical);
    std::string copy = canonical;
    if (!rec.family.empty()) copy += " family=" + rec.family;
    if (!rec.format.empty()) copy += " format=" + rec.format;
    if (!rec.quantization.empty()) copy += " quant=" + rec.quantization;
    s.pushKV("copy_text", copy);
    s.pushKV("family", rec.family);
    s.pushKV("format", rec.format);
    s.pushKV("quantization", rec.quantization);
    s.pushKV("signed", rec.signed_ok);
    s.pushKV("size_bytes", rec.size_bytes);
    s.pushKV("file_count", rec.file_count);
    return s;
}

Digest48 ResolveUserId(const std::string& s, std::string& err)
{
    EnsureSearchBound();
    Digest48 id = IdFromUser(s, err);
    if (!id.IsNull()) {
        err.clear();
        return id;
    }
    err.clear();
    std::lock_guard<std::mutex> lock(g_search_mu);
    if (const auto* rec = g_search_idx.FindByAlias(s)) return rec->model_id;
    err = "unknown id or alias";
    return {};
}

bool LoadShareText(const fs::path& p, std::string& text, std::string& err)
{
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz > 65536) {
        err = "share file too large or unreadable";
        return false;
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        err = "cannot read share file";
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    text = ss.str();
    if (text.size() > 65536) text.resize(65536);
    UniValue o;
    if (o.read(text) && o.isObject()) {
        if (o.exists("uri") && o["uri"].isStr() && o["uri"].get_str().rfind("btx://", 0) == 0) {
            text = o["uri"].get_str();
            return true;
        }
        if (o.exists("copy_text") && o["copy_text"].isStr() && o["copy_text"].get_str().find("btx://") != std::string::npos) {
            text = o["copy_text"].get_str();
            return true;
        }
        if (o.exists("link") && o["link"].isObject() && o["link"].exists("uri") && o["link"]["uri"].isStr()) {
            text = o["link"]["uri"].get_str();
            return true;
        }
    }
    return text.find("btx://") != std::string::npos;
}

bool LooksLikeSharePath(const fs::path& p)
{
    if (!fs::is_regular_file(p)) return false;
    const auto lower = ToLower(fs::PathToString(p.filename()));
    return lower.ends_with(".btx") || lower.ends_with(".btxlink") || lower.ends_with(".magnet");
}

UniValue NextActionsArray(const std::vector<std::string>& steps)
{
    UniValue a(UniValue::VARR);
    for (const auto& s : steps) a.push_back(s);
    a.push_back("automatic_spend_atoms stays 0");
    return a;
}

void AttachLocalShare(ModelCatalog& cat, const Digest48& id, UniValue& result)
{
    EnsureSearchBound();
    CatalogEntry e;
    const bool local = cat.Find(id, e);
    ModelSearchRecord rec;
    {
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (const auto* r = g_search_idx.Get(id)) rec = *r;
        else if (local) rec = DraftSearchFromCatalog(e);
    }
    std::string uri = rec.btx_uri;
    std::string ierr;
    if (uri.empty() && local) EncodeResource(ResourceKind::MODEL, e.model_id, uri, ierr);
    if (uri.empty()) EncodeResource(ResourceKind::MODEL, id, uri, ierr);
    result.pushKV("uri", uri);
    UniValue share = MakeShareObject(uri, rec);
    if (local) share.pushKV("file_count", static_cast<int>(e.core.files.size()));
    result.pushKV("share", share);
    result.pushKV("automatic_spend_atoms", 0);
}

bool LooksLikeWatchTemp(const std::string& lower_name)
{
    return lower_name.ends_with(".part") || lower_name.ends_with(".tmp") ||
           lower_name.ends_with(".crdownload") || lower_name.ends_with(".aria2") ||
           lower_name.ends_with(".!qb") || lower_name.starts_with(".");
}

void DecorateCatalogRow(ModelCatalog& cat, UniValue& o)
{
    Digest48 id;
    std::string ierr;
    if (!o.exists("model_id") || !o["model_id"].isStr() || !Digest48::FromHex(o["model_id"].get_str(), id, ierr)) {
        return;
    }
    CatalogEntry e;
    const bool local = cat.Find(id, e);
    if (local) {
        o.pushKV("useful_bytes_served", e.useful_bytes_served);
        o.pushKV("useful_bytes_received", e.useful_bytes_received);
        o.pushKV("served", e.useful_bytes_served);
        o.pushKV("received", e.useful_bytes_received);
        o.pushKV("seeding_started_at", e.seeding_started_at);
        if (e.completed_at) o.pushKV("completed_at", e.completed_at);
        const int64_t last_activity = std::max(e.last_access_at, e.last_served_at);
        if (last_activity) o.pushKV("last_activity", last_activity);
        if (!o.exists("source_path")) o.pushKV("source_path", e.source_path);
        if (e.useful_bytes_received > 0) {
            o.pushKV("ratio", static_cast<double>(e.useful_bytes_served) / static_cast<double>(e.useful_bytes_received));
        } else {
            o.pushKV("ratio", UniValue());
        }
        const int64_t now_ms = ConnNowMs();
        {
            std::lock_guard<std::mutex> ul(g_ul_mu);
            UlSample& samp = g_ul_last[id.Hex()];
            if (samp.ms > 0 && now_ms > samp.ms && e.useful_bytes_served >= samp.served) {
                const int64_t dt = now_ms - samp.ms;
                const int64_t dbytes = e.useful_bytes_served - samp.served;
                if (dbytes > 0) o.pushKV("ul_bytes_per_sec", dbytes * 1000 / dt);
            }
            samp.served = e.useful_bytes_served;
            samp.ms = now_ms;
        }
        std::string state = "local";
        if (e.incomplete) state = "downloading";
        else if (e.seeded) state = "seeding";
        else if (e.pinned) state = "pinned";
        o.pushKV("state", state);
    }
    ModelSearchRecord rec;
    {
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (const auto* r = g_search_idx.Get(id)) rec = *r;
        else if (local) rec = DraftSearchFromCatalog(e);
    }
    std::string uri = o.exists("uri") && o["uri"].isStr() ? o["uri"].get_str() : rec.btx_uri;
    if (uri.empty() && local) EncodeResource(ResourceKind::MODEL, e.model_id, uri, ierr);
    if (uri.empty() && !id.IsNull()) EncodeResource(ResourceKind::MODEL, id, uri, ierr);
    if (!o.exists("uri") && !uri.empty()) o.pushKV("uri", uri);
    UniValue share = MakeShareObject(uri, rec);
    if (local) share.pushKV("file_count", static_cast<int>(e.core.files.size()));
    o.pushKV("share", share);
    UniValue aliases(UniValue::VARR);
    for (const auto& a : rec.aliases) aliases.push_back(a);
    o.pushKV("aliases", aliases);
    const std::string name = !rec.aliases.empty() ? rec.aliases.front() :
        (!rec.display_name.empty() ? rec.display_name : (o.exists("label") ? o["label"].get_str() : ""));
    o.pushKV("name", name);
    if (local) o.pushKV("imported_at", e.imported_at);
    if (local) {
        UniValue files = cat.FileAvailabilityJson(e.artifact_id, e.core);
        int64_t have = 0, total = 0;
        for (const auto& f : files.getValues()) {
            if (f.exists("piece_count") && f["piece_count"].isNum()) have += f["piece_count"].getInt<int64_t>();
            if (f.exists("pieces_total") && f["pieces_total"].isNum()) total += f["pieces_total"].getInt<int64_t>();
        }
        if (total > 0) o.pushKV("percent", static_cast<int>(std::min<int64_t>(100, have * 100 / total)));
        else if (o.exists("complete") && o["complete"].isTrue()) o.pushKV("percent", 100);
        else if (e.incomplete) o.pushKV("percent", 0);
        else o.pushKV("percent", 100);
    }
}

void AttachDoctor(ModelCatalog& cat, UniValue& result)
{
    std::vector<unsigned char> pk, sk;
    Digest48 publisher_id;
    std::string perr;
    const bool id_ok = EnsureDefaultPublisherIdentity(HelperDir(cat), pk, sk, publisher_id, perr);
    result.pushKV("identity_ready", id_ok);
    if (id_ok) {
        result.pushKV("identity_id", publisher_id.Hex());
        result.pushKV("identity_label", "local publisher");
        result.pushKV("identity_wallet_key", false);
    } else if (!perr.empty()) {
        result.pushKV("identity_error", perr);
    }
    Pq1Context pq;
    result.pushKV("pq1_ready", pq.Ready());
    result.pushKV("ready_to_host", id_ok && pq.Ready() && cat.QuotaBytes() > 0);
    result.pushKV("watch_dir", g_runtime.watch_dir);
    std::vector<std::string> next;
    if (cat.QuotaBytes() == 0) next.emplace_back("set -modelstorage=auto or a positive size before import");
    if (!id_ok) next.emplace_back("createmodelidentity (helper also creates one on start)");
    if (id_ok && cat.QuotaBytes() > 0) next.emplace_back("hostmodel <path>  # pin, sign search card, demand-seed");
    next.emplace_back("searchmodels {\"scope\":\"LOCAL\"}");
    next.emplace_back("getmodeltransfers");
    result.pushKV("next_actions", NextActionsArray(next));
    result.pushKV("quota", cat.QuotaBytes());
    result.pushKV("pq1", result.exists("pq1_ready") && result["pq1_ready"].isTrue());
    const uint64_t remaining = cat.QuotaBytes() > cat.UsedBytes() ? cat.QuotaBytes() - cat.UsedBytes() : 0;
    result.pushKV("remaining_bytes", remaining);
    OperatorProfile prof = OperatorProfile::CUSTOM;
    ProfilePolicy policy;
    std::string perr2;
    (void)LoadOperatorProfile(OperatorProfilePath(HelperDir(cat)), prof, policy, perr2);
    result.pushKV("profile", OperatorProfileName(prof));
    result.pushKV("profile_host_mode", HostModeName(policy.host_mode));
    result.pushKV("cloud_optional", true);
    result.pushKV("cloud_layout_sentence",
                  "Cloud backing is optional. R2 AUTO stores one SOURCE_FILES object per original file and streams it; 4 MiB pieces remain the swarm unit.");
    result.pushKV("r2_auto_sentence",
                  "R2 AUTO is SOURCE_FILES + STREAM_FILE. PIECE_OBJECTS is an explicit override and is refused on R2 without allow_request_heavy_cloud_layout.");
    result.pushKV("automatic_spend_atoms", 0);
    std::string one = "hostmodel <path>";
    if (cat.QuotaBytes() == 0) one = "set -modelstorage=auto or a positive size before import";
    else if (!id_ok) one = "createmodelidentity (helper also creates one on start)";
    else if (!pq.Ready()) one = "install OpenSSL 3.5+ so PQ1 is ready";
    result.pushKV("one_liner", one);
}

void ApplyProfilePolicyLive(ModelCatalog& cat, const ProfilePolicy& policy)
{
    g_runtime.preserve_rare = policy.preserve_rare;
    g_runtime.follow_peers = policy.follow_peers;
    g_runtime.upload_bps = policy.upload_bps;
    g_runtime.demand_seed = policy.seed != "off";
    g_swarm.relay = policy.relay;
    g_swarm.host = HostModeWantsHosting(policy.host_mode);
    PreservationPolicy p = cat.Policy();
    p.preserve_rare = policy.preserve_rare;
    p.follow_configured_peers = policy.follow_peers;
    p.upload_bps = policy.upload_bps;
    SeedMode sm;
    if (SeedModeFromName(policy.seed, sm)) {
        p.seed_mode = sm;
        p.seed_upon_download = sm == SeedMode::AUTO;
    }
    cat.SetPolicy(p);
    RefreshAdvertisedHost(&cat);
    SetNodeModelHostAdvertised(g_runtime.advertised_host);
}

bool CollectPreviewFiles(const fs::path& src, std::vector<std::pair<fs::path, std::string>>& files, std::string& err)
{
    auto skip_name = [](const std::string& rels) {
        const auto lower = ToLower(rels);
        return lower.ends_with(".pt") || lower.ends_with(".pth") || lower.ends_with(".pkl") ||
               lower.ends_with(".pickle") || lower.ends_with(".py") || lower.ends_with(".so") ||
               lower.ends_with(".bin") || lower.ends_with(".exe") || lower.ends_with(".dll");
    };
    if (!fs::exists(src)) {
        err = "path does not exist";
        return false;
    }
    if (fs::is_regular_file(src)) {
        const std::string name = fs::PathToString(src.filename());
        if (skip_name(name)) {
            err = "pickle/.pt/.py/.so/.bin skipped";
            return false;
        }
        files.emplace_back(src, name);
        return true;
    }
    if (!fs::is_directory(src)) {
        err = "not a file or directory";
        return false;
    }
    for (const auto& ent : fs::recursive_directory_iterator(src)) {
        if (!ent.is_regular_file()) continue;
        fs::path rel = fs::relative(ent.path(), src);
        const std::string rels = rel.generic_string();
        std::string perr;
        if (!IsPortableRelPath(rels, perr)) continue;
        if (skip_name(rels)) continue;
        files.emplace_back(ent.path(), rels);
    }
    if (files.empty()) {
        err = "no importable files (pickle/.pt/.py/.so/.bin skipped)";
        return false;
    }
    return true;
}

bool ImportAndPublish(ModelCatalog& cat, const std::string& path, bool pin, bool publish, UniValue& result, std::string& err_code, std::string& err)
{
    CatalogEntry e;
    if (!cat.ImportPath(path, pin, e, err)) {
        err_code = "IMPORT_FAILED";
        if (cat.QuotaBytes() == 0) {
            err = err.empty() ? "payload storage is 0 until -modelstorage allocates a quota" : err;
        }
        return false;
    }
    std::string uri;
    EncodeResource(ResourceKind::MODEL, e.model_id, uri, err);
    err.clear();
    result.pushKV("schema_version", 2);
    result.pushKV("uri", uri);
    result.pushKV("model_id", e.model_id.Hex());
    result.pushKV("artifact_id", e.artifact_id.Hex());
    result.pushKV("admission", AdmissionLevelName(e.admission));
    result.pushKV("qualification", "structure only; not usefulness, safety, or alignment");
    result.pushKV("seeded", e.seeded);
    result.pushKV("pinned", e.pinned);
    result.pushKV("propagation", ShouldDemandSeed(cat.Policy(), e.admission) || e.seeded ? "demand" : "local_only");
    ModelSearchRecord rec = DraftSearchFromCatalog(e);
    rec.btx_uri = uri;
    if (publish) {
        EnsureSearchBound();
        EnsureEconomy(cat);
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* prev = g_search_idx.Get(rec.model_id)) {
                rec.metadata_sequence = prev->metadata_sequence + 1;
                if (rec.canonical_name.empty()) rec.canonical_name = prev->canonical_name;
            }
        }
        std::string serr;
        (void)SignSearchRecordWithDefaultIdentity(HelperDir(cat), rec, serr);
        bool published = false;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            published = g_search_idx.Put(rec, ConnNowMs(), err);
            if (published) AfterIndexPut(rec, ConnNowMs());
        }
        PersistEconomy(cat);
        result.pushKV("search_published", published);
        result.pushKV("signed_metadata", rec.signed_ok);
        if (!published) {
            result.pushKV("search_error", err.empty() ? "search put rejected" : err);
            err.clear();
        }
        result.pushKV("format", rec.format);
        result.pushKV("family", rec.family);
        result.pushKV("quantization", rec.quantization);
    } else {
        result.pushKV("search_published", false);
        result.pushKV("signed_metadata", false);
        result.pushKV("format", rec.format);
        result.pushKV("family", rec.family);
        result.pushKV("quantization", rec.quantization);
    }
    result.pushKV("share", MakeShareObject(uri, rec));
    result.pushKV("next_actions", NextActionsArray({
        "searchmodels {\"scope\":\"LOCAL\"}",
        "getmodelsharecard " + uri,
        "getmodeltransfers",
    }));
    result.pushKV("automatic_spend_atoms", 0);
    PublishCatalogToCloud(e, result);
    return true;
}

int ScanWatchDir(ModelCatalog& cat, UniValue& result, std::string& err, const std::string& dir_override = {})
{
    result.setObject();
    result.pushKV("schema_version", 2);
    const std::string watch = dir_override.empty() ? g_runtime.watch_dir : dir_override;
    result.pushKV("watch_dir", watch);
    UniValue imported(UniValue::VARR);
    UniValue skipped(UniValue::VARR);
    UniValue opened(UniValue::VARR);
    auto skip_obj = [&](const std::string& path, const std::string& reason) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("path", path);
        o.pushKV("reason", reason);
        skipped.push_back(o);
    };
    if (watch.empty()) {
        result.pushKV("imported", imported);
        result.pushKV("skipped", skipped);
        result.pushKV("opened", opened);
        result.pushKV("imported_count", 0);
        result.pushKV("opened_count", 0);
        result.pushKV("note", "set -modelwatch=<dir> or pass a path to scanmodelwatch");
        return 0;
    }
    const fs::path root = fs::PathFromString(watch);
    if (!fs::exists(root) || !fs::is_directory(root)) {
        err = "watch dir missing";
        result.pushKV("error", err);
        return 0;
    }
    UniValue seen;
    ReadJsonFile(HelperDir(cat) / "watch-imported.json", seen);
    std::set<std::string> already;
    if (seen.exists("paths") && seen["paths"].isArray()) {
        for (const auto& p : seen["paths"].getValues()) {
            if (p.isStr()) already.insert(p.get_str());
            else if (p.isObject() && p.exists("path") && p["path"].isStr()) already.insert(p["path"].get_str());
        }
    }
    auto consider = [&](const fs::path& src) {
        const std::string key = fs::PathToString(src);
        if (already.count(key)) {
            skip_obj(key, "already imported");
            return;
        }
        uint64_t nbytes = 0;
        std::error_code ec;
        if (fs::is_regular_file(src)) {
            nbytes = static_cast<uint64_t>(fs::file_size(src, ec));
        } else if (fs::is_directory(src)) {
            std::vector<std::pair<fs::path, std::string>> files;
            std::string perr;
            if (CollectPreviewFiles(src, files, perr)) {
                for (const auto& f : files) {
                    if (fs::is_regular_file(f.first)) nbytes += static_cast<uint64_t>(fs::file_size(f.first, ec));
                }
            }
        }
        if (cat.QuotaBytes() > 0 && cat.UsedBytes() + nbytes > cat.QuotaBytes()) {
            skip_obj(key, "would not fit quota");
            return;
        }
        UniValue one(UniValue::VOBJ);
        std::string code, ierr;
        if (!ImportAndPublish(cat, key, true, true, one, code, ierr)) {
            skip_obj(key, ierr.empty() ? code : ierr);
            return;
        }
        imported.push_back(one);
        already.insert(key);
    };
    for (const auto& ent : fs::directory_iterator(root)) {
        if (ent.is_regular_file()) {
            const auto lower = ToLower(fs::PathToString(ent.path().filename()));
            if (LooksLikeSharePath(ent.path())) {
                const std::string key = fs::PathToString(ent.path());
                if (already.count(key)) {
                    skip_obj(key, "already opened");
                    continue;
                }
                UniValue one(UniValue::VOBJ);
                one.pushKV("path", key);
                one.pushKV("imported", false);
                one.pushKV("reason", "share_card");
                std::string share_text, serr;
                if (LoadShareText(ent.path(), share_text, serr)) {
                    one.pushKV("uri", FirstBtxToken(share_text));
                    one.pushKV("share_text", share_text);
                } else {
                    one.pushKV("error", serr.empty() ? "not a share card" : serr);
                }
                opened.push_back(one);
                already.insert(key);
                continue;
            }
            if (LooksLikeWatchTemp(lower)) {
                skip_obj(fs::PathToString(ent.path()), "temp suffix");
                continue;
            }
            if (lower.ends_with(".gguf") || lower.ends_with(".safetensors")) consider(ent.path());
        } else if (ent.is_directory()) {
            std::vector<std::pair<fs::path, std::string>> files;
            std::string perr;
            if (CollectPreviewFiles(ent.path(), files, perr)) consider(ent.path());
        }
    }
    UniValue paths(UniValue::VARR);
    for (const auto& p : already) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("path", p);
        std::error_code ec;
        const fs::path fp = fs::PathFromString(p);
        if (fs::is_regular_file(fp, ec)) {
            o.pushKV("size", static_cast<int64_t>(fs::file_size(fp, ec)));
        }
        paths.push_back(o);
    }
    UniValue store(UniValue::VOBJ);
    store.pushKV("paths", paths);
    std::string werr;
    WriteJsonFile(HelperDir(cat) / "watch-imported.json", store, werr);
    g_runtime.last_watch_scan_ms = ConnNowMs();
    g_runtime.last_watch_imported = static_cast<int>(imported.size());
    g_runtime.last_watch_skipped = static_cast<int>(skipped.size());
    result.pushKV("imported", imported);
    result.pushKV("skipped", skipped);
    result.pushKV("opened", opened);
    result.pushKV("imported_count", static_cast<int>(imported.size()));
    result.pushKV("opened_count", static_cast<int>(opened.size()));
    result.pushKV("last_scan_ms", g_runtime.last_watch_scan_ms);
    result.pushKV("automatic_spend_atoms", 0);
    return static_cast<int>(imported.size());
}
std::mutex g_seed_budget_mu;
int64_t g_seed_tokens{0};
int64_t g_seed_last_ms{0};

bool AllowModelSeedBytes(const ModelCatalog& cat, size_t n)
{
    UniValue o;
    ReadJsonFile(HelperDir(cat) / "governor-permit.json", o);
    bool seeding_allowed = true;
    if (o.exists("seeding_allowed") && o["seeding_allowed"].isBool()) {
        seeding_allowed = o["seeding_allowed"].get_bool();
    }
    if (!seeding_allowed) return false;
    int64_t gov_cap = 0;
    const bool have_gov = o.exists("upload_bps") && o["upload_bps"].isNum();
    if (have_gov) gov_cap = o["upload_bps"].getInt<int64_t>();
    if (have_gov && gov_cap <= 0) return false;
    uint64_t cap = 0;
    if (have_gov) {
        cap = EffectiveHostUploadBps(g_runtime.upload_bps, gov_cap, seeding_allowed);
    } else if (g_runtime.upload_bps == 0) {
        return true;
    } else {
        cap = g_runtime.upload_bps;
    }
    if (cap == 0) return false;
    const int64_t cap_i = cap > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ?
                              std::numeric_limits<int64_t>::max() :
                              static_cast<int64_t>(cap);
    const int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    std::lock_guard<std::mutex> lock(g_seed_budget_mu);
    if (g_seed_last_ms <= 0) g_seed_last_ms = now;
    const int64_t dt = std::max<int64_t>(0, now - g_seed_last_ms);
    g_seed_last_ms = now;
    g_seed_tokens = std::min(cap_i, g_seed_tokens + cap_i * dt / 1000);
    if (g_seed_tokens < static_cast<int64_t>(n)) return false;
    g_seed_tokens -= static_cast<int64_t>(n);
    return true;
}

static bool PreservationPermitted(const ModelCatalog& cat)
{
    UniValue o;
    ReadJsonFile(HelperDir(cat) / "governor-permit.json", o);
    if (!o.exists("preservation_allowed")) return true;
    return o["preservation_allowed"].isBool() && o["preservation_allowed"].get_bool();
}

static std::string LocalPexEndpoint()
{
    if (!g_swarm.nat.external.empty()) return g_swarm.nat.external;
    if (g_swarm.bind.empty()) return {};
    if (g_swarm.bind.rfind("0.0.0.0:", 0) == 0 || g_swarm.bind.rfind("[::]:", 0) == 0) return {};
    return g_swarm.bind;
}

static void RefreshLocalPex(ModelCatalog& cat)
{
    const std::string ep = LocalPexEndpoint();
    if (ep.empty()) return;
    UniValue listed;
    cat.List(listed);
    if (!listed.exists("models")) return;
    const int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    int n = 0;
    std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
    for (const auto& m : listed["models"].getValues()) {
        if (!m.exists("seeded") || !m["seeded"].get_bool() || !m.exists("model_id")) continue;
        ProviderHint h;
        h.endpoint = ep;
        h.model_id = m["model_id"].get_str();
        h.availability_summary = "seeded";
        h.expiry_ms = now + PEX_DEFAULT_TTL_MS;
        g_swarm.pex.NoteLocal(h);
        if (++n >= static_cast<int>(PEX_MAX_RECORDS_PER_MESSAGE)) break;
    }
}

bool JsonLooksLikeCloudSecret(const UniValue& o)
{
    if (!o.isObject()) return false;
    for (const std::string& k : o.getKeys()) {
        const std::string lk = ToLower(k);
        if (lk == "aws_secret_access_key" || lk == "secret_access_key" || lk == "secret" ||
            lk == "aws_access_key_id" || lk == "access_key_id" || lk == "aws_secret" ||
            lk == "aws_session_token" || lk == "session_token") {
            return true;
        }
        if (o[k].isStr()) {
            const std::string v = o[k].get_str();
            if (v.find("aws_secret_access_key") != std::string::npos) return true;
        }
    }
    return false;
}

bool CloudConfigFromJson(const UniValue& o, CloudStoreConfig& cfg, std::string& err)
{
    cfg = CloudStoreConfig{};
    if (!o.isObject()) {
        err = "cloud config must be an object";
        return false;
    }
    if (JsonLooksLikeCloudSecret(o)) {
        err = "pass credential_ref (0600 file or env name), not raw cloud secrets";
        return false;
    }
    if (o.exists("automatic_spend_atoms")) {
        if (!o["automatic_spend_atoms"].isNum() || o["automatic_spend_atoms"].getInt<int64_t>() != 0) {
            err = "automatic_spend_atoms must remain 0";
            return false;
        }
    }
    if (!o.exists("endpoint") || !o["endpoint"].isStr() || o["endpoint"].get_str().empty()) {
        err = "cloud endpoint is required";
        return false;
    }
    if (!o.exists("bucket") || !o["bucket"].isStr() || o["bucket"].get_str().empty()) {
        err = "cloud bucket is required";
        return false;
    }
    cfg.s3.endpoint = o["endpoint"].get_str();
    cfg.s3.bucket = o["bucket"].get_str();
    if (o.exists("prefix") && o["prefix"].isStr()) cfg.s3.prefix = o["prefix"].get_str();
    if (o.exists("region") && o["region"].isStr() && !o["region"].get_str().empty()) cfg.s3.region = o["region"].get_str();
    std::string layout = "AUTO";
    if (o.exists("layout") && o["layout"].isStr()) layout = o["layout"].get_str();
    else if (o.exists("cloud_object_layout") && o["cloud_object_layout"].isStr()) layout = o["cloud_object_layout"].get_str();
    if (!CloudObjectLayoutFromName(layout, cfg.layout)) {
        err = "layout must be AUTO|SOURCE_FILES|PIECE_OBJECTS";
        return false;
    }
    std::string provider = "AUTO";
    if (o.exists("provider") && o["provider"].isStr()) provider = o["provider"].get_str();
    else if (o.exists("cloud_provider") && o["cloud_provider"].isStr()) provider = o["cloud_provider"].get_str();
    if (!CloudProviderFromName(provider, cfg.provider)) {
        err = "provider must be AUTO|GENERIC_S3|AWS_S3|CLOUDFLARE_R2|MINIO";
        return false;
    }
    std::string strat = "AUTO";
    if (o.exists("read_strategy") && o["read_strategy"].isStr()) strat = o["read_strategy"].get_str();
    else if (o.exists("cloud_read_strategy") && o["cloud_read_strategy"].isStr()) strat = o["cloud_read_strategy"].get_str();
    if (!CloudReadStrategyFromName(strat, cfg.read_strategy)) {
        err = "read_strategy must be AUTO|STREAM_FILE|PIECE_GET";
        return false;
    }
    if (o.exists("credential_ref") && o["credential_ref"].isStr()) cfg.s3.creds.value = o["credential_ref"].get_str();
    std::string kind = "path";
    if (o.exists("credential_ref_kind") && o["credential_ref_kind"].isStr()) kind = o["credential_ref_kind"].get_str();
    cfg.s3.creds.kind = (ToLower(kind) == "env") ? CredentialRefKind::ENV : CredentialRefKind::PATH;
    if (cfg.s3.creds.value.rfind("env:", 0) == 0) {
        cfg.s3.creds.kind = CredentialRefKind::ENV;
        cfg.s3.creds.value = cfg.s3.creds.value.substr(4);
    } else if (cfg.s3.creds.value.rfind("file:", 0) == 0) {
        cfg.s3.creds.kind = CredentialRefKind::PATH;
        cfg.s3.creds.value = cfg.s3.creds.value.substr(5);
    }
    if (cfg.s3.creds.value.empty()) {
        err = "credential_ref is required";
        return false;
    }
    if (cfg.s3.creds.value.find('\n') != std::string::npos || cfg.s3.creds.value.find('=') != std::string::npos ||
        cfg.s3.creds.value.size() > 256 ||
        ToLower(cfg.s3.creds.value).find("akia") != std::string::npos ||
        ToLower(cfg.s3.creds.value).find("aws_secret") != std::string::npos) {
        err = "credential_ref looks like a secret; pass a 0600 path or env name";
        return false;
    }
    if (cfg.s3.creds.kind == CredentialRefKind::ENV) {
        for (unsigned char c : cfg.s3.creds.value) {
            if (!(std::isalnum(c) || c == '_')) {
                err = "credential env name is invalid";
                return false;
            }
        }
    } else {
        std::error_code ec;
        const fs::path p = fs::PathFromString(cfg.s3.creds.value);
        const auto st = fs::status(p, ec);
        if (!ec && st.type() == fs::file_type::regular) {
            const auto leaked = fs::perms::group_read | fs::perms::group_write | fs::perms::group_exec |
                                fs::perms::others_read | fs::perms::others_write | fs::perms::others_exec;
            if ((st.permissions() & leaked) != fs::perms::none) {
                err = "credential file must be mode 0600";
                return false;
            }
        }
    }
    cfg.allow_request_heavy_cloud_layout =
        o.exists("allow_request_heavy_cloud_layout") && o["allow_request_heavy_cloud_layout"].isBool() &&
        o["allow_request_heavy_cloud_layout"].get_bool();
    if (o.exists("projected_piece_objects") && o["projected_piece_objects"].isNum()) {
        cfg.projected_piece_objects = o["projected_piece_objects"].getInt<uint64_t>();
    }
    if (o.exists("budget_gets") && o["budget_gets"].isNum()) cfg.budget_gets = o["budget_gets"].getInt<uint64_t>();
    if (o.exists("budget_origin_bytes") && o["budget_origin_bytes"].isNum()) {
        cfg.budget_origin_bytes = o["budget_origin_bytes"].getInt<uint64_t>();
    }
    auto read_cap = [&](const char* key, uint64_t& dest) {
        if (!o.exists(key)) return;
        if (o[key].isNum()) dest = o[key].getInt<uint64_t>();
        else if (o[key].isStr()) {
            try {
                dest = static_cast<uint64_t>(std::stoull(o[key].get_str()));
            } catch (...) {
            }
        }
    };
    read_cap("budget_gets_per_day", cfg.budget_gets_per_day);
    read_cap("budget_gets_per_month", cfg.budget_gets_per_month);
    read_cap("budget_bytes_per_day", cfg.budget_bytes_per_day);
    read_cap("budget_bytes_per_month", cfg.budget_bytes_per_month);
    cfg.s3.use_fake = !o.exists("use_fake") || (o["use_fake"].isBool() && o["use_fake"].get_bool());
    cfg.s3.allow_http_loopback = o.exists("allow_http_loopback") && o["allow_http_loopback"].isBool() &&
                                o["allow_http_loopback"].get_bool();
    cfg.s3.allow_link_local = false;
    if (o.exists("allow_link_local") && o["allow_link_local"].isBool() && o["allow_link_local"].get_bool()) {
        err = "allow_link_local cannot be enabled; metadata/link-local hosts stay blocked";
        return false;
    }
    if (!S3HttpsTransportAvailable() && !cfg.s3.use_fake) {
        err = "HTTPS transport unavailable; set use_fake=true for in-process FakeS3";
        return false;
    }
    return true;
}

UniValue CloudConfigPersistJson(const CloudStoreConfig& cfg)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("endpoint", cfg.s3.endpoint);
    o.pushKV("bucket", cfg.s3.bucket);
    o.pushKV("prefix", cfg.s3.prefix);
    o.pushKV("region", cfg.s3.region);
    o.pushKV("layout", CloudObjectLayoutName(cfg.layout));
    o.pushKV("cloud_object_layout", CloudObjectLayoutName(cfg.layout));
    o.pushKV("provider", CloudProviderName(cfg.provider));
    o.pushKV("cloud_provider", CloudProviderName(cfg.provider));
    o.pushKV("read_strategy", CloudReadStrategyName(cfg.read_strategy));
    o.pushKV("cloud_read_strategy", CloudReadStrategyName(cfg.read_strategy));
    o.pushKV("credential_ref", cfg.s3.creds.value);
    o.pushKV("credential_ref_kind", cfg.s3.creds.kind == CredentialRefKind::ENV ? "env" : "path");
    o.pushKV("allow_request_heavy_cloud_layout", cfg.allow_request_heavy_cloud_layout);
    o.pushKV("projected_piece_objects", cfg.projected_piece_objects);
    o.pushKV("use_fake", cfg.s3.use_fake);
    o.pushKV("allow_http_loopback", cfg.s3.allow_http_loopback);
    o.pushKV("automatic_spend_atoms", 0);
    auto persist_cap = [&](const char* key, uint64_t v) {
        if (v != std::numeric_limits<uint64_t>::max()) o.pushKV(key, v);
    };
    persist_cap("budget_gets", cfg.budget_gets);
    persist_cap("budget_origin_bytes", cfg.budget_origin_bytes);
    persist_cap("budget_gets_per_day", cfg.budget_gets_per_day);
    persist_cap("budget_gets_per_month", cfg.budget_gets_per_month);
    persist_cap("budget_bytes_per_day", cfg.budget_bytes_per_day);
    persist_cap("budget_bytes_per_month", cfg.budget_bytes_per_month);
    return o;
}

void ApplyCloudCapsLocked()
{
    const bool ready = g_cloud && g_cloud->IsReady();
    SetAdvertisedCloudCaps(ready, ready && g_cloud->Layout() == CloudObjectLayout::SOURCE_FILES);
}

UniValue CloudPublicJson()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("configured", g_cloud != nullptr);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("https_enabled", S3HttpsTransportAvailable());
    o.pushKV("secrets_in_response", false);
    if (!g_cloud) {
        o.pushKV("reachable", false);
        o.pushKV("auth", false);
        o.pushKV("auth_ok", false);
        o.pushKV("fake", false);
        return o;
    }
    UniValue cfg = g_cloud->ConfigJson();
    UniValue health = g_cloud->HealthJson();
    for (const std::string& k : cfg.getKeys()) o.pushKV(k, cfg[k]);
    for (const std::string& k : health.getKeys()) {
        if (!o.exists(k)) o.pushKV(k, health[k]);
    }
    o.pushKV("credential_ref", g_cloud_cfg.s3.creds.kind == CredentialRefKind::ENV
                                     ? (std::string("env:") + g_cloud_cfg.s3.creds.value)
                                     : fs::PathToString(fs::PathFromString(g_cloud_cfg.s3.creds.value).filename()));
    o.pushKV("auth_ok", health.exists("auth") ? health["auth"] : UniValue(false));
    o.pushKV("health", health);
    return o;
}

void EnsureCloudLoaded(ModelCatalog& cat)
{
    const fs::path dir = HelperDir(cat);
    std::lock_guard<std::mutex> lock(g_cloud_mu);
    if (g_cloud && g_cloud_dir == dir) {
        ApplyCloudCapsLocked();
        return;
    }
    g_cloud.reset();
    g_cloud_cfg = CloudStoreConfig{};
    g_cloud_dir = dir;
    ApplyCloudCapsLocked();
    UniValue stored;
    if (!ReadJsonFile(dir / "cloud.json", stored) || !stored.isObject() || !stored.exists("endpoint")) return;
    std::string err;
    CloudStoreConfig cfg;
    if (!CloudConfigFromJson(stored, cfg, err)) return;
    cfg.budget_state_path = dir / "cloud-budget.json";
    auto store = std::make_unique<S3PieceStore>(cfg);
    if (!store->Init(err)) return;
    g_cloud_cfg = cfg;
    g_cloud = std::move(store);
    ApplyCloudCapsLocked();
}

void PublishCatalogToCloud(const CatalogEntry& e, UniValue& result)
{
    std::lock_guard<std::mutex> lock(g_cloud_mu);
    if (!g_cloud || !g_cloud->IsReady()) {
        result.pushKV("cloud_uploaded", false);
        return;
    }
    UniValue files(UniValue::VARR);
    bool all_ok = true;
    const bool piece_layout = g_cloud->Layout() == CloudObjectLayout::PIECE_OBJECTS;
    const fs::path root = fs::PathFromString(e.source_path);
    for (uint32_t i = 0; i < e.core.files.size(); ++i) {
        fs::path src = root;
        std::error_code ec;
        if (fs::is_directory(root, ec)) src = root / fs::PathFromString(e.core.files[i].path);
        const uint64_t n = e.core.files[i].size == 0 ? 1 : ((e.core.files[i].size + PIECE_SIZE - 1) / PIECE_SIZE);
        std::string cerr;
        UniValue f(UniValue::VOBJ);
        f.pushKV("file_index", static_cast<int>(i));
        f.pushKV("path", e.core.files[i].path);
        f.pushKV("bytes", e.core.files[i].size);
        f.pushKV("logical_pieces", n);
        f.pushKV("object_key", piece_layout ? g_cloud->PieceFileKey(e.artifact_id, i, 0) :
                                               g_cloud->SourceFileKey(e.artifact_id, i));
        const bool put_ok = piece_layout
                                 ? g_cloud->PutPieceObjects(e.artifact_id, i, src, e.core.files[i].size, cerr)
                                 : g_cloud->PutSourceFile(e.artifact_id, i, src, e.core.files[i].size, n, cerr);
        if (!put_ok) {
            f.pushKV("ok", false);
            f.pushKV("error", cerr);
            all_ok = false;
        } else {
            f.pushKV("ok", true);
            if (piece_layout) f.pushKV("piece_objects", n);
        }
        files.push_back(f);
    }
    result.pushKV("cloud_files", files);
    result.pushKV("cloud_uploaded", all_ok);
    result.pushKV("cloud_layout", CloudObjectLayoutName(g_cloud->Layout()));
    if (!all_ok) result.pushKV("cloud_error", "one or more source files failed to upload");
}

bool TryHydrateFromCloud(ModelCatalog& cat, CatalogEntry& e, UniValue& result, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_cloud_mu);
    if (!g_cloud || !g_cloud->IsReady() || e.core.files.empty()) return false;
    const CloudObjectLayout layout = g_cloud->Layout();
    if (layout != CloudObjectLayout::SOURCE_FILES && layout != CloudObjectLayout::PIECE_OBJECTS) return false;
    const fs::path qdir = HelperDir(cat) / "cloud-hydrate-q";
    fs::create_directories(qdir);
    ModelStore quarantine(qdir, cat.QuotaBytes() ? cat.QuotaBytes() : (64ull << 20));
    int origin_gets = 0;
    for (uint32_t fi = 0; fi < e.core.files.size(); ++fi) {
        std::string serr;
        if (!GlobalOriginStampede().Allow("cloud-origin", "cloud", ConnNowMs(), serr)) {
            err = serr;
            return false;
        }
        const CoreFile& cf = e.core.files[fi];
        FileStreamHydration hyd(e.artifact_id, fi, cf.size, cat.Store(), quarantine);
        hyd.SetExpectedSha384(cf.sha384);
        hyd.SetExpectedPiecesRoot(cf.pieces_root);
        hyd.SetJobDir(HelperDir(cat));
        FileStreamJobRecord rec;
        std::string jerr;
        const bool resume = LoadFileStreamJob(HelperDir(cat), e.artifact_id, fi, rec, jerr) &&
                            hyd.ApplyRecord(rec, jerr);
        if (layout == CloudObjectLayout::PIECE_OBJECTS) {
            const uint32_t n = cf.size == 0 ? 1u : static_cast<uint32_t>((cf.size + PIECE_SIZE - 1) / PIECE_SIZE);
            for (uint32_t p = 0; p < n; ++p) {
                std::vector<unsigned char> piece;
                if (!g_cloud->GetPieceObject(e.artifact_id, fi, p, piece, err)) {
                    GlobalOriginStampede().NoteError("cloud-origin", ConnNowMs());
                    return false;
                }
                if (!hyd.Feed(Span<const unsigned char>{piece.data(), piece.size()}, err)) return false;
                origin_gets += 1;
            }
            if (!hyd.Finish(err)) return false;
        } else {
        const std::string key = g_cloud->SourceFileKey(e.artifact_id, fi);
        if (cf.size <= kCloudStreamChunkBytes && !resume) {
            std::vector<unsigned char> body;
            if (!g_cloud->GetSourceFile(e.artifact_id, fi, body, err)) {
                GlobalOriginStampede().NoteError("cloud-origin", ConnNowMs());
                return false;
            }
            if (!hyd.Feed(Span<const unsigned char>{body.data(), body.size()}, err)) return false;
            if (!hyd.Finish(err)) return false;
            origin_gets += 1;
        } else {
            uint64_t pos = hyd.ResumeOffset();
            auto read = [&](size_t want, unsigned char* buf, size_t& got, std::string& rerr) -> bool {
                std::vector<unsigned char> chunk;
                if (!g_cloud->GetObject(key, pos, want, chunk, rerr)) return false;
                got = chunk.size();
                if (got) std::memcpy(buf, chunk.data(), got);
                pos += got;
                return true;
            };
            if (!hyd.Ingest(read, resume, err)) {
                GlobalOriginStampede().NoteError("cloud-origin", ConnNowMs());
                return false;
            }
            origin_gets += hyd.Progress().origin_get_ops;
        }
        }
        if (!hyd.IsAdvertisable()) {
            err = "cloud hydration not advertisable";
            return false;
        }
        GlobalOriginStampede().NoteSuccess("cloud-origin");
    }
    result.pushKV("cloud_hydrated", true);
    result.pushKV("origin_get_ops", origin_gets);
    return true;
}

void LiveObserveFeed(const FeedEvent& fe)
{
    if (!BoundModelEventJournal()) return;
    ObserveResult ores;
    std::string jerr;
    (void)JournalObserveFeed(fe, ores, jerr);
}

void LiveObserveCampaign(const ReleaseCampaign& c, FeedEventType t)
{
    FeedEvent fe;
    fe.event_type = t;
    fe.model_id = c.model_id;
    fe.release_id = c.release_id.Hex();
    fe.published_at = c.campaign_created_at;
    fe.campaign = c;
    fe.has_campaign = true;
    LiveObserveFeed(fe);
}

bool IsCloudHelperMethod(const std::string& method)
{
    return method == "setcloudstorage" || method == "testcloudstorage" || method == "getcloudstorageinfo" ||
           method == "removemodelstorage" || method == "setmodelstoragepolicy";
}

bool DispatchCloudStorageRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                             std::string& err_code, std::string& err)
{
    auto Arg0 = [&]() -> UniValue {
        if (params.isArray() && params.size() > 0) return params[0];
        if (params.isObject()) return params;
        return UniValue(UniValue::VOBJ);
    };
    if (method == "setcloudstorage") {
        UniValue o = Arg0();
        if (o.isArray() && o.size() > 0 && o[0].isObject()) o = o[0];
        CloudStoreConfig cfg;
        if (!CloudConfigFromJson(o, cfg, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        cfg.budget_state_path = HelperDir(cat) / "cloud-budget.json";
        std::string perr;
        const fs::path cloud_path = HelperDir(cat) / "cloud.json";
        if (!WriteJsonFile(cloud_path, CloudConfigPersistJson(cfg), perr)) {
            err_code = "IO_ERROR";
            err = perr;
            return false;
        }
        std::error_code pec;
        fs::permissions(cloud_path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, pec);
        std::lock_guard<std::mutex> lock(g_cloud_mu);
        g_cloud.reset();
        g_cloud_cfg = cfg;
        g_cloud_dir = HelperDir(cat);
        auto store = std::make_unique<S3PieceStore>(cfg);
        std::string ierr;
        const bool ok = store->Init(ierr);
        if (ok) g_cloud = std::move(store);
        ApplyCloudCapsLocked();
        result = CloudPublicJson();
        result.pushKV("applied", ok);
        result.pushKV("note", ok ? "cloud origin configured locally; credentials stay in the ref"
                                  : (ierr.empty() ? "cloud.json persisted; origin not ready" : ierr));
        if (!ok) result.pushKV("init_error", ierr);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    EnsureCloudLoaded(cat);
    if (method == "testcloudstorage") {
        std::lock_guard<std::mutex> lock(g_cloud_mu);
        result = CloudPublicJson();
        bool probe_ok = false;
        if (g_cloud && g_cloud->IsReady()) {
            std::string dummy = "btx-cloud-probe";
            std::istringstream body(dummy);
            std::string perr;
            if (g_cloud->PutObject("health/probe", body, dummy.size(), perr)) {
                std::vector<unsigned char> got;
                probe_ok = g_cloud->GetObject("health/probe", 0, 0, got, perr) && got.size() == dummy.size();
            }
            result = CloudPublicJson();
            result.pushKV("probe_ok", probe_ok);
            if (!perr.empty()) result.pushKV("probe_error", perr);
        } else {
            result.pushKV("probe_ok", false);
            result.pushKV("note", "configure setcloudstorage first; real HTTPS R2 is NOT_RUN on this host");
        }
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getcloudstorageinfo") {
        EnsureCloudLoaded(cat);
        std::lock_guard<std::mutex> lock(g_cloud_mu);
        result = CloudPublicJson();
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "removemodelstorage") {
        UniValue o = Arg0();
        if (o.isArray() && o.size() > 0 && o[0].isObject()) o = o[0];
        std::string mode = "DETACH";
        if (o.exists("mode") && o["mode"].isStr()) mode = o["mode"].get_str();
        result.pushKV("mode", mode);
        result.pushKV("remote_objects_deleted", false);
        result.pushKV("automatic_spend_atoms", 0);
        if (mode == "MIGRATE") {
            result.pushKV("detached", false);
            result.pushKV("executed", false);
            result.pushKV("note", "MIGRATE is a plan only; no bulk I/O and no remote deletes");
            return true;
        }
        const fs::path cloud_path = HelperDir(cat) / "cloud.json";
        std::error_code rec;
        fs::remove(cloud_path, rec);
        std::lock_guard<std::mutex> lock(g_cloud_mu);
        g_cloud.reset();
        g_cloud_cfg = CloudStoreConfig{};
        ApplyCloudCapsLocked();
        result = CloudPublicJson();
        result.pushKV("detached", true);
        result.pushKV("remote_objects_deleted", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "local handle detached; bucket objects were not deleted");
        return true;
    }
    if (method == "setmodelstoragepolicy") {
        EnsureCloudLoaded(cat);
        std::lock_guard<std::mutex> lock(g_cloud_mu);
        result = CloudPublicJson();
        result.pushKV("policy_applied", g_cloud && g_cloud->IsReady());
        result.pushKV("bulk_io", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "local handle only; entering credentials does not approve unlimited I/O");
        return true;
    }
    err_code = "METHOD_NOT_FOUND";
    err = method;
    return false;
}

bool IsMirrorHelperMethod(const std::string& method)
{
    return method == "getmodelmirror" || method == "setmodelmirror";
}

UniValue MirrorPolicyToJson(const UniValue& stored, const OperatorProfile& prof, const ProfilePolicy& policy)
{
    UniValue o = stored.isObject() ? stored : UniValue(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("role", "node");
    o.pushKV("mirror_privilege", false);
    o.pushKV("consensus", false);
    o.pushKV("search_authority", false);
    o.pushKV("profile", OperatorProfileName(prof));
    o.pushKV("preserve_rare", policy.preserve_rare);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("note", "mirror is a local keep/follow policy, not a monetary or consensus privilege");
    if (!o.exists("selectors") || !o["selectors"].isArray()) {
        o.pushKV("selectors", UniValue(UniValue::VARR));
    }
    return o;
}

bool DispatchMirrorRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                        std::string& err_code, std::string& err)
{
    auto Arg0 = [&]() -> UniValue {
        if (params.isArray() && params.size() > 0) return params[0];
        if (params.isObject()) return params;
        return UniValue(UniValue::VOBJ);
    };
    OperatorProfile prof = OperatorProfile::CUSTOM;
    ProfilePolicy policy;
    std::string perr;
    (void)LoadOperatorProfile(OperatorProfilePath(HelperDir(cat)), prof, policy, perr);
    const fs::path path = HelperDir(cat) / "mirror.json";
    UniValue stored;
    (void)ReadJsonFile(path, stored);
    if (!stored.isObject()) stored.setObject();

    if (method == "getmodelmirror") {
        result = MirrorPolicyToJson(stored, prof, policy);
        return true;
    }
    if (method == "setmodelmirror") {
        UniValue o = Arg0();
        if (o.isArray() && o.size() > 0 && o[0].isObject()) o = o[0];
        if (!o.isObject()) o.setObject();
        if (o.exists("automatic_spend_atoms") && o["automatic_spend_atoms"].getInt<int64_t>() != 0) {
            err_code = "INVALID_PARAMETER";
            err = "automatic_spend_atoms must remain 0";
            return false;
        }
        auto StrField = [&](const char* k) -> std::string {
            if (!o.exists(k) || o[k].isNull()) return {};
            if (o[k].isStr()) return o[k].get_str();
            return {};
        };
        const std::string publisher = StrField("publisher_id");
        const std::string collection = StrField("collection_id");
        const std::string query = StrField("query");
        int keep_latest = 0;
        if (o.exists("keep_latest") && !o["keep_latest"].isNull()) {
            if (o["keep_latest"].isNum()) keep_latest = o["keep_latest"].getInt<int>();
            else if (o["keep_latest"].isStr()) keep_latest = std::atoi(o["keep_latest"].get_str().c_str());
        }
        if (keep_latest < 0) {
            err_code = "INVALID_PARAMETER";
            err = "keep_latest must be non-negative";
            return false;
        }
        UniValue selectors = stored.exists("selectors") && stored["selectors"].isArray() ? stored["selectors"]
                                                                                           : UniValue(UniValue::VARR);
        UniValue sel(UniValue::VOBJ);
        sel.pushKV("publisher_id", publisher);
        sel.pushKV("collection_id", collection);
        sel.pushKV("query", query);
        sel.pushKV("keep_latest", keep_latest);
        sel.pushKV("automatic_spend_atoms", 0);
        UniValue next(UniValue::VARR);
        bool replaced = false;
        for (const UniValue& existing : selectors.getValues()) {
            if (!existing.isObject()) continue;
            const std::string ep = existing.exists("publisher_id") && existing["publisher_id"].isStr()
                                       ? existing["publisher_id"].get_str()
                                       : std::string();
            const std::string ec = existing.exists("collection_id") && existing["collection_id"].isStr()
                                       ? existing["collection_id"].get_str()
                                       : std::string();
            const std::string eq = existing.exists("query") && existing["query"].isStr() ? existing["query"].get_str()
                                                                                         : std::string();
            if (ep == publisher && ec == collection && eq == query) {
                next.push_back(sel);
                replaced = true;
            } else {
                next.push_back(existing);
            }
        }
        if (!replaced && (!publisher.empty() || !collection.empty() || !query.empty() || keep_latest > 0)) {
            next.push_back(sel);
        }
        stored.pushKV("selectors", next);
        stored.pushKV("automatic_spend_atoms", 0);
        std::string werr;
        if (!WriteJsonFile(path, stored, werr)) {
            err_code = "IO_ERROR";
            err = werr;
            return false;
        }
        if (keep_latest > 0 && BoundModelWatchStore()) {
            ModelWatch w;
            w.action = ActionPolicy::KEEP;
            w.keep_n = keep_latest;
            if (!publisher.empty()) {
                w.kind = WatchKind::PUBLISHER;
                w.publisher_id = publisher;
            } else if (!collection.empty()) {
                w.kind = WatchKind::COLLECTION;
                w.collection_id = collection;
            } else if (!query.empty()) {
                w.kind = WatchKind::QUERY;
                w.query_text = query;
            }
            if (w.kind == WatchKind::PUBLISHER || w.kind == WatchKind::COLLECTION || w.kind == WatchKind::QUERY) {
                std::string werr2;
                (void)BoundModelWatchStore()->PutWatch(w, werr2);
                result.pushKV("watch_id", w.watch_id);
            }
        }
        result = MirrorPolicyToJson(stored, prof, policy);
        result.pushKV("publisher_id", publisher);
        result.pushKV("collection_id", collection);
        result.pushKV("query", query);
        result.pushKV("keep_latest", keep_latest);
        result.pushKV("applied", true);
        return true;
    }
    err_code = "METHOD_NOT_FOUND";
    err = method;
    return false;
}

void ExecuteQueuedFreeDownloads(ModelCatalog& cat, UniValue& result)
{
    static thread_local bool in_drain = false;
    if (in_drain || !result.exists("actions") || !result["actions"].isArray()) return;
    in_drain = true;
    UniValue executed(UniValue::VARR);
    for (const UniValue& a_in : result["actions"].getValues()) {
        UniValue a = a_in;
        if (a.isObject() && a.exists("action") && a["action"].isStr() && a["action"].get_str() == "PREPARE_FUNDING") {
            SubscriptionEvent ev;
            if (a.exists("event_id") && a["event_id"].isStr()) ev.event_id = a["event_id"].get_str();
            if (a.exists("object_id") && a["object_id"].isStr()) ev.object_id = a["object_id"].get_str();
            SignedTerms terms;
            terms.known = false;
            a.pushKV("prepare_funding", PrepareFundingPlan(ev, terms));
            a.pushKV("unsigned", true);
            a.pushKV("wallet_signed", false);
            a.pushKV("wallet", false);
            a.pushKV("automatic_spend_atoms", 0);
            executed.push_back(a);
            continue;
        }
        if (a.isObject() && a.exists("action") && a["action"].isStr() && a["action"].get_str() == "FUND_WITH_MANDATE") {
            SubscriptionEvent ev;
            if (a.exists("event_id") && a["event_id"].isStr()) ev.event_id = a["event_id"].get_str();
            if (a.exists("object_id") && a["object_id"].isStr()) ev.object_id = a["object_id"].get_str();
            if (a.exists("publisher_id") && a["publisher_id"].isStr()) ev.publisher_id = a["publisher_id"].get_str();
            if (a.exists("mandate_id") && a["mandate_id"].isStr()) ev.mandate_id = a["mandate_id"].get_str();
            ev.action = "FUND_WITH_MANDATE";
            SignedTerms terms;
            terms.known = false;
            if (a.exists("signed_terms") && a["signed_terms"].isObject()) {
                std::string terr;
                (void)TermsFromJson(a["signed_terms"], terms, terr);
            }
            a.pushKV("prepare_funding", PrepareFundingPlan(ev, terms));
            a.pushKV("unsigned", true);
            a.pushKV("wallet_signed", false);
            a.pushKV("wallet", false);
            a.pushKV("spends", false);
            a.pushKV("automatic_spend_atoms", 0);
            if (ev.mandate_id.empty()) {
                a.pushKV("evaluate_ok", false);
                a.pushKV("evaluate_error", "FUND_WITH_MANDATE requires mandate_id");
                executed.push_back(a);
                continue;
            }
            UniValue p(UniValue::VOBJ);
            p.pushKV("mandate_id", ev.mandate_id);
            p.pushKV("event_id", ev.event_id);
            p.pushKV("object_id", ev.object_id);
            p.pushKV("publisher_id", ev.publisher_id);
            p.pushKV("action", "FUND_WITH_MANDATE");
            if (terms.known) {
                p.pushKV("signed_terms", a["signed_terms"]);
            }
            UniValue rparams(UniValue::VARR);
            rparams.push_back(p);
            UniValue rsv;
            std::string code, gerr;
            const bool ok = DispatchSubscriptionRpc("reservesubscriptionmandate", rparams, rsv, code, gerr);
            a.pushKV("evaluate_ok", ok);
            if (ok) a.pushKV("reservation", rsv);
            else a.pushKV("evaluate_error", gerr);
            executed.push_back(a);
            continue;
        }
        if (!a.isObject() || !a.exists("action") || a["action"].get_str() != "FREE_DOWNLOAD") {
            executed.push_back(a);
            continue;
        }
        if (!a.exists("object_id") || !a["object_id"].isStr() || a["object_id"].get_str().empty()) {
            executed.push_back(a);
            continue;
        }
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", "getmodel");
        UniValue p(UniValue::VARR);
        p.push_back(a["object_id"].get_str());
        p.push_back("FREE_ONLY");
        req.pushKV("params", p);
        UniValue got;
        std::string code, gerr;
        const bool ok = DispatchHelperRpc(cat, req, got, code, gerr, nullptr);
        a.pushKV("queued_for_coordinator", false);
        a.pushKV("executed", ok);
        a.pushKV("getmodel_mode", "FREE_ONLY");
        a.pushKV("getmodel", got);
        if (!ok) a.pushKV("getmodel_error", gerr);
        a.pushKV("automatic_spend_atoms", 0);
        executed.push_back(a);
    }
    UniValue rebuilt(UniValue::VOBJ);
    for (const std::string& k : result.getKeys()) {
        if (k == "actions") continue;
        rebuilt.pushKV(k, result[k]);
    }
    rebuilt.pushKV("actions", executed);
    result = std::move(rebuilt);
    in_drain = false;
}

bool DispatchHelperRpc(ModelCatalog& cat, const UniValue& request, UniValue& result, std::string& err_code, std::string& err, std::atomic<bool>* stop)
{
    result = UniValue(UniValue::VOBJ);
    try {
    const std::string requested =
        (request.exists("method") && request["method"].isStr()) ? request["method"].get_str() : "";
    std::string alias_of;
    const std::string method = ResolveHelperMethodAlias(requested, alias_of);
    struct CatalogAliasStamp {
        UniValue& result;
        std::string alias_of;
        std::string requested;
        ~CatalogAliasStamp()
        {
            if (alias_of.empty() || !result.isObject()) return;
            if (!result.exists("alias_of")) result.pushKV("alias_of", alias_of);
            if (!result.exists("catalog_method")) result.pushKV("catalog_method", requested);
        }
    } alias_stamp{result, alias_of, requested};
    const UniValue params = request.exists("params") ? request["params"] : UniValue(UniValue::VARR);
    auto Arg = [&](size_t i) -> const UniValue& {
        if (params.isArray() && params.size() > i) return params[i];
        static const UniValue none;
        return none;
    };

    if (!BoundModelEventJournal()) BindModelEventLayer(HelperDir(cat));
    EnsureCloudLoaded(cat);
    LoadRetrieveJobs(cat);
    if (IsCloudHelperMethod(method)) {
        if (method == "setcloudstorage" || method == "setmodelstoragepolicy") {
            return WithNetwork02Idempotency(method, params, result, err_code, err, [&] {
                return DispatchCloudStorageRpc(cat, method, params, result, err_code, err);
            });
        }
        return DispatchCloudStorageRpc(cat, method, params, result, err_code, err);
    }
    if (IsNetwork02HelperMethod(method)) {
        return DispatchNetwork02Rpc(cat, method, params, result, err_code, err);
    }
    if (IsHcpHelperMethod(method)) {
        return DispatchHcpRpc(cat, method, params, result, err_code, err);
    }
    if (IsCapabilityHelperMethod(method)) {
        return DispatchCapabilityRpc(cat, method, params, result, err_code, err);
    }
    if (IsMirrorHelperMethod(method)) {
        if (method == "setmodelmirror") {
            return WithNetwork02Idempotency(method, params, result, err_code, err, [&] {
                return DispatchMirrorRpc(cat, method, params, result, err_code, err);
            });
        }
        return DispatchMirrorRpc(cat, method, params, result, err_code, err);
    }
    if (IsModelWatchHelperMethod(method)) {
        const bool ok = DispatchModelWatchRpc(method, params, result, err_code, err, stop);
        if (ok && method == "getmodelwatchactions" && result.exists("actions")) {
            ExecuteQueuedFreeDownloads(cat, result);
            result.pushKV("executed_free_downloads", true);
        }
        return ok;
    }
    if (IsSubscriptionHelperMethod(method)) {
        return DispatchSubscriptionRpc(method, params, result, err_code, err);
    }
    if (method == "getmodelprofile") {
        OperatorProfile prof = OperatorProfile::CUSTOM;
        ProfilePolicy policy;
        std::string perr;
        (void)LoadOperatorProfile(OperatorProfilePath(HelperDir(cat)), prof, policy, perr);
        result = OperatorProfileToJson(prof, policy);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "preset only; no monetary, search, consensus, or bounty privilege");
        return true;
    }
    if (method == "setmodelprofile") {
        std::string name;
        if (params.isArray() && params.size() > 0 && params[0].isStr()) name = params[0].get_str();
        else if (params.isArray() && params.size() > 0 && params[0].isObject() && params[0].exists("profile")) {
            name = params[0]["profile"].get_str();
        }
        OperatorProfile prof = OperatorProfile::CUSTOM;
        if (!ParseOperatorProfile(name, prof)) {
            err_code = "INVALID_PARAMETER";
            err = "profile must be personal|infrastructure|mirror|custom";
            return false;
        }
        ProfileOverrides ov;
        const ProfilePolicy policy = ResolveProfile(prof, ov);
        std::string serr;
        if (!SaveOperatorProfile(OperatorProfilePath(HelperDir(cat)), prof, policy, serr)) {
            err_code = "IO_ERROR";
            err = serr;
            return false;
        }
        result = OperatorProfileToJson(prof, policy);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("applied", true);
        result.pushKV("note", "follow/preserve/upload/host-auto applied live; NODE_MODEL_HOST still follows AutoHostShouldAdvertise");
        ApplyProfilePolicyLive(cat, policy);
        RefreshAdvertisedHost(&cat);
        return true;
    }

    if (IsBountyHelperMethod(method)) {
        const bool ok = DispatchBountyHelperRpc(cat, method, params, result, err_code, err);
        if (ok && (method == "publishbounty" || method == "revisebounty") && result.exists("search_record")) {
            EnsureSearchBound();
            ModelSearchRecord rec;
            std::string ierr;
            const UniValue& sr = result["search_record"];
            rec.object_kind = "BOUNTY";
            rec.expires_at = 0;
            rec.metadata_sequence = 1;
            if (sr.exists("canonical_name") && sr["canonical_name"].isStr()) rec.canonical_name = sr["canonical_name"].get_str();
            if (sr.exists("display_name") && sr["display_name"].isStr()) rec.display_name = sr["display_name"].get_str();
            if (sr.exists("short_description") && sr["short_description"].isStr()) rec.short_description = sr["short_description"].get_str();
            if (sr.exists("description") && sr["description"].isStr()) rec.description = sr["description"].get_str();
            if (result.exists("bounty_id") && result["bounty_id"].isStr()) {
                rec.bounty_id = result["bounty_id"].get_str();
                Digest48::FromHex(rec.bounty_id, rec.model_id, ierr);
                rec.artifact_id = rec.model_id;
            }
            std::vector<unsigned char> pk, sk;
            Digest48 sid;
            if (LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, sid, ierr)) {
                rec.pubkey = pk;
                SignSearchRecord(rec, Span<const unsigned char>{sk.data(), sk.size()}, ierr);
            }
            std::lock_guard<std::mutex> lock(g_search_mu);
            g_search_idx.Put(rec, ConnNowMs(), ierr);
        }
        if (ok && (method == "searchbounties" || method == "getmodelbounties")) {
            UniValue q(UniValue::VOBJ);
            if (params.isArray() && params.size() > 0 && params[0].isObject()) q = params[0];
            else if (params.isObject()) q = params;
            SearchScope scope = SearchScope::LOCAL;
            if (q.exists("scope")) ParseSearchScope(q["scope"].get_str(), scope);
            result.pushKV("global_complete", false);
            if (scope != SearchScope::LOCAL) {
                EnsureSearchBound();
                std::vector<std::string> index_peers;
                std::vector<std::string> fanout;
                auto add_ep = [&](const std::string& ep) {
                    if (ep.empty()) return;
                    if (!g_swarm.bind.empty() && (ep == g_swarm.bind || ep == "[" + g_swarm.bind + "]")) return;
                    if (std::find(fanout.begin(), fanout.end(), ep) != fanout.end()) return;
                    if (static_cast<int>(fanout.size()) >= SEARCH_FANOUT_MAX) return;
                    fanout.push_back(ep);
                };
                {
                    std::lock_guard<std::mutex> lock(g_search_mu);
                    index_peers = g_search_idx.IndexPeers();
                    for (const auto& p : index_peers) add_ep(p);
                    for (const auto& p : cat.Peers()) add_ep(p);
                }
                {
                    std::lock_guard<std::mutex> plock(g_swarm.pex_mu);
                    for (const auto& h : g_swarm.pex.Recent(ConnNowMs())) add_ep(h.endpoint);
                }
                SearchQuery sq;
                std::string perr;
                ParseSearchQuery(q, sq, perr);
                sq.filters.object_kind = "BOUNTY";
                sq.scope = SearchScope::NETWORK;
                SearchJob job;
                {
                    std::lock_guard<std::mutex> lock(g_search_mu);
                    job = g_search_rt.Start(sq, {}, ConnNowMs());
                }
                Pq1Context pq;
                std::string tls_err;
                const fs::path pinfile = HelperDir(cat) / "tls" / "pins.json";
                const bool pq_ok = LoadPq1Identity(pq, HelperDir(cat), tls_err);
                UniValue qbody(UniValue::VOBJ);
                qbody.pushKV("text", sq.text);
                qbody.pushKV("limit", sq.limit);
                qbody.pushKV("ttl", SEARCH_TTL_DEFAULT);
                qbody.pushKV("query_id", job.query_id);
                qbody.pushKV("scope", "LOCAL");
                UniValue filters(UniValue::VOBJ);
                filters.pushKV("object_kind", "BOUNTY");
                qbody.pushKV("filters", filters);
                int index_queried = 0;
                int responses = 0;
                int timed = 0;
                UniValue extra(UniValue::VARR);
                for (const auto& ep : fanout) {
                    {
                        std::lock_guard<std::mutex> cl(g_search_mu);
                        if (g_search_rt.IsCancelled(job.query_id)) break;
                    }
                    if (!pq_ok) {
                        ++timed;
                        continue;
                    }
                    UniValue reply;
                    bool to = false;
                    std::string perr2;
                    const bool is_index = std::find(index_peers.begin(), index_peers.end(), ep) != index_peers.end();
                    if (QuerySearchPeer(pq, pinfile, ep, qbody, reply, to, perr2)) {
                        ++responses;
                        if (is_index) ++index_queried;
                        auto take = [&](const UniValue& arr) {
                            if (!arr.isArray()) return;
                            for (const auto& card : arr.getValues()) {
                                if (!card.isObject()) continue;
                                const std::string kind =
                                    card.exists("object_kind") ? card["object_kind"].get_str() : std::string{};
                                if (!kind.empty() && kind != "BOUNTY") continue;
                                extra.push_back(card);
                            }
                        };
                        if (reply.exists("results")) take(reply["results"]);
                        if (reply.exists("records")) take(reply["records"]);
                    } else if (to) {
                        ++timed;
                    }
                }
                {
                    std::lock_guard<std::mutex> lock(g_search_mu);
                    const auto local_hits = g_search_idx.Search(sq, ConnNowMs());
                    UniValue arr = result.exists("results") && result["results"].isArray() ? result["results"]
                                                                                            : UniValue(UniValue::VARR);
                    std::set<std::string> seen;
                    for (const auto& r : arr.getValues()) {
                        if (r.exists("bounty_id") && r["bounty_id"].isStr()) seen.insert(r["bounty_id"].get_str());
                    }
                    for (const auto& h : local_hits) {
                        if (h.rec.object_kind != "BOUNTY") continue;
                        if (!h.rec.bounty_id.empty() && seen.count(h.rec.bounty_id)) continue;
                        arr.push_back(SearchRecordToJson(h.rec));
                        if (!h.rec.bounty_id.empty()) seen.insert(h.rec.bounty_id);
                    }
                    for (const auto& card : extra.getValues()) {
                        const std::string bid =
                            card.exists("bounty_id") && card["bounty_id"].isStr() ? card["bounty_id"].get_str() : "";
                        if (!bid.empty() && seen.count(bid)) continue;
                        arr.push_back(card);
                        if (!bid.empty()) seen.insert(bid);
                    }
                    result.pushKV("results", arr);
                    g_search_rt.Finish(job);
                }
                result.pushKV("complete", false);
                result.pushKV("global_complete", false);
                result.pushKV("index_peers_configured", static_cast<int>(index_peers.size()));
                result.pushKV("index_peers_queried", index_queried);
                result.pushKV("responses_received", responses);
                result.pushKV("timed_out", timed);
                result.pushKV("query_id", job.query_id);
                result.pushKV("fanout_attempted", true);
            } else {
                EnsureSearchBound();
                SearchQuery sq;
                std::string perr;
                ParseSearchQuery(q, sq, perr);
                sq.filters.object_kind = "BOUNTY";
                std::lock_guard<std::mutex> lock(g_search_mu);
                const auto local_hits = g_search_idx.Search(sq, ConnNowMs());
                UniValue arr = result.exists("results") && result["results"].isArray() ? result["results"]
                                                                                    : UniValue(UniValue::VARR);
                std::set<std::string> seen;
                for (const auto& r : arr.getValues()) {
                    if (r.exists("bounty_id") && r["bounty_id"].isStr()) seen.insert(r["bounty_id"].get_str());
                }
                for (const auto& h : local_hits) {
                    if (h.rec.object_kind != "BOUNTY") continue;
                    const std::string bid = h.rec.bounty_id.empty() ? h.rec.model_id.Hex() : h.rec.bounty_id;
                    if (!bid.empty() && seen.count(bid)) continue;
                    UniValue card(UniValue::VOBJ);
                    card.pushKV("bounty_id", bid);
                    card.pushKV("object_kind", "BOUNTY");
                    card.pushKV("title", h.rec.canonical_name);
                    card.pushKV("description", h.rec.short_description.empty() ? h.rec.description : h.rec.short_description);
                    arr.push_back(card);
                    if (!bid.empty()) seen.insert(bid);
                }
                UniValue out(UniValue::VOBJ);
                if (result.isObject()) {
                    for (const std::string& k : result.getKeys()) {
                        if (k == "results") continue;
                        out.pushKV(k, result[k]);
                    }
                }
                out.pushKV("results", arr);
                result = out;
            }
        }
        return ok;
    }

    if (method == "getmodelnetworkinfo" || method == "getmodelcryptoinfo") {
        result.pushKV("schema_version", 2);
        result.pushKV("enabled", true);
        result.pushKV("helper_ready", true);
        Pq1Context pq;
        result.pushKV("pq1_ready", pq.Ready());
        result.pushKV("error", pq.Ready() ? "" : pq.Error());
        result.pushKV("openssl", OpenSSL_version(OPENSSL_VERSION));
        result.pushKV("transport", "pq1");
        result.pushKV("quic", false);
        result.pushKV("evaluated_transport", [] {
            UniValue o(UniValue::VOBJ);
            o.pushKV("utp", "NONSHIPPING");
            o.pushKV("quic", false);
            o.pushKV("content_defined_dedup", "NONSHIPPING");
            o.pushKV("erasure_64_80", "NONSHIPPING");
            o.pushKV("catalog_10m", "NOT_RUN");
            o.pushKV("btx_torrentd_process", false);
            return o;
        }());
        result.pushKV("group", "MLKEM768");
        result.pushKV("cipher", "TLS_AES_256_GCM_SHA384");
        result.pushKV("sigalg", "mldsa44");
        result.pushKV("max_send_fragment", 512);
        result.pushKV("resumption", false);
        result.pushKV("early_data", false);
        result.pushKV("retrieval_default", "FREE_ONLY");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("quota_bytes", cat.QuotaBytes());
        result.pushKV("used_bytes", cat.UsedBytes());
        result.pushKV("storage_mode", StorageModeName(g_runtime.storage_mode));
        result.pushKV("storage_target_bytes", g_runtime.target_bytes);
        result.pushKV("storage_effective_quota_bytes", g_runtime.effective_quota ? g_runtime.effective_quota : cat.QuotaBytes());
        result.pushKV("storage_used_bytes", cat.UsedBytes());
        result.pushKV("storage_pinned_bytes", cat.PinnedBytes());
        result.pushKV("storage_reclaimable_bytes", cat.ReclaimableBytes());
        result.pushKV("filesystem_capacity_bytes", g_runtime.fs_capacity);
        result.pushKV("filesystem_available_bytes", g_runtime.fs_available);
        result.pushKV("filesystem_reserve_bytes", g_runtime.reserve_bytes);
        result.pushKV("seed_mode", cat.Policy().seed_mode == SeedMode::AUTO ? "auto" : SeedModeName(cat.Policy().seed_mode));
        result.pushKV("demand_seed", g_runtime.demand_seed && cat.Policy().seed_mode == SeedMode::AUTO && cat.QuotaBytes() > 0);
        result.pushKV("preserve_rare", g_runtime.preserve_rare);
        result.pushKV("follow_configured_peers", cat.Policy().follow_configured_peers);
        result.pushKV("public_host_reachable", g_runtime.public_host_reachable);
        RefreshAdvertisedHost(&cat);
        result.pushKV("advertised_host", g_runtime.advertised_host);
        {
            FileStreamCaps caps;
            caps.random_piece_access = true;
            caps.sequential_file_stream = true;
            std::vector<std::string> origin_ids;
            bool source_files = true;
            uint64_t n_files = 0;
            uint64_t n_pieces = 0;
            {
                std::lock_guard<std::mutex> lock(g_cloud_mu);
                const bool ready = g_cloud && g_cloud->IsReady();
                const bool live_origin = ready && !g_cloud_cfg.s3.use_fake;
                caps.direct_file_seed = live_origin && g_cloud->Layout() == CloudObjectLayout::SOURCE_FILES;
                caps.origin_file_complete = ready;
                caps.local_piece_complete = CatalogHasVerifiedSeededRange(cat);
                source_files = !ready || g_cloud->Layout() == CloudObjectLayout::SOURCE_FILES;
                if (ready) {
                    if (live_origin) origin_ids.push_back(std::string("cloud:") + g_cloud_cfg.s3.bucket);
                    result.pushKV("cloud_storage", CloudPublicJson());
                }
            }
            result.pushKV("delivery", FileStreamCapsJson(caps));
            result.pushKV("origin_diversity", OriginDiversityJson(SummarizeOriginDiversity(
                0, 0, 0, origin_ids, /*enough_p2p_without_origin=*/false)));
            result.pushKV("cloud_amplification", CloudAmplificationJson(n_files, n_pieces, source_files));
            result.pushKV("origin_stampede", GlobalOriginStampede().Json(ConnNowMs()));
        }
        result.pushKV("nat_limited", !g_runtime.public_host_reachable);
        result.pushKV("nat_status", ModelNatStatusName(g_swarm.nat.status));
        result.pushKV("relay_status", g_swarm.relay ? "optional" : "off");
        result.pushKV("peers_connected", GlobalConnLimits().Inbound() + GlobalConnLimits().Outbound());
        result.pushKV("providers_known", g_swarm.providers_known);
        result.pushKV("min_rarity", g_swarm.min_rarity);
        result.pushKV("rare_pieces_1_source", g_swarm.rare_1);
        result.pushKV("rare_pieces_2_sources", g_swarm.rare_2);
        {
            std::lock_guard<std::mutex> lock(g_swarm.snap_mu);
            if (g_swarm.last_swarm_json.isObject()) result.pushKV("swarm", g_swarm.last_swarm_json);
        }
        result.pushKV("active_piece_requests", g_swarm.active_piece_requests.load());
        result.pushKV("duplicate_endgame_requests", g_swarm.duplicate_endgame_requests.load());
        result.pushKV("current_endgame", g_swarm.current_endgame.load());
        result.pushKV("partial_seeded_pieces", g_swarm.partial_seeded_pieces.load());
        result.pushKV("bytes_served_while_partial", g_swarm.bytes_served_while_partial.load());
        result.pushKV("pex_records_received", g_swarm.pex_received.load());
        result.pushKV("pex_records_accepted", g_swarm.pex_accepted.load());
        {
            std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
            const UniValue rs = g_swarm.reach.StatusJson();
            result.pushKV("reachability_state", rs["reachability_state"]);
            result.pushKV("direct_ipv4", g_swarm.reach.BestCandidate());
            result.pushKV("direct_ipv6", "");
            result.pushKV("mapped_endpoint", rs["mapped_endpoint"]);
            result.pushKV("external_observations", rs["observations"]);
            result.pushKV("relay_reservations", g_swarm.relays.StatusJson());
            result.pushKV("active_relay", rs["relay"]);
            result.pushKV("routing_table_size", static_cast<int>(g_swarm.routes.Size()));
            result.pushKV("provider_cache_size", static_cast<int>(g_swarm.providers.Size()));
            result.pushKV("bootstrap_peers", 0);
            result.pushKV("bootstrap_dependency", !BootstrapIndependent(true, g_swarm.routes.Size()) && g_swarm.routes.Size() == 0);
            result.pushKV("network_epoch", static_cast<int64_t>(g_swarm.net_epoch.epoch));
        }
        result.pushKV("last_provider_lookup", g_swarm.last_provider_lookup.load());
        result.pushKV("provider_records_found", g_swarm.provider_records_found.load());
        result.pushKV("hole_punch_attempts", g_swarm.hole_punch_attempts.load());
        result.pushKV("hole_punch_successes", g_swarm.hole_punch_successes.load());
        result.pushKV("relay_bytes", g_swarm.relay_bytes.load());
        result.pushKV("direct_bytes", g_swarm.direct_bytes.load());
        result.pushKV("classical_fallback", false);
        result.pushKV("upload_limit", g_runtime.upload_bps);
        result.pushKV("active_transfers", g_runtime.active_transfers);
        result.pushKV("helper_managed_by_btxd", false);
        result.pushKV("helper_state", "READY");
        result.pushKV("helper_pid", static_cast<int>(getpid()));
        result.pushKV("helper_restart_count", 0);
        result.pushKV("propagation", PolicyToJson(cat.Policy()));
        result.pushKV("capabilities", CapabilitiesObject());
        result.pushKV("http_workers", PQ1_HTTP_WORKERS);
        result.pushKV("http_queue", PQ1_HTTP_QUEUE);
        result.pushKV("inflight_pieces", PQ1_INFLIGHT_PIECES);
        result.pushKV("inbound_per_netgroup", PQ1_MAX_INBOUND_PER_NETGROUP);
        result.pushKV("transfer_timeout_ms", PQ1_TRANSFER_MS);
        result.pushKV("inbound_connections", GlobalConnLimits().Inbound());
        result.pushKV("outbound_connections", GlobalConnLimits().Outbound());
        result.pushKV("peer_pin", "TOFU tls_spki_hash D384(BTX/TransportKey/v2, DER_SPKI)");
        result.pushKV("htlc", "reuses final 0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund");
        result.pushKV("node_model_index", true);
        result.pushKV("search_ttl_default", SEARCH_TTL_DEFAULT);
        result.pushKV("search_ttl_max", SEARCH_TTL_MAX);
        result.pushKV("search_monetary_coupling", false);
        AttachDoctor(cat, result);
        return true;
    }
    if (method == "checkmodelsetup") {
        result.pushKV("schema_version", 2);
        result.pushKV("helper_ready", true);
        result.pushKV("quota_bytes", cat.QuotaBytes());
        result.pushKV("used_bytes", cat.UsedBytes());
        result.pushKV("seed_mode", cat.Policy().seed_mode == SeedMode::AUTO ? "auto" : SeedModeName(cat.Policy().seed_mode));
        result.pushKV("automatic_spend_atoms", 0);
        AttachDoctor(cat, result);
        return true;
    }
    if (method == "getsetupstatus") {
        // Helper unix public surface (AHP-PRIV-08). Money plane stays on btxd.
        UniValue models(UniValue::VOBJ);
        models.pushKV("schema_version", 2);
        models.pushKV("helper_ready", true);
        models.pushKV("quota_bytes", cat.QuotaBytes());
        models.pushKV("used_bytes", cat.UsedBytes());
        models.pushKV("seed_mode", cat.Policy().seed_mode == SeedMode::AUTO ? "auto" : SeedModeName(cat.Policy().seed_mode));
        models.pushKV("automatic_spend_atoms", 0);
        AttachDoctor(cat, models);
        UniValue money(UniValue::VOBJ);
        money.pushKV("error", "start btxd");
        money.pushKV("note", "money doctor is btxd getsetupstatus; helper unix returns models only");
        UniValue next(UniValue::VARR);
        next.push_back("start btxd");
        if (models.exists("ready_to_host") && models["ready_to_host"].isTrue()) {
            next.push_back("hostmodel <path>");
        }
        result.pushKV("schema_version", 1);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("money", money);
        result.pushKV("models", models);
        result.pushKV("next_actions", next);
        return true;
    }
    if (method == "hello") {
        result.pushKV("schema_version", 2);
        result.pushKV("protocol", 2);
        result.pushKV("suite", "pq1");
        result.pushKV("group", "MLKEM768");
        result.pushKV("cipher", "TLS_AES_256_GCM_SHA384");
        result.pushKV("sigalg", "mldsa44");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("full_file_stream_v1", true);
        result.pushKV("capability", FULL_FILE_STREAM_V1);
        result.pushKV("capabilities", HelloCapabilityArrayMaybeIntersect(params.isObject() ? params : Arg(0)));
        result.pushKV("subpiece_v1", true);
        result.pushKV("quic", false);
        FileStreamCaps caps;
        caps.random_piece_access = true;
        caps.sequential_file_stream = true;
        result.pushKV("delivery", FileStreamCapsJson(caps));
        result.pushKV("note", "A BTX node already has compute. BTX gives it models and money.");
        return true;
    }
    if (method == "lookupmodelproviders") {
        Digest48 id;
        if (!Digest48::FromHex(Arg(0).get_str(), id, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        LookupBudget budget;
        budget.start_ms = ConnNowMs();
        std::vector<ProviderRecord> found;
        std::lock_guard<std::mutex> lock(g_swarm.conn_mu);
        (void)LookupStep(g_swarm.routes, g_swarm.providers, id, budget, ConnNowMs(), found, err);
        g_swarm.last_provider_lookup.store(static_cast<int>(ConnNowMs() / 1000));
        g_swarm.provider_records_found.store(static_cast<int>(found.size()));
        UniValue arr(UniValue::VARR);
        for (const auto& r : found) arr.push_back(ProviderRecordToJson(r));
        result.pushKV("schema_version", 2);
        result.pushKV("records", arr);
        result.pushKV("queries", budget.queries);
        result.pushKV("authoritative", false);
        result.pushKV("inference", false);
        return true;
    }
    if (method == "decoderesource" || method == "decoderesourceuri" || method == "openbtxuri" || method == "openmodelshare") {
        Resource r;
        std::string user = Arg(0).isStr() ? Arg(0).get_str() : "";
        const fs::path maybe = fs::PathFromString(user);
        if (fs::is_regular_file(maybe)) {
            std::error_code ec;
            const auto sz = fs::file_size(maybe, ec);
            if (!ec && sz <= 65536) {
                std::string share_text, serr;
                if (LoadShareText(maybe, share_text, serr)) user = share_text;
            }
        }
        const std::string token = FirstBtxToken(user);
        const std::string use = token.empty() ? user : token;
        if (!DecodeResource(use, r, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("uri", r.Uri());
        result.pushKV("kind", ResourceKindName(r.kind));
        result.pushKV("digest", r.digest.Hex());
        if (method == "openbtxuri" || method == "openmodelshare") {
            UniValue actions(UniValue::VARR);
            if (r.kind == ResourceKind::MODEL) {
                actions.push_back("getmodelsharecard");
                actions.push_back("getmodelmanifest");
                actions.push_back("getmodel FREE_ONLY");
                actions.push_back("exportmodelpath");
            } else {
                actions.push_back("getbounty");
                actions.push_back("getbountyeconomy");
            }
            result.pushKV("proposed_actions", actions);
            result.pushKV("next_actions", actions);
            UniValue share(UniValue::VOBJ);
            share.pushKV("uri", r.Uri());
            share.pushKV("copy_text", r.Uri());
            result.pushKV("share", share);
            result.pushKV("network", false);
            result.pushKV("inference", false);
            result.pushKV("wallet", false);
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("note", "Preview only. Opening a URI never runs inference, mining, or spend.");
        }
        return true;
    }
    if (method == "encoderesource" || method == "encoderesourceuri") {
        ResourceKind kind = ResourceKind::MODEL;
        bool found = false;
        for (int i = 0; i <= 8; ++i) {
            ResourceKind k;
            if (ResourceKindFromInt(i, k) && Arg(0).get_str() == ResourceKindName(k)) {
                kind = k;
                found = true;
                break;
            }
        }
        if (!found) {
            err_code = "INVALID_PARAMETER";
            err = "unknown resource kind";
            return false;
        }
        Digest48 d;
        if (!Digest48::FromHex(Arg(1).get_str(), d, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        std::string uri;
        if (!EncodeResource(kind, d, uri, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result = uri;
        return true;
    }
    if (method == "importmodel" || method == "hostmodel") {
        const std::string path = Arg(0).get_str();
        const fs::path src = fs::PathFromString(path);
        if (LooksLikeSharePath(src)) {
            std::string share_text, share_err;
            (void)LoadShareText(src, share_text, share_err);
            const std::string token = FirstBtxToken(share_text.empty() ? path : share_text);
            ModelSearchRecord rec;
            CatalogEntry e;
            bool local = false;
            if (!token.empty()) {
                std::string dummy;
                const Digest48 sid = ResolveUserId(token, dummy);
                if (!sid.IsNull()) {
                    local = cat.Find(sid, e);
                    std::lock_guard<std::mutex> lock(g_search_mu);
                    if (const auto* r = g_search_idx.Get(sid)) rec = *r;
                    else if (local) rec = DraftSearchFromCatalog(e);
                }
            }
            result.pushKV("schema_version", 2);
            result.pushKV("imported", false);
            result.pushKV("host", false);
            result.pushKV("reason", "share_card");
            result.pushKV("share_text", share_text.empty() ? path : share_text);
            result.pushKV("uri", token);
            result.pushKV("share", MakeShareObject(token, rec));
            result.pushKV("local", local);
            result.pushKV("next_actions", NextActionsArray({
                "getmodel " + (token.empty() ? path : token) + " FREE_ONLY",
                "showmodel",
                "openmodelshare",
            }));
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("note", "this path is a share card, not weights; getmodel retrieves, hostmodel hosts a GGUF/SafeTensors directory");
            return true;
        }
        bool pin = true;
        bool publish = true;
        if (params.isArray() && params.size() > 1 && params[1].isObject()) {
            if (params[1].exists("pin")) pin = params[1]["pin"].get_bool();
            if (params[1].exists("publish")) publish = params[1]["publish"].get_bool();
        }
        return ImportAndPublish(cat, path, pin, publish, result, err_code, err);
    }
    if (method == "previewmodelimport") {
        const std::string path = Arg(0).get_str();
        std::vector<std::pair<fs::path, std::string>> files;
        if (!CollectPreviewFiles(fs::PathFromString(path), files, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        uint64_t bytes = 0;
        bool saw_gguf = false, saw_st = false;
        UniValue filej(UniValue::VARR);
        for (const auto& f : files) {
            const uint64_t sz = fs::is_regular_file(f.first) ? static_cast<uint64_t>(fs::file_size(f.first)) : 0;
            bytes += sz;
            const auto lower = ToLower(f.second);
            if (lower.ends_with(".gguf")) saw_gguf = true;
            if (lower.ends_with(".safetensors")) saw_st = true;
            UniValue o(UniValue::VOBJ);
            o.pushKV("path", f.second);
            o.pushKV("bytes", sz);
            filej.push_back(o);
        }
        const std::string label = fs::PathToString(fs::PathFromString(path).filename());
        result.pushKV("schema_version", 2);
        result.pushKV("path", path);
        result.pushKV("file_count", static_cast<int>(files.size()));
        result.pushKV("bytes", bytes);
        result.pushKV("quota_bytes", cat.QuotaBytes());
        result.pushKV("used_bytes", cat.UsedBytes());
        result.pushKV("would_fit", cat.QuotaBytes() > 0 && cat.UsedBytes() + bytes <= cat.QuotaBytes());
        result.pushKV("remaining_bytes", cat.QuotaBytes() > cat.UsedBytes() ? cat.QuotaBytes() - cat.UsedBytes() : 0);
        result.pushKV("one_liner", (cat.QuotaBytes() > 0 && cat.UsedBytes() + bytes <= cat.QuotaBytes()) ? ("hostmodel " + path) : "would not fit quota");
        result.pushKV("format", saw_gguf && !saw_st ? "gguf" : (saw_st ? "safetensors" : ""));
        result.pushKV("family", InferFamilyFromLabel(label));
        result.pushKV("quantization", InferQuantizationFromLabel(label));
        result.pushKV("files", filej);
        result.pushKV("hashes", false);
        result.pushKV("next_actions", NextActionsArray({"hostmodel " + path}));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelsharecard") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            err = err.empty() ? "id" : err;
            return false;
        }
        CatalogEntry e;
        const bool local = cat.Find(id, e);
        ModelSearchRecord rec;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* r = g_search_idx.Get(id)) rec = *r;
            else if (local) rec = DraftSearchFromCatalog(e);
        }
        std::string uri = rec.btx_uri;
        if (uri.empty() && local) EncodeResource(ResourceKind::MODEL, e.model_id, uri, err);
        if (uri.empty() && !id.IsNull()) EncodeResource(ResourceKind::MODEL, id, uri, err);
        result.pushKV("schema_version", 2);
        result.pushKV("share", MakeShareObject(uri, rec));
        result.pushKV("local", local);
        result.pushKV("signed_metadata", rec.signed_ok);
        result.pushKV("next_actions", NextActionsArray({"showmodel", "getmodel FREE_ONLY"}));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "showmodel") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            err = err.empty() ? "id" : err;
            return false;
        }
        CatalogEntry e;
        const bool local = cat.Find(id, e);
        ModelSearchRecord rec;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* r = g_search_idx.Get(id)) rec = *r;
            else if (local) rec = DraftSearchFromCatalog(e);
        }
        std::string uri = rec.btx_uri;
        if (uri.empty() && local) EncodeResource(ResourceKind::MODEL, e.model_id, uri, err);
        if (uri.empty()) EncodeResource(ResourceKind::MODEL, id, uri, err);
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", id.Hex());
        result.pushKV("uri", uri);
        result.pushKV("share", MakeShareObject(uri, rec));
        result.pushKV("local", local);
        UniValue aliases(UniValue::VARR);
        for (const auto& a : rec.aliases) aliases.push_back(a);
        result.pushKV("aliases", aliases);
        result.pushKV("name", !rec.aliases.empty() ? rec.aliases.front() : rec.display_name);
        result.pushKV("family", rec.family);
        result.pushKV("format", rec.format);
        result.pushKV("quantization", rec.quantization);
        result.pushKV("architecture", rec.architecture);
        {
            UniValue details(UniValue::VOBJ);
            details.pushKV("format", rec.format);
            details.pushKV("family", rec.family);
            UniValue families(UniValue::VARR);
            if (!rec.family.empty()) families.push_back(rec.family);
            details.pushKV("families", families);
            if (rec.parameter_count > 0) details.pushKV("parameter_size", rec.parameter_count);
            else details.pushKV("parameter_size", UniValue());
            details.pushKV("quantization_level", rec.quantization);
            result.pushKV("details", details);
        }
        if (rec.parameter_count > 0) result.pushKV("parameters", rec.parameter_count);
        else result.pushKV("parameters", UniValue());
        {
            UniValue langs(UniValue::VARR);
            for (const auto& l : rec.languages) langs.push_back(l);
            result.pushKV("languages", langs);
            UniValue tags(UniValue::VARR);
            for (const auto& t : rec.tags) tags.push_back(t);
            result.pushKV("tags", tags);
        }
        result.pushKV("description", !rec.short_description.empty() ? rec.short_description : rec.description);
        result.pushKV("signed_metadata", rec.signed_ok);
        if (local) {
            uint64_t bytes = 0;
            for (const auto& f : e.core.files) bytes += f.size;
            result.pushKV("bytes", bytes);
            result.pushKV("file_count", static_cast<int>(e.core.files.size()));
            result.pushKV("seeded", e.seeded);
            result.pushKV("pinned", e.pinned);
            result.pushKV("imported_at", e.imported_at);
            UniValue files(UniValue::VARR);
            UniValue siblings(UniValue::VARR);
            for (const auto& f : e.core.files) {
                UniValue ff(UniValue::VOBJ);
                ff.pushKV("path", f.path);
                ff.pushKV("size", static_cast<int64_t>(f.size));
                ff.pushKV("role", FileRoleName(f.role));
                files.push_back(ff);
                UniValue sib(UniValue::VOBJ);
                sib.pushKV("rfilename", f.path);
                sib.pushKV("size", static_cast<int64_t>(f.size));
                siblings.push_back(sib);
            }
            result.pushKV("files", files);
            result.pushKV("siblings", siblings);
        }
        result.pushKV("next_actions", NextActionsArray({
            local ? std::string("exportmodelpath") : std::string("getmodel FREE_ONLY"),
            "getmodelsharecard",
        }));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "exportmodellink") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        CatalogEntry e;
        const bool local = cat.Find(id, e);
        ModelSearchRecord rec;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* r = g_search_idx.Get(id)) rec = *r;
            else if (local) rec = DraftSearchFromCatalog(e);
        }
        std::string uri = rec.btx_uri;
        if (uri.empty() && local) EncodeResource(ResourceKind::MODEL, e.model_id, uri, err);
        if (uri.empty()) EncodeResource(ResourceKind::MODEL, id, uri, err);
        UniValue share = MakeShareObject(uri, rec);
        UniValue link(UniValue::VOBJ);
        link.pushKV("schema_version", 2);
        link.pushKV("kind", "MODEL");
        link.pushKV("uri", share["uri"]);
        link.pushKV("copy_text", share["copy_text"]);
        link.pushKV("family", rec.family);
        link.pushKV("format", rec.format);
        link.pushKV("quantization", rec.quantization);
        link.pushKV("signed", rec.signed_ok);
        result.pushKV("schema_version", 2);
        result.pushKV("share", share);
        result.pushKV("link", link);
        if (params.isArray() && params.size() > 1 && Arg(1).isStr() && !Arg(1).get_str().empty()) {
            const fs::path outp = fs::PathFromString(Arg(1).get_str());
            if (!outp.parent_path().empty()) fs::create_directories(outp.parent_path());
            std::ofstream f(outp, std::ios::trunc);
            if (!f) {
                err_code = "IO";
                err = "write link file";
                return false;
            }
            f << link.write(2, 0) << "\n";
            result.pushKV("path", Arg(1).get_str());
            result.pushKV("written", true);
        }
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"openmodelshare", "getmodel FREE_ONLY"}));
        return true;
    }
    if (method == "unhostmodel") {
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        std::string perr;
        (void)cat.PinModel(id, false, perr);
        if (!cat.Seed(id, false, err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", id.Hex());
        result.pushKV("pinned", false);
        result.pushKV("seeded", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"seedmodel", "pinmodel"}));
        return true;
    }
    if (method == "removemodelalias") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull() || !Arg(1).isStr()) {
            err_code = "INVALID_PARAMETER";
            err = "id and alias required";
            return false;
        }
        const std::string alias = Arg(1).get_str();
        ModelSearchRecord rec;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* prev = g_search_idx.Get(id)) {
                rec = *prev;
                rec.metadata_sequence = prev->metadata_sequence + 1;
            }
        }
        if (rec.model_id.IsNull()) {
            err_code = "NOT_FOUND";
            err = "unknown model";
            return false;
        }
        rec.aliases.erase(std::remove(rec.aliases.begin(), rec.aliases.end(), alias), rec.aliases.end());
        std::string serr;
        if (!SignSearchRecordWithDefaultIdentity(HelperDir(cat), rec, serr)) {
            err_code = "CRYPTO";
            err = serr;
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (!g_search_idx.Put(rec, ConnNowMs(), err)) {
                err_code = "REJECTED";
                if (err.empty()) err = "search put rejected";
                return false;
            }
            AfterIndexPut(rec, ConnNowMs());
        }
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", rec.model_id.Hex());
        result.pushKV("removed", alias);
        result.pushKV("signed_metadata", rec.signed_ok);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodeltransfers") {
        UniValue listed;
        cat.List(listed);
        UniValue arr(UniValue::VARR);
        if (listed.exists("models") && listed["models"].isArray()) {
            for (const auto& m : listed["models"].getValues()) {
                UniValue o = m;
                DecorateCatalogRow(cat, o);
                if (Arg(0).isObject()) {
                    if (Arg(0).exists("pinned") && o.exists("pinned") && o["pinned"].isBool() &&
                        o["pinned"].get_bool() != Arg(0)["pinned"].get_bool()) continue;
                    if (Arg(0).exists("seeded") && o.exists("seeded") && o["seeded"].isBool() &&
                        o["seeded"].get_bool() != Arg(0)["seeded"].get_bool()) continue;
                }
                arr.push_back(o);
            }
        }
        {
            std::vector<std::shared_ptr<RetrieveJob>> jobs;
            {
                std::lock_guard<std::mutex> lock(g_retrieve_mu);
                for (auto& kv : g_retrieve_jobs) jobs.push_back(kv.second);
            }
            for (auto& job : jobs) {
                if (!job || job->model_id.IsNull()) continue;
                const std::string mid = job->model_id.Hex();
                UniValue jj = RetrieveJobJson(*job);
                std::string st;
                {
                    std::lock_guard<std::mutex> jl(job->mu);
                    st = job->status;
                }
                UniValue rebuilt(UniValue::VARR);
                bool found = false;
                for (const auto& t : arr.getValues()) {
                    UniValue o = t;
                    if (o.exists("model_id") && o["model_id"].isStr() && o["model_id"].get_str() == mid) {
                        found = true;
                        if (jj.exists("bytes_per_sec")) o.pushKV("bytes_per_sec", jj["bytes_per_sec"]);
                        o.pushKV("job_id", job->id);
                        if (o.exists("bytes") && o["bytes"].isNum() && jj.exists("bytes_committed")) {
                            const int64_t total = o["bytes"].getInt<int64_t>();
                            const int64_t done = jj["bytes_committed"].getInt<int64_t>();
                            o.pushKV("bytes_committed", done);
                            o.pushKV("percent", total > 0 ? static_cast<int>(std::min<int64_t>(100, done * 100 / total)) : 0);
                            if (jj.exists("bytes_per_sec") && jj["bytes_per_sec"].getInt<int64_t>() > 0 && total > done) {
                                o.pushKV("eta_s", (total - done) / jj["bytes_per_sec"].getInt<int64_t>());
                            }
                        }
                        if (jj.exists("pieces_committed")) o.pushKV("pieces_committed", jj["pieces_committed"]);
                        o.pushKV("resumable", st == "running" || (o.exists("percent") && o["percent"].isNum() && o["percent"].getInt<int>() < 100));
                        if (st == "running") o.pushKV("state", "downloading");
                        if (jj.exists("stalled_for_ms")) o.pushKV("stalled_for_ms", jj["stalled_for_ms"]);
                        if (jj.exists("last_err")) o.pushKV("last_err", jj["last_err"]);
                    }
                    rebuilt.push_back(o);
                }
                arr = rebuilt;
                if (!found) {
                    UniValue o(UniValue::VOBJ);
                    o.pushKV("model_id", mid);
                    o.pushKV("state", st == "running" ? "downloading" : st);
                    o.pushKV("job_id", job->id);
                    if (jj.exists("bytes_per_sec")) o.pushKV("bytes_per_sec", jj["bytes_per_sec"]);
                    arr.push_back(o);
                }
            }
        }
        result.pushKV("schema_version", 2);
        result.pushKV("transfers", arr);
        result.pushKV("count", static_cast<int>(arr.size()));
        result.pushKV("active_transfers", g_runtime.active_transfers);
        {
            std::lock_guard<std::mutex> lock(g_swarm.snap_mu);
            if (g_swarm.last_swarm_json.isObject()) result.pushKV("swarm", g_swarm.last_swarm_json);
        }
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"getmodeljob"}));
        return true;
    }
    if (method == "setmodelalias") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull() || !Arg(1).isStr()) {
            err_code = "INVALID_PARAMETER";
            err = "id and alias required";
            return false;
        }
        const std::string alias = Arg(1).get_str();
        if (alias.empty() || alias.size() > SEARCH_ALIAS_MAX) {
            err_code = "INVALID_PARAMETER";
            err = "alias";
            return false;
        }
        ModelSearchRecord rec;
        CatalogEntry local;
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (const auto* prev = g_search_idx.Get(id)) {
                rec = *prev;
                rec.metadata_sequence = prev->metadata_sequence + 1;
            }
        }
        if (rec.model_id.IsNull()) {
            if (!cat.Find(id, local)) {
                err_code = "NOT_FOUND";
                err = "unknown model";
                return false;
            }
            rec = DraftSearchFromCatalog(local);
            rec.model_id = local.model_id;
            EncodeResource(ResourceKind::MODEL, rec.model_id, rec.btx_uri, err);
        }
        if (std::find(rec.aliases.begin(), rec.aliases.end(), alias) == rec.aliases.end()) {
            if (rec.aliases.size() >= SEARCH_ALIASES_MAX) {
                err_code = "INVALID_PARAMETER";
                err = "alias cap";
                return false;
            }
            rec.aliases.push_back(alias);
        }
        std::string serr;
        if (!SignSearchRecordWithDefaultIdentity(HelperDir(cat), rec, serr)) {
            err_code = "CRYPTO";
            err = serr;
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (!g_search_idx.Put(rec, ConnNowMs(), err)) {
                err_code = "REJECTED";
                if (err.empty()) err = "search put rejected";
                return false;
            }
            AfterIndexPut(rec, ConnNowMs());
        }
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", rec.model_id.Hex());
        result.pushKV("alias", alias);
        result.pushKV("signed_metadata", rec.signed_ok);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelwatchstatus") {
        result.pushKV("schema_version", 2);
        result.pushKV("watch_dir", g_runtime.watch_dir);
        result.pushKV("configured", !g_runtime.watch_dir.empty());
        result.pushKV("last_scan_ms", g_runtime.last_watch_scan_ms);
        result.pushKV("last_imported_count", g_runtime.last_watch_imported);
        result.pushKV("last_skipped", g_runtime.last_watch_skipped);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"scanmodelwatch", "hostmodel <path>"}));
        result.pushKV("one_liner", g_runtime.watch_dir.empty() ? "set -modelwatch=<dir>" : ("scanmodelwatch " + g_runtime.watch_dir));
        return true;
    }
    if (method == "scanmodelwatch") {
        std::string werr;
        const std::string override_dir = Arg(0).isStr() ? Arg(0).get_str() : "";
        ScanWatchDir(cat, result, werr, override_dir);
        if (!werr.empty() && result.exists("error")) {
            err_code = "INVALID_PARAMETER";
            err = werr;
            return false;
        }
        return true;
    }
    if (method == "listmodels") {
        cat.List(result);
        if (result.exists("models") && result["models"].isArray()) {
            UniValue arr(UniValue::VARR);
            for (const auto& m : result["models"].getValues()) {
                UniValue o = m;
                DecorateCatalogRow(cat, o);
                if (Arg(0).isObject()) {
                    if (Arg(0).exists("pinned") && o.exists("pinned") && o["pinned"].isBool() &&
                        o["pinned"].get_bool() != Arg(0)["pinned"].get_bool()) continue;
                    if (Arg(0).exists("seeded") && o.exists("seeded") && o["seeded"].isBool() &&
                        o["seeded"].get_bool() != Arg(0)["seeded"].get_bool()) continue;
                }
                arr.push_back(o);
            }
            result.pushKV("models", arr);
        }
        result.pushKV("next_actions", NextActionsArray({"getmodeltransfers", "searchmodels {\"scope\":\"LOCAL\"}"}));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "searchmodels") {
        EnsureSearchBound();
        EnsureEconomy(cat);
        std::unique_lock<std::mutex> lock(g_search_mu);
        IngestCatalogIntoSearch(cat);
        SearchQuery q;
        if (params.isArray() && params.size() > 0) {
            if (!ParseSearchQuery(Arg(0), q, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (Arg(0).isObject() && !Arg(0).exists("scope") && !Arg(0).exists("text")) {
                q.scope = SearchScope::LOCAL;
            }
        } else {
            q.scope = SearchScope::LOCAL;
        }
        std::vector<SearchIndex*> extras;
        auto job = g_search_rt.Start(q, extras, ConnNowMs());
        const std::vector<std::string> index_peers = g_search_idx.IndexPeers();
        const int index_configured = static_cast<int>(index_peers.size());
        std::vector<std::string> fanout;
        auto add_ep = [&](const std::string& ep) {
            if (ep.empty()) return;
            if (!g_swarm.bind.empty() && (ep == g_swarm.bind || ep == "[" + g_swarm.bind + "]")) return;
            if (std::find(fanout.begin(), fanout.end(), ep) != fanout.end()) return;
            if (static_cast<int>(fanout.size()) >= SEARCH_FANOUT_MAX) return;
            fanout.push_back(ep);
        };
        if (q.scope != SearchScope::LOCAL) {
            for (const auto& p : index_peers) add_ep(p);
            for (const auto& p : cat.Peers()) add_ep(p);
        }
        lock.unlock();
        int index_queried = 0;
        std::vector<UniValue> remote_records;
        std::vector<SearchHit> remote_hits;
        if (q.scope != SearchScope::LOCAL) {
            {
                std::lock_guard<std::mutex> plock(g_swarm.pex_mu);
                for (const auto& h : g_swarm.pex.Recent(ConnNowMs())) add_ep(h.endpoint);
            }
            Pq1Context pq;
            std::string tls_err;
            const fs::path pinfile = HelperDir(cat) / "tls" / "pins.json";
            const bool pq_ok = LoadPq1Identity(pq, HelperDir(cat), tls_err);
            UniValue qbody(UniValue::VOBJ);
            qbody.pushKV("text", q.text);
            qbody.pushKV("limit", q.limit);
            qbody.pushKV("ttl", SEARCH_TTL_DEFAULT);
            qbody.pushKV("query_id", job.query_id);
            qbody.pushKV("scope", "LOCAL");
            for (const auto& ep : fanout) {
                {
                    std::lock_guard<std::mutex> cl(g_search_mu);
                    if (g_search_rt.IsCancelled(job.query_id)) break;
                }
                if (!pq_ok) {
                    NoteSearchPeerTimeout(job.coverage);
                    continue;
                }
                UniValue reply;
                bool timed = false;
                std::string perr;
                const bool is_index = std::find(index_peers.begin(), index_peers.end(), ep) != index_peers.end();
                if (QuerySearchPeer(pq, pinfile, ep, qbody, reply, timed, perr)) {
                    job.coverage.responses_received += 1;
                    if (is_index) ++index_queried;
                    else job.coverage.connected_peers_queried += 1;
                    if (reply.exists("records") && reply["records"].isArray()) {
                        for (const auto& recj : reply["records"].getValues()) {
                            if (recj.isObject()) remote_records.push_back(recj);
                        }
                    }
                    if (reply.exists("results") && reply["results"].isArray()) {
                        for (const auto& card : reply["results"].getValues()) {
                            SearchHit hit;
                            std::string herr;
                            if (SearchHitFromCard(card, hit, herr)) {
                                hit.provenance = {ep};
                                remote_hits.push_back(std::move(hit));
                            }
                        }
                    }
                } else if (timed) {
                    NoteSearchPeerTimeout(job.coverage);
                }
            }
        }
        lock.lock();
        for (const auto& recj : remote_records) {
            ModelSearchRecord rec;
            std::string ierr;
            if (!SearchRecordFromJson(recj, rec, ierr)) continue;
            if (g_search_idx.Put(rec, ConnNowMs(), ierr)) AfterIndexPut(rec, ConnNowMs());
        }
        MergeRemoteSearchHits(job, std::move(remote_hits));
        job.hits = g_search_idx.Search(q, ConnNowMs());
        lock.unlock();
        int routing_known = 0;
        std::map<std::string, std::vector<ProviderObservation>> extra_obs;
        {
            std::lock_guard<std::mutex> slock(g_swarm.conn_mu);
            routing_known = static_cast<int>(g_swarm.routes.Size());
            for (const auto& h : job.hits) {
                const auto found = g_swarm.providers.Get(h.rec.model_id, ConnNowMs());
                for (const auto& pr : found) {
                    ProviderObservation o;
                    o.provider_id = pr.service_id.Hex();
                    o.endpoint = pr.endpoints.empty() ? "" : pr.endpoints.front();
                    o.complete = pr.complete;
                    o.direct = pr.reachability_kind != "relay";
                    o.relayed = pr.reachability_kind == "relay";
                    o.ranges = pr.ranges;
                    o.last_seen_ms = ConnNowMs();
                    extra_obs[h.rec.model_id.Hex()].push_back(o);
                }
            }
        }
        lock.lock();
        for (auto& kv : extra_obs) {
            auto& obs = g_search_obs[kv.first];
            for (const auto& o : kv.second) {
                bool dup = false;
                for (const auto& e : obs) {
                    if (e.provider_id == o.provider_id) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) obs.push_back(o);
            }
        }
        result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
        result.pushKV("query_id", job.query_id);
        result.pushKV("text", q.text);
        result.pushKV("scope", SearchScopeName(q.scope));
        UniValue cov(UniValue::VOBJ);
        cov.pushKV("local", true);
        cov.pushKV("connected_peers_queried", q.scope == SearchScope::LOCAL ? 0 : job.coverage.connected_peers_queried);
        cov.pushKV("index_peers_queried", q.scope == SearchScope::LOCAL ? 0 : index_queried);
        cov.pushKV("index_peers_configured", index_configured);
        cov.pushKV("routing_peers_queried", q.scope == SearchScope::LOCAL ? 0 : std::min(routing_known, SEARCH_FANOUT_MAX));
        cov.pushKV("responses_received", job.coverage.responses_received);
        cov.pushKV("timed_out", job.coverage.timed_out);
        cov.pushKV("complete", false);
        cov.pushKV("global_complete", false);
        result.pushKV("coverage", cov);
        UniValue arr(UniValue::VARR);
        std::vector<SearchHit> decorated;
        for (auto& h : job.hits) {
            auto it = g_search_obs.find(h.rec.model_id.Hex());
            if (it != g_search_obs.end()) h.health = ComputeSwarmHealth(0, 0, it->second);
            CatalogEntry e;
            if (cat.Find(h.rec.model_id, e)) {
                h.local.known = true;
                h.local.seeded = e.seeded;
                h.local.pinned = e.pinned;
                h.local.partial = e.incomplete;
                h.local.downloaded = e.bytes_verified;
            }
            decorated.push_back(h);
        }
        auto entries = EconomyHits(std::move(decorated), q, &cat);
        if (static_cast<int>(entries.size()) > q.limit && q.limit > 0) entries.resize(q.limit);
        for (const auto& e : entries) arr.push_back(EconomySearchCard(e));
        result.pushKV("results", arr);
        result.pushKV("results_returned", static_cast<int>(arr.size()));
        result.pushKV("total_candidates_seen", static_cast<int>(job.hits.size()));
        result.pushKV("applied_filters", AppliedFiltersJson(q.filters));
        result.pushKV("unsupported_filters", UniValue(UniValue::VARR));
        result.pushKV("remote_count", job.coverage.responses_received);
        result.pushKV("note", "current network view; not a complete global directory");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"getmodel FREE_ONLY", "getmodeltransfers"}));
        g_search_rt.Finish(job);
        return true;
    }
    if (method == "getmodelsearchrecord") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        std::lock_guard<std::mutex> lock(g_search_mu);
        const auto* r = g_search_idx.Get(id);
        if (!r) {
            err_code = "NOT_FOUND";
            err = "no search record";
            return false;
        }
        result = SearchRecordToJson(*r);
        result.pushKV("locally_cached", true);
        return true;
    }
    if (method == "publishmodelsearchrecord" || method == "updatemodelsearchrecord") {
        EnsureSearchBound();
        EnsureEconomy(cat);
        ModelSearchRecord rec;
        if (Arg(1).isObject()) {
            if (!SearchRecordFromJson(Arg(1), rec, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
        }
        rec.model_id = IdFromUser(Arg(0).isStr() ? Arg(0).get_str() : "", err);
        if (rec.model_id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        if (rec.canonical_name.empty()) rec.canonical_name = rec.display_name;
        CatalogEntry local;
        if (cat.Find(rec.model_id, local)) {
            if (rec.artifact_id.IsNull()) rec.artifact_id = local.artifact_id;
            if (rec.size_bytes == 0) {
                for (const auto& f : local.core.files) rec.size_bytes += f.size;
            }
            if (rec.file_count == 0) rec.file_count = static_cast<int>(local.core.files.size());
            if (rec.canonical_name.empty()) rec.canonical_name = local.label;
            if (rec.display_name.empty()) rec.display_name = local.label;
        }
        {
            std::lock_guard<std::mutex> lock(g_search_mu);
            const auto* prev = g_search_idx.Get(rec.model_id);
            if (prev) rec.metadata_sequence = prev->metadata_sequence + 1;
        }
        std::string serr;
        if (!SignSearchRecordWithDefaultIdentity(HelperDir(cat), rec, serr)) {
            err_code = "CRYPTO";
            err = serr.empty() ? "could not sign search record" : serr;
            return false;
        }
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (!g_search_idx.Put(rec, ConnNowMs(), err)) {
            err_code = "REJECTED";
            return false;
        }
        AfterIndexPut(rec, ConnNowMs());
        PersistEconomy(cat);
        const auto* stored = g_search_idx.Get(rec.model_id);
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", rec.model_id.Hex());
        result.pushKV("sequence", stored ? static_cast<int64_t>(stored->metadata_sequence) : 1);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("wallet_key", false);
        result.pushKV("signed_metadata", rec.signed_ok);
        return true;
    }
    if (method == "removemodelsearchrecord") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        std::lock_guard<std::mutex> lock(g_search_mu);
        const auto* existing = g_search_idx.Get(id);
        if (!existing) {
            err_code = "NOT_FOUND";
            return false;
        }
        if (!existing->signed_ok) {
            g_search_idx.Hide(id, true);
            result.pushKV("schema_version", 2);
            result.pushKV("tombstone", false);
            result.pushKV("hidden_local", true);
            result.pushKV("guaranteed_global_delete", false);
            return true;
        }
        ModelSearchRecord t = *existing;
        t.tombstone = true;
        t.metadata_sequence = existing->metadata_sequence + 1;
        std::vector<unsigned char> pk, sk;
        Digest48 sid;
        if (!LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, sid, err)) {
            err_code = "REJECTED";
            return false;
        }
        if (t.signer_id != sid) {
            err_code = "REJECTED";
            err = "wrong signer";
            return false;
        }
        if (!SignSearchRecord(t, Span<const unsigned char>{sk.data(), sk.size()}, err)) {
            err_code = "REJECTED";
            return false;
        }
        if (!g_search_idx.Put(t, ConnNowMs(), err)) {
            err_code = "REJECTED";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("tombstone", true);
        result.pushKV("guaranteed_global_delete", false);
        return true;
    }
    if (method == "listmodelsearchrecords" || method == "exportmodelindex") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        int limit = 100;
        int64_t after = 0;
        if (Arg(0).isObject()) {
            if (Arg(0).exists("limit")) limit = Arg(0)["limit"].getInt<int>();
            if (Arg(0).exists("updated_after")) after = Arg(0)["updated_after"].getInt<int64_t>();
        }
        if (limit > 100) limit = 100;
        result = g_search_idx.ExportSince(0, limit);
        result.pushKV("updated_after", after);
        result.pushKV("next_cursor", "");
        return true;
    }
    if (method == "importmodelindex") {
        EnsureSearchBound();
        if (!Arg(0).isObject() || !Arg(0).exists("records")) {
            err_code = "INVALID_PARAMETER";
            err = "records";
            return false;
        }
        int ok = 0, bad = 0;
        std::lock_guard<std::mutex> lock(g_search_mu);
        for (const auto& recj : Arg(0)["records"].getValues()) {
            ModelSearchRecord rec;
            std::string ierr;
            if (!SearchRecordFromJson(recj, rec, ierr) || !g_search_idx.Put(rec, ConnNowMs(), err)) ++bad;
            else {
                AfterIndexPut(rec, ConnNowMs());
                ++ok;
            }
        }
        result.pushKV("schema_version", 2);
        result.pushKV("imported", ok);
        result.pushKV("rejected", bad);
        result.pushKV("reverified", true);
        return true;
    }
    if (method == "getmodeldirectoryentry" || method == "getmodeldirectory") {
        EnsureSearchBound();
        EnsureEconomy(cat);
        std::lock_guard<std::mutex> lock(g_search_mu);
        IngestCatalogIntoSearch(cat);
        if (method == "getmodeldirectory") {
            SearchQuery q;
            if (Arg(0).isObject()) ParseSearchQuery(Arg(0), q, err);
            q.scope = SearchScope::ALL;
            const auto hits = g_search_idx.Search(q, ConnNowMs());
            UniValue arr(UniValue::VARR);
            auto entries = EconomyHits(hits, q, &cat);
            for (const auto& e : entries) arr.push_back(EconomySearchCard(e));
            result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
            result.pushKV("results", arr);
            result.pushKV("global_complete", false);
            return true;
        }
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        SearchHit h;
        const auto* r = g_search_idx.Get(id);
        if (r) h.rec = *r;
        else h.rec.model_id = id;
        auto it = g_search_obs.find(id.Hex());
        if (it != g_search_obs.end()) h.health = ComputeSwarmHealth(0, 0, it->second);
        CatalogEntry e;
        if (cat.Find(id, e)) {
            h.local.known = true;
            h.local.seeded = e.seeded;
            h.local.pinned = e.pinned;
            h.local.partial = e.incomplete;
        }
        result = EconomySearchCard(EconomyForHit(h, &cat));
        return true;
    }
    if (method == "getmodelproviders" || method == "getmodelavailability" || method == "getmodelpeercount") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        std::lock_guard<std::mutex> lock(g_search_mu);
        const auto obs = g_search_obs[id.Hex()];
        const SwarmHealth h = ComputeSwarmHealth(0, 0, obs);
        if (method == "getmodelproviders") {
            UniValue arr(UniValue::VARR);
            for (const auto& o : obs) {
                UniValue p(UniValue::VOBJ);
                p.pushKV("provider_id", o.provider_id);
                p.pushKV("reachability", o.direct ? "direct" : "relay");
                p.pushKV("complete", o.complete);
                p.pushKV("last_seen", o.last_seen_ms);
                p.pushKV("direct", o.direct);
                p.pushKV("relayed", o.relayed);
                arr.push_back(p);
            }
            result.pushKV("schema_version", 2);
            result.pushKV("providers", arr);
            return true;
        }
        if (method == "getmodelpeercount") {
            result = PeerCountJson(h);
            result.pushKV("schema_version", 2);
            return true;
        }
        result = AvailabilityJson(h);
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", id.Hex());
        return true;
    }
    if (method == "getnetworkmodelstats") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        UniValue listed;
        cat.List(listed);
        result.pushKV("schema_version", 2);
        result.pushKV("models_known", g_search_idx.Size());
        result.pushKV("models_local", listed.exists("local_count") ? listed["local_count"].getInt<int>() : 0);
        result.pushKV("search_records_known", static_cast<int>(g_search_idx.Size()));
        result.pushKV("searches_running", g_search_rt.Running());
        result.pushKV("searches_completed", g_search_rt.Completed());
        result.pushKV("index_records", static_cast<int>(g_search_idx.Size()));
        result.pushKV("coverage_disclaimer", "this node's observations only");
        result.pushKV("global_complete", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelaliases") {
        EnsureSearchBound();
        UniValue arr(UniValue::VARR);
        auto push_aliases = [&](const ModelSearchRecord& r) {
            for (const auto& a : r.aliases) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("alias", a);
                o.pushKV("model_id", r.model_id.Hex());
                o.pushKV("uri", r.btx_uri);
                o.pushKV("provenance", r.signed_ok ? "publisher_metadata" : "unsigned");
                arr.push_back(o);
            }
        };
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (Arg(0).isStr() && !Arg(0).get_str().empty()) {
            const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
            if (const auto* r = g_search_idx.Get(id)) push_aliases(*r);
        } else {
            for (const auto& r : g_search_idx.All()) push_aliases(r);
        }
        result.pushKV("schema_version", 2);
        result.pushKV("aliases", arr);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "searchpublishers" || method == "getpublisher" || method == "getmodelpublishers") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        UniValue arr(UniValue::VARR);
        SearchQuery q;
        if (method == "searchpublishers" && Arg(0).isObject()) ParseSearchQuery(Arg(0), q, err);
        else if (method == "searchpublishers" && Arg(0).isStr()) q.text = Arg(0).get_str();
        const auto hits = g_search_idx.Search(q, ConnNowMs());
        std::map<std::string, int> pubs;
        for (const auto& h : hits) {
            const std::string pid = h.rec.publisher_identity.Hex();
            if (pid.empty() || pid == std::string(96, '0')) continue;
            pubs[pid] += 1;
            if (method == "getpublisher" && Arg(0).isStr() && Arg(0).get_str() == pid) {
                result.pushKV("schema_version", 2);
                result.pushKV("id", pid);
                result.pushKV("display_name", h.rec.publisher_display_name);
                result.pushKV("model_count_observed", 1);
                return true;
            }
        }
        for (const auto& kv : pubs) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("id", kv.first);
            o.pushKV("model_count_observed", kv.second);
            arr.push_back(o);
        }
        result.pushKV("schema_version", 2);
        result.pushKV("publishers", arr);
        return true;
    }
    if (method == "searchcollections" || method == "getcollection" || method == "getmodelcollections") {
        EnsureSearchBound();
        UniValue arr(UniValue::VARR);
        std::string needle;
        if (Arg(0).isStr()) needle = ToLower(Arg(0).get_str());
        else if (Arg(0).isObject() && Arg(0).exists("text") && Arg(0)["text"].isStr()) {
            needle = ToLower(Arg(0)["text"].get_str());
        }
        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        for (const auto& h : RecordsFor(cat).All(now)) {
            if (h.kind != RECORD_COLLECTION) continue;
            UniValue body(UniValue::VOBJ);
            std::string derr;
            if (!h.payload.empty()) DecodeRecord(h.kind, Span<const unsigned char>{h.payload.data(), h.payload.size()}, body, derr);
            UniValue o(UniValue::VOBJ);
            o.pushKV("id", h.record_id.Hex());
            o.pushKV("kind", "COLLECTION");
            o.pushKV("signed_ok", h.signed_ok);
            o.pushKV("provider_id", h.provider_id);
            if (body.exists("title")) o.pushKV("title", body["title"]);
            if (body.exists("description")) o.pushKV("description", body["description"]);
            if (body.exists("entries")) o.pushKV("entries", body["entries"]);
            o.pushKV("on_chain_membership", false);
            o.pushKV("automatic_preservation", false);
            if (method == "getcollection") {
                const bool match = Arg(0).isStr() && (Arg(0).get_str() == h.record_id.Hex() ||
                                                       (!h.provider_id.empty() && Arg(0).get_str() == h.provider_id));
                if (match) {
                    result = o;
                    result.pushKV("schema_version", 2);
                    return true;
                }
                continue;
            }
            if (!needle.empty()) {
                const std::string hay = ToLower(o.write());
                if (hay.find(needle) == std::string::npos) continue;
            }
            arr.push_back(o);
        }
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "community.json", store);
        if (store.exists("subscriptions") && store["subscriptions"].isArray()) {
            for (const auto& x : store["subscriptions"].getValues()) {
                if (!x.isStr()) continue;
                UniValue o(UniValue::VOBJ);
                o.pushKV("id", x.get_str());
                o.pushKV("kind", "COLLECTION");
                o.pushKV("subscribed_locally", true);
                o.pushKV("on_chain_membership", false);
                if (!needle.empty() && ToLower(x.get_str()).find(needle) == std::string::npos) continue;
                bool dup = false;
                for (const auto& y : arr.getValues()) {
                    if (y.isObject() && y.exists("id") && y["id"].isStr() && y["id"].get_str() == x.get_str()) dup = true;
                }
                if (!dup) arr.push_back(o);
            }
        }
        if (method == "getcollection") {
            err_code = "NOT_FOUND";
            err = "collection not cached";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("collections", arr);
        result.pushKV("global_complete", false);
        return true;
    }
    if (method == "browsemodels" || method == "gettrendingmodels" || method == "getsimilarmodels" ||
        method == "getnewmodels" || method == "getrecentreleases") {
        EnsureSearchBound();
        EnsureEconomy(cat);
        auto remap_feed = [&](UniValue& feed) {
            UniValue arr(UniValue::VARR);
            if (feed.exists("items") && feed["items"].isArray()) {
                for (const auto& it : feed["items"].getValues()) {
                    if (it.isObject() && it.exists("entry") && it["entry"].isObject()) arr.push_back(it["entry"]);
                    else arr.push_back(it);
                }
            }
            feed.pushKV("results", arr);
        };
        if (method == "getrecentreleases") {
            SearchScope scope = SearchScope::NETWORK;
            if (Arg(0).isObject() && Arg(0).exists("scope")) {
                ParseSearchScope(Arg(0)["scope"].get_str(), scope);
            }
            if (scope != SearchScope::LOCAL) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("scope", "NETWORK");
                o.pushKV("mode", "NEW_RELEASE_CAMPAIGNS");
                if (Arg(0).isObject() && Arg(0).exists("limit")) o.pushKV("limit", Arg(0)["limit"]);
                if (Arg(0).isObject() && Arg(0).exists("filters")) o.pushKV("filters", Arg(0)["filters"]);
                UniValue inner(UniValue::VARR);
                inner.push_back(o);
                UniValue req(UniValue::VOBJ);
                req.pushKV("method", "getmodelfeed");
                req.pushKV("params", inner);
                if (!DispatchHelperRpc(cat, req, result, err_code, err, stop)) return false;
                remap_feed(result);
                result.pushKV("scope", "NETWORK");
                return true;
            }
        }
        if (method == "getnewmodels" && Arg(0).isObject() && Arg(0).exists("scope")) {
            SearchScope scope = SearchScope::LOCAL;
            ParseSearchScope(Arg(0)["scope"].get_str(), scope);
            if (scope != SearchScope::LOCAL) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("scope", SearchScopeName(scope));
                o.pushKV("mode", "NEWEST");
                if (Arg(0).exists("limit")) o.pushKV("limit", Arg(0)["limit"]);
                UniValue inner(UniValue::VARR);
                inner.push_back(o);
                UniValue req(UniValue::VOBJ);
                req.pushKV("method", "getmodelfeed");
                req.pushKV("params", inner);
                if (!DispatchHelperRpc(cat, req, result, err_code, err, stop)) return false;
                remap_feed(result);
                result.pushKV("scope", SearchScopeName(scope));
                return true;
            }
        }
        std::lock_guard<std::mutex> lock(g_search_mu);
        IngestCatalogIntoSearch(cat);
        SearchQuery q;
        if (Arg(0).isObject()) {
            if (!ParseSearchQuery(Arg(0), q, err)) {
                err_code = "INVALID_PARAMS";
                return false;
            }
        }
        if (method == "getnewmodels") {
            if (!Arg(0).isObject() || !Arg(0).exists("scope")) q.scope = SearchScope::LOCAL;
            q.sort = SearchSort::NEWEST;
        }
        if (method == "gettrendingmodels") q.sort = SearchSort::TRENDING;
        if (method == "browsemodels" && (!Arg(0).isObject() || !Arg(0).exists("sort"))) {
            q.sort = SearchSort::AVAILABILITY;
        }
        if (method == "getsimilarmodels" && Arg(0).isObject()) {
            if (Arg(0).exists("family")) q.filters.family = Arg(0)["family"].get_str();
        }
        const auto hits = g_search_idx.Search(q, ConnNowMs());
        UniValue arr(UniValue::VARR);
        if (method == "getrecentreleases") {
            for (const auto& c : g_campaigns.List()) {
                SearchHit h;
                if (const auto* r = g_search_idx.Get(c.model_id)) h.rec = *r;
                else {
                    h.rec.model_id = c.model_id;
                    h.rec.artifact_id = c.artifact_id;
                    h.rec.release_id = c.release_id.Hex();
                    h.rec.release_state = "FUNDING";
                    h.rec.release_target_atoms = c.target_atoms;
                    h.rec.key_hash = c.key_hash;
                    h.rec.refund_height = c.refund_height;
                }
                if (h.rec.release_id.empty()) h.rec.release_id = c.release_id.Hex();
                auto e = ComposeEconomyEntry(h, &c, ObservationFromHit(h, &c, &cat));
                if (Arg(0).isObject() && Arg(0).exists("scope") && ToUpper(Arg(0)["scope"].get_str()) == "LOCAL") {
                    // keep
                }
                arr.push_back(EconomySearchCard(e));
            }
        } else {
            auto entries = EconomyHits(hits, q, &cat);
            for (const auto& e : entries) arr.push_back(EconomySearchCard(e));
        }
        result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
        result.pushKV("results", arr);
        result.pushKV("metric", method == "gettrendingmodels" ? "observed_provider_growth_local" : SearchSortName(q.sort));
        result.pushKV("global_complete", false);
        if (method == "getnewmodels" && (!Arg(0).isObject() || !Arg(0).exists("scope"))) {
            result.pushKV("scope", "LOCAL");
            result.pushKV("note", "bare getnewmodels remains local-index; use getmodelfeed scope=NETWORK");
        }
        return true;
    }
    if (method == "getsearchstatus") {
        EnsureSearchBound();
        SearchJob job;
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (!Arg(0).isStr() || !g_search_rt.Status(Arg(0).get_str(), job)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("query_id", Arg(0).isStr() ? Arg(0).get_str() : "");
        result.pushKV("state", job.state == SearchJobState::COMPLETE ? "COMPLETE" :
                               (job.state == SearchJobState::CANCELLED ? "CANCELLED" :
                                (job.state == SearchJobState::TIMED_OUT ? "TIMED_OUT" : "RUNNING")));
        UniValue arr(UniValue::VARR);
        for (const auto& h : job.hits) arr.push_back(SearchResultCard(h));
        result.pushKV("results", arr);
        result.pushKV("results_returned", static_cast<int>(job.hits.size()));
        result.pushKV("complete", false);
        result.pushKV("global_complete", false);
        return true;
    }
    if (method == "cancelmodelsearch") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        result.pushKV("ok", g_search_rt.Cancel(Arg(0).get_str()));
        return true;
    }
    if (method == "getsearchpeers") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        UniValue arr(UniValue::VARR);
        for (const auto& p : g_search_idx.IndexPeers()) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("endpoint", p);
            o.pushKV("capability", "NODE_MODEL_INDEX");
            o.pushKV("monetary_service_bit", false);
            arr.push_back(o);
        }
        result.pushKV("schema_version", 2);
        result.pushKV("peers", arr);
        return true;
    }
    if (method == "addmodelindex" || method == "removemodelindex") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        if (method == "addmodelindex") g_search_idx.AddIndexPeer(Arg(0).get_str());
        else g_search_idx.RemoveIndexPeer(Arg(0).get_str());
        result.pushKV("schema_version", 2);
        result.pushKV("index_peers", static_cast<int>(g_search_idx.IndexPeers().size()));
        result.pushKV("addrman", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "hidesearchmodel" || method == "unhidesearchmodel") {
        EnsureSearchBound();
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        std::lock_guard<std::mutex> lock(g_search_mu);
        g_search_idx.Hide(id, method == "hidesearchmodel");
        result.pushKV("hidden", method == "hidesearchmodel");
        return true;
    }
    if (method == "mutesearchpublisher" || method == "unmutesearchpublisher") {
        EnsureSearchBound();
        std::lock_guard<std::mutex> lock(g_search_mu);
        g_search_idx.MutePublisher(Arg(0).get_str(), method == "mutesearchpublisher");
        result.pushKV("muted", method == "mutesearchpublisher");
        return true;
    }
    if (method == "getmodelmanifest") {
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        if (!err.empty() && id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        err.clear();
        if (!cat.GetManifest(id, result, err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        return true;
    }
    if (method == "seedmodel" || method == "unseedmodel") {
        std::string derr;
        const Digest48 id = ResolveUserId(Arg(0).get_str(), derr);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            err = derr;
            return false;
        }
        if (!cat.Seed(id, method == "seedmodel", err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("seeded", method == "seedmodel");
        AttachLocalShare(cat, id, result);
        result.pushKV("next_actions", NextActionsArray({"getmodeltransfers", "unhostmodel"}));
        return true;
    }
    if (method == "pinmodel" || method == "unpinmodel") {
        std::string derr;
        const Digest48 id = ResolveUserId(Arg(0).get_str(), derr);
        if (id.IsNull()) {
            err_code = "INVALID_PARAMETER";
            err = derr;
            return false;
        }
        if (!cat.PinModel(id, method == "pinmodel", err)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("pinned", method == "pinmodel");
        AttachLocalShare(cat, id, result);
        result.pushKV("next_actions", NextActionsArray({"getmodeltransfers", "unhostmodel"}));
        return true;
    }
    if (method == "stop") {
        if (stop) stop->store(true);
        result.pushKV("stopping", true);
        return true;
    }
    if (method == "qualifymodel") {
        QualReport report;
        const auto qr = QualifyFile(Arg(0).get_str(), report);
        result.pushKV("schema_version", 2);
        result.pushKV("result", QualResultName(qr));
        result.pushKV("admission", AdmissionLevelName(report.level));
        result.pushKV("detail", report.detail);
        result.pushKV("tensor_count", report.tensor_count);
        result.pushKV("note", "not a claim of usefulness, safety, or alignment");
        return true;
    }
    if (method == "getmodel") {
        Resource r;
        std::string hexerr;
        const std::string user = Arg(0).get_str();
        const std::string token = FirstBtxToken(user);
        if (!DecodeResource(token.empty() ? user : token, r, err)) {
            const Digest48 id = ResolveUserId(user, hexerr);
            if (id.IsNull()) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            CatalogEntry found;
            if (cat.Find(id, found)) {
                r.kind = ResourceKind::MODEL;
                r.digest = found.model_id;
            } else {
                r.kind = ResourceKind::MODEL;
                r.digest = id;
            }
            err.clear();
        }
        if (r.kind != ResourceKind::MODEL) {
            err_code = "INVALID_PARAMETER";
            err = "resource is not a MODEL";
            return false;
        }
        RetrievalMode mode = RetrievalMode::FREE_ONLY;
        int64_t budget_atoms = 0;
        bool approved = false;
        UniValue requester(UniValue::VOBJ);
        if (params.isArray() && params.size() > 1) {
            if (params[1].isStr()) {
                if (!RetrievalModeFromName(params[1].get_str(), mode)) {
                    err_code = "INVALID_PARAMETER";
                    err = "unknown retrieval mode";
                    return false;
                }
            } else if (params[1].isObject()) {
                requester = params[1];
                std::string pol;
                if (requester.exists("retrieval_policy") && requester["retrieval_policy"].isStr()) {
                    pol = requester["retrieval_policy"].get_str();
                } else if (requester.exists("mode") && requester["mode"].isStr()) {
                    const std::string m = requester["mode"].get_str();
                    if (m != "plan" && m != "approve") pol = m;
                }
                if (!pol.empty() && !RetrievalModeFromName(pol, mode)) {
                    err_code = "INVALID_PARAMETER";
                    err = "unknown retrieval mode";
                    return false;
                }
                if (requester.exists("max_atoms")) budget_atoms = requester["max_atoms"].getInt<int64_t>();
                approved = requester.exists("approved") && requester["approved"].get_bool();
                if (requester.exists("mode") && requester["mode"].isStr() && requester["mode"].get_str() == "approve") {
                    approved = true;
                }
            }
        }
        result.pushKV("schema_version", 2);
        result.pushKV("uri", r.Uri());
        result.pushKV("automatic_spend_atoms", 0);

        CatalogEntry local_probe;
        const bool have_local = cat.Find(r.digest, local_probe);
        std::vector<PieceNeed> missing;
        if (have_local && !local_probe.core.files.empty()) {
            const auto& f = local_probe.core.files[0];
            const uint32_t n = f.size == 0 ? 1u : static_cast<uint32_t>((f.size + PIECE_SIZE - 1) / PIECE_SIZE);
            for (uint32_t i = 0; i < n; ++i) {
                PieceNeed p;
                p.file_index = 0;
                p.piece_index = i;
                missing.push_back(p);
            }
        } else {
            PieceNeed p;
            missing.push_back(p);
        }
        std::vector<SourceOffer> sources;
        if (have_local) {
            SourceOffer s;
            s.peer = "local";
            s.available = true;
            sources.push_back(s);
        }
        if (!cat.Peers().empty()) {
            SourceOffer s;
            s.peer = "peer";
            s.available = true;
            sources.push_back(s);
        }
        std::vector<Quote> quotes;
        std::vector<PaymentJournal> journal;
        const fs::path dir = cat.Store().Root().parent_path();
        LoadPaymentState(dir, quotes, journal, err);
        for (auto& p : missing) {
            if (DuplicateReservedRange(journal, p.file_index, p.piece_index, 1)) p.reserved_paid = true;
        }
        int64_t outstanding = 0;
        for (const auto& q : quotes) {
            if (!(q.model_id == r.digest) || q.price_atoms <= 0) continue;
            bool delivered = false;
            for (const auto& j : journal) {
                if (j.delivered && j.quote_id == q.offer_id.Hex()) delivered = true;
            }
            if (delivered) continue;
            outstanding += q.price_atoms;
            if (q.fee_cap_atoms > 0) outstanding += q.fee_cap_atoms;
        }
        if (mode != RetrievalMode::FREE_ONLY) {
            Quote q;
            int64_t price = 0;
            if (mode == RetrievalMode::EXPLICIT_PAID) {
                if (requester.exists("price_atoms") && requester["price_atoms"].isNum()) {
                    price = requester["price_atoms"].getInt<int64_t>();
                } else if (budget_atoms > 0) {
                    price = budget_atoms;
                } else {
                    price = 1; // explicit paid is never a free quote; automatic spend stays 0
                }
            }
            MakePrepaidQuote(q, r.digest, have_local ? local_probe.artifact_id : Digest48{}, 0, 0, price, err);
            quotes.push_back(q);
            SavePaymentState(dir, quotes, journal, err);
            result.pushKV("quote", QuoteToJson(q));
            if (mode == RetrievalMode::EXPLICIT_PAID) {
                result.pushKV("funding_rpc", "preparemodelfunding");
                result.pushKV("wallet", false);
                result.pushKV("note", "EXPLICIT_PAID quotes a price; automatic spend remains 0. preparemodelfunding / signmodelfunding / submitmodelfunding freeze htlc_sha256.");
            }
        }
        bool paid_binding = false;
        for (const auto& q : quotes) {
            if (!(q.model_id == r.digest)) continue;
            if (QuoteMayBeTakenAsFree(q, requester)) continue;
            paid_binding = true;
            SourceOffer s;
            s.peer = "quote";
            s.paid = true;
            s.price_atoms = q.price_atoms;
            s.fee_atoms = q.fee_cap_atoms;
            s.file_index = q.file_index;
            s.first_piece = q.first_piece;
            s.piece_count = q.piece_count;
            s.available = true;
            sources.push_back(s);
        }
        if (paid_binding && requester.exists("price_atoms") && requester["price_atoms"].getInt<int64_t>() == 0) {
            result.pushKV("plan", "APPROVAL_REQUIRED");
            result.pushKV("bypass_rejected", true);
            result.pushKV("note", "price=0 in requester JSON cannot bypass an accepted paid quote");
            return true;
        }
        const HybridPlan hp = PlanRetrieval(missing, sources, mode, budget_atoms, approved, outstanding);
        result.pushKV("paid_atoms", mode == RetrievalMode::FREE_ONLY ? 0 : hp.paid_atoms);
        result.pushKV("free_piece_count", static_cast<int>(hp.free_pieces.size()));
        result.pushKV("paid_piece_count", static_cast<int>(hp.paid_pieces.size()));
        result.pushKV("eta_s", EtaWithFees(/*queue_s=*/0,
                                            hp.paid_atoms > 0 ? 600 : 0,
                                            hp.paid_atoms,
                                            hp.paid_atoms > 0 ? 30 : 0));
        if (hp.unknown_eta) result.pushKV("eta", "unknown");
        if (mode != RetrievalMode::FREE_ONLY && !hp.paid_pieces.empty()) {
            result.pushKV("plan", (approved || mode == RetrievalMode::FREE_FIRST_BUDGET) ? "PAID" : "APPROVAL_REQUIRED");
            result.pushKV("note", "automatic spend remains 0; FREE_ONLY never becomes paid because a timer expired");
            return true;
        }
        CatalogEntry local;
        if (cat.Find(r.digest, local)) {
            if (local.incomplete) {
                std::string herr;
                (void)TryHydrateFromCloud(cat, local, result, herr);
                cat.Find(r.digest, local);
            }
            cat.ApplyDemandSeed(local.model_id, err);
            cat.Find(r.digest, local);
            result.pushKV("plan", "FREE");
            result.pushKV("status", "local");
            result.pushKV("model_id", local.model_id.Hex());
            result.pushKV("artifact_id", local.artifact_id.Hex());
            result.pushKV("seeded", local.seeded);
            return true;
        }
        {
            Digest48 artifact;
            {
                std::lock_guard<std::mutex> slock(g_search_mu);
                if (const auto* rec = g_search_idx.Get(r.digest)) artifact = rec->artifact_id;
            }
            std::lock_guard<std::mutex> lock(g_cloud_mu);
            if (g_cloud && g_cloud->IsReady() && !g_cloud_cfg.s3.use_fake) {
                result.pushKV("cloud_origin", true);
                result.pushKV("cloud_layout", CloudObjectLayoutName(g_cloud->Layout()));
                result.pushKV("cloud_amplification", CloudAmplificationJson(1, 0, g_cloud->Layout() == CloudObjectLayout::SOURCE_FILES));
                if (!artifact.IsNull()) {
                    uint64_t sz = 0;
                    std::string herr;
                    if (g_cloud->HeadObject(g_cloud->SourceFileKey(artifact, 0), sz, herr)) {
                        result.pushKV("origin_file_complete", true);
                        result.pushKV("origin_bytes", sz);
                        if (requester.exists("direct_seed") && requester["direct_seed"].isBool() && requester["direct_seed"].get_bool()) {
                            std::string url;
                            DirectSeedPolicy pol;
                            pol.enabled = true;
                            pol.limits = DirectSeedLimits{};
                            ParsedS3Endpoint origin;
                            std::string perr;
                            if (ParseS3Endpoint(g_cloud_cfg.s3.endpoint, origin, perr)) {
                                pol.allowed_https_host = origin.host;
                            }
                            std::string peer_key = "rpc-local";
                            if (requester.exists("peer") && requester["peer"].isStr() && !requester["peer"].get_str().empty()) {
                                peer_key = requester["peer"].get_str();
                            } else if (requester.exists("from") && requester["from"].isStr() && !requester["from"].get_str().empty()) {
                                peer_key = requester["from"].get_str();
                            }
                            const std::string ng = DirectSeedNetgroup(peer_key);
                            std::string admit_err;
                            if (sz > pol.limits.max_object_bytes) {
                                herr = "direct seed object exceeds limit";
                            } else if (!DirectSeedAllowIssue(g_direct_seed_admit, pol.limits, peer_key, ng, ConnNowMs(),
                                                             admit_err)) {
                                herr = admit_err;
                                result.pushKV("direct_seed_limited", true);
                                result.pushKV("direct_seed_error", admit_err);
                            } else if (!g_cloud->PresignSourceFileGet(artifact, 0, 60, url, herr)) {
                                // presign failed
                            } else if (!DirectSeedUrlAllowed(url, pol, herr)) {
                                // refuse to emit an unallowlisted URL
                            } else {
                                DirectSeedOffer offer;
                                offer.object_key = g_cloud->SourceFileKey(artifact, 0);
                                offer.size = sz;
                                offer.full_file = true;
                                offer.presigned_get = url;
                                offer.expires_at_ms = ConnNowMs() + pol.limits.ttl_ms;
                                result.pushKV("direct_seed", DirectSeedOfferPublicJson(offer));
                                if (requester.exists("direct_seed_fetch") && requester["direct_seed_fetch"].isBool() &&
                                    requester["direct_seed_fetch"].get_bool()) {
                                    std::vector<unsigned char> body;
                                    if (g_cloud->FetchPresignedGet(url, body, herr)) {
                                        result.pushKV("direct_seed_fetched", true);
                                        result.pushKV("direct_seed_bytes", static_cast<int64_t>(body.size()));
                                    } else {
                                        result.pushKV("direct_seed_fetched", false);
                                        result.pushKV("direct_seed_fetch_error", herr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        auto peers = cat.Peers();
        ResolveQueryPlan rplan;
        PlanRouterQueries(peers, peers.size() >= 2 ? std::vector<std::string>{peers.back()} : std::vector<std::string>{}, rplan);
        if (rplan.contacts.empty()) {
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "not_local");
            result.pushKV("peers", 0);
            result.pushKV("unknown_eta", true);
            return true;
        }
        if (stop) {
            const std::string job_id = EnqueueRetrieve(cat, r.digest, stop);
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "running");
            result.pushKV("async", true);
            result.pushKV("job_id", job_id);
            result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
            result.pushKV("max_routers", MAX_ROUTER_CONTACTS);
            result.pushKV("note", "poll getmodeljob; helper unix RPC does not wait for WAN retrieve");
            return true;
        }
        Pq1Context pq;
        std::string tls_err;
        if (!LoadPq1Identity(pq, cat.Store().Root().parent_path(), tls_err)) {
            result.pushKV("retrieve_error", tls_err);
            result.pushKV("plan", "WAIT_FREE");
            result.pushKV("status", "not_local");
            result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
            return true;
        }
        for (const auto& ep : rplan.contacts) {
            std::string host;
            uint16_t port = 0;
            if (pq.Ready() && SplitHostPort(ep, host, port) &&
                RetrieveFreeFromPeer(cat, pq, host, port, r.digest, err, stop,
                                     cat.Store().Root().parent_path() / "tls" / "pins.json")) {
                cat.ApplyDemandSeed(r.digest, err);
                CatalogEntry got;
                result.pushKV("plan", "FREE");
                result.pushKV("status", "retrieved");
                result.pushKV("seeded", cat.Find(r.digest, got) && got.seeded);
                result.pushKV("propagation", "demand");
                return true;
            }
        }
        result.pushKV("retrieve_error", err.empty() ? tls_err : err);
        result.pushKV("plan", "WAIT_FREE");
        result.pushKV("status", "not_local");
        result.pushKV("peers", static_cast<int>(rplan.contacts.size()));
        return true;
    }
    if (method == "addmodelnode") {
        const std::string peer = Arg(0).get_str();
        cat.AddPeer(peer);
        result.setObject();
        result.pushKV("schema_version", 2);
        result.pushKV("ok", true);
        result.pushKV("added", peer);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "model-plane contact; not AddrMan; not monetary addnode");
        return true;
    }
    if (method == "getmodelpeers") {
        result.pushKV("schema_version", 2);
        UniValue arr(UniValue::VARR);
        for (const auto& p : cat.Peers()) arr.push_back(p);
        result.pushKV("peers", arr);
        result.pushKV("note", "model-plane contacts; not AddrMan; not monetary addnode");
        return true;
    }
    if (method == "getmodeljob" || method == "cancelmodeljob") {
        result.pushKV("schema_version", 2);
        std::string want;
        if (params.isArray() && params.size() > 0 && Arg(0).isStr()) want = Arg(0).get_str();
        UniValue arr(UniValue::VARR);
        std::vector<std::shared_ptr<RetrieveJob>> listed;
        {
            std::lock_guard<std::mutex> lock(g_retrieve_mu);
            if (method == "cancelmodeljob" && !want.empty()) {
                const auto it = g_retrieve_jobs.find(want);
                if (it != g_retrieve_jobs.end()) {
                    it->second->cancel.store(true);
                    {
                        std::lock_guard<std::mutex> jlock(it->second->mu);
                        if (it->second->status == "running" || it->second->status == "queued") {
                            it->second->status = "cancelled";
                        }
                    }
                    PersistRetrieveJobsLocked();
                    result.pushKV("cancelled", true);
                    result.pushKV("job_id", want);
                } else {
                    result.pushKV("cancelled", false);
                    result.pushKV("job_id", want);
                }
            }
            PruneRetrieveJobsLocked();
            for (auto& kv : g_retrieve_jobs) {
                if (!want.empty() && kv.first != want) continue;
                if (!kv.second->modeldir.empty() && kv.second->modeldir != HelperDir(cat)) continue;
                listed.push_back(kv.second);
            }
        }
        std::sort(listed.begin(), listed.end(), [](const std::shared_ptr<RetrieveJob>& a, const std::shared_ptr<RetrieveJob>& b) {
            return RetrieveJobIsNewer(a->created_ms, a->id, b->created_ms, b->id);
        });
        for (const auto& j : listed) arr.push_back(RetrieveJobJson(*j));
        result.pushKV("jobs", arr);
        result.pushKV("job_count", static_cast<int>(arr.size()));
        result.pushKV("used_bytes", cat.UsedBytes());
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("next_actions", NextActionsArray({"getmodeltransfers", "getmodel FREE_ONLY"}));
        return true;
    }
    if (method == "createmodelrelease") {
        EnsureEconomy(cat);
        std::string uri;
        std::string secret_hex;
        int64_t refund_height = 0;
        UniValue options(UniValue::VOBJ);
        if (Arg(0).isObject()) {
            if (Arg(0).exists("uri")) uri = Arg(0)["uri"].get_str();
            if (Arg(0).exists("secret32_hex")) secret_hex = Arg(0)["secret32_hex"].get_str();
            else if (Arg(0).exists("secret")) secret_hex = Arg(0)["secret"].get_str();
            if (Arg(0).exists("refund_height")) refund_height = Arg(0)["refund_height"].getInt<int64_t>();
            options = Arg(0);
        } else {
            if (!Arg(0).isStr()) {
                err_code = "INVALID_PARAMETER";
                err = "model uri required";
                return false;
            }
            uri = Arg(0).get_str();
            if (params.isArray() && params.size() < 3) {
                err_code = "INVALID_PARAMETER";
                err = "createmodelrelease(uri, secret32_hex, refund_height)";
                return false;
            }
            secret_hex = Arg(1).get_str();
            refund_height = Arg(2).getInt<int64_t>();
            if (params.isArray() && params.size() > 4 && Arg(4).isObject()) options = Arg(4);
            else if (params.isArray() && params.size() > 3 && Arg(3).isObject()) options = Arg(3);
        }
        Resource r;
        if (!DecodeResource(uri, r, err) || r.kind != ResourceKind::MODEL) {
            err_code = "INVALID_PARAMETER";
            err = "model uri required";
            return false;
        }
        if (!RejectHash160Campaign(options, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        const auto secret = TryParseHex<unsigned char>(secret_hex);
        if (!secret || secret->size() != 32) {
            err_code = "INVALID_PARAMETER";
            err = "secret must be 32 bytes hex (stored as SHA-256 only)";
            return false;
        }
        ReleaseCampaign c;
        unsigned char nonce[32];
        GetStrongRandBytes(Span<unsigned char>{nonce, 32});
        c.release_id = DomainHash("BTX/ReleaseCampaign/v1", Span<const unsigned char>{nonce, 32});
        c.model_id = r.digest;
        CatalogEntry local;
        if (cat.Find(r.digest, local)) c.artifact_id = local.artifact_id;
        c.ciphertext_artifact_id = c.artifact_id;
        if (cat.Find(r.digest, local) && !local.core.files.empty()) {
            std::vector<unsigned char> plain;
            std::string rerr;
            if (ReadCatalogBytes(cat, local, plain, rerr) && !LooksLikeBtxEnc2(Span<const unsigned char>{plain.data(), plain.size()})) {
                std::vector<unsigned char> wrapped;
                if (WrapBtxEnc2(Span<const unsigned char>{secret->data(), secret->size()},
                                 Span<const unsigned char>{plain.data(), plain.size()}, wrapped, rerr)) {
                    const fs::path tmp = HelperDir(cat) / "tmp-cipher.btxenc";
                    {
                        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                        out.write(reinterpret_cast<const char*>(wrapped.data()), static_cast<std::streamsize>(wrapped.size()));
                    }
                    CatalogEntry enc;
                    if (cat.ImportPath(fs::PathToString(tmp), /*pin=*/false, enc, rerr)) {
                        c.ciphertext_artifact_id = enc.artifact_id.IsNull() ? enc.model_id : enc.artifact_id;
                    }
                    fs::remove(tmp);
                }
            } else if (LooksLikeBtxEnc2(Span<const unsigned char>{plain.data(), plain.size()})) {
                c.ciphertext_artifact_id = local.artifact_id;
            }
        }
        c.key_hash = ReleaseHash(*secret);
        c.hashlock_algorithm = "SHA256";
        c.assurance = "KEY_RELEASE_ONLY";
        c.refund_height = static_cast<uint32_t>(refund_height);
        if (params.isArray() && params.size() > 3 && Arg(3).isNum()) c.target_atoms = Arg(3).getInt<int64_t>();
        else if (options.exists("target_atoms")) c.target_atoms = options["target_atoms"].getInt<int64_t>();
        c.campaign_created_at = ConnNowMs();
        if (!ValidRefundWindow(1, 1, 1, c.refund_height) && c.refund_height < 10) {
            err_code = "INVALID_PARAMETER";
            err = "refund_height too low";
            return false;
        }
        {
            UniValue store;
            ReadJsonFile(HelperDir(cat) / "identities.json", store);
            if (store.exists("identities") && store["identities"].isArray() && !store["identities"].getValues().empty()) {
                const UniValue& idj = store["identities"].getValues().front();
                if (idj.exists("pubkey_hex") && idj.exists("id")) {
                    c.pubkey = ParseHex(idj["pubkey_hex"].get_str());
                    const std::string hexid = idj["id"].get_str();
                    const fs::path skpath = HelperDir(cat) / "tls" /
                                            fs::PathFromString("identity-" + hexid.substr(0, 16) + ".sk");
                    std::ifstream skf(fs::PathToString(skpath), std::ios::binary);
                    std::vector<unsigned char> sk((std::istreambuf_iterator<char>(skf)), std::istreambuf_iterator<char>());
                    std::string serr;
                    if (!sk.empty() && SignReleaseCampaign(c, Span<const unsigned char>{sk.data(), sk.size()}, serr)) {
                        c.signed_ok = true;
                    }
                }
            }
        }
        std::string cerr;
        g_campaigns.Put(c, cerr);
        SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
        g_feed.NoteCampaign(c, ConnNowMs());
        LiveObserveCampaign(c, FeedEventType::RELEASE_CAMPAIGN_CREATED);
        bool published_search = false;
        std::string search_record_id;
        const bool want_pub = !options.exists("publish_search_record") || options["publish_search_record"].get_bool();
        if (want_pub && (options.exists("searchable_metadata") || options.exists("display_name") || options.exists("short_description"))) {
            ModelSearchRecord rec;
            if (options.exists("searchable_metadata") && options["searchable_metadata"].isObject()) {
                SearchRecordFromJson(options["searchable_metadata"], rec, err);
            }
            rec.model_id = c.model_id;
            rec.artifact_id = c.artifact_id;
            rec.release_id = c.release_id.Hex();
            rec.release_state = "FUNDING";
            rec.release_target_atoms = c.target_atoms;
            rec.key_hash = c.key_hash;
            rec.refund_height = c.refund_height;
            rec.campaign_created_at = c.campaign_created_at;
            rec.ciphertext_artifact_id = c.ciphertext_artifact_id;
            rec.assurance = "KEY_RELEASE_ONLY";
            if (options.exists("display_name")) rec.display_name = options["display_name"].get_str();
            if (options.exists("short_description")) rec.short_description = options["short_description"].get_str();
            if (rec.canonical_name.empty()) rec.canonical_name = rec.display_name;
            rec.published_at = c.campaign_created_at;
            std::lock_guard<std::mutex> lock(g_search_mu);
            if (g_search_idx.Put(rec, ConnNowMs(), err)) {
                AfterIndexPut(rec, ConnNowMs());
                published_search = true;
                search_record_id = rec.model_id.Hex();
            }
        }
        PersistEconomy(cat);
        result = CampaignToJson(c);
        result.pushKV("secret_retained", false);
        result.pushKV("search_record_id", search_record_id);
        result.pushKV("publish_state", published_search ? "published" : "local_campaign_only");
        result.pushKV("lifecycle_state", "FUNDING");
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelrelease") {
        EnsureEconomy(cat);
        result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
        UniValue arr(UniValue::VARR);
        if (params.isArray() && params.size() > 0 && Arg(0).isStr() && !Arg(0).get_str().empty()) {
            Digest48 id;
            SearchHit h;
            const Digest48 user = ResolveUserId(Arg(0).get_str(), err);
            const ReleaseCampaign* c = g_campaigns.GetByRelease(user);
            if (!c) c = g_campaigns.GetByModel(user);
            if (!c && Digest48::FromHex(Arg(0).get_str(), id, err)) c = g_campaigns.GetByRelease(id);
            if (!c) {
                err_code = "NOT_FOUND";
                err = "unknown release";
                return false;
            }
            if (const auto* rec = g_search_idx.Get(c->model_id)) h.rec = *rec;
            else h.rec.model_id = c->model_id;
            auto e = ComposeEconomyEntry(h, c, ObservationFromHit(h, c, &cat));
            UniValue one = CampaignToJson(*c);
            one.pushKV("lifecycle_state", ModelLifecycleName(e.lifecycle));
            one.pushKV("remaining_atoms", e.remaining_atoms);
            if (e.funded_percent_known) one.pushKV("funded_percent", MilliToDisplayPercent(e.funded_percent_milli));
            if (e.pledged_percent_known) one.pushKV("pledged_percent", MilliToDisplayPercent(e.pledged_percent_milli));
            one.pushKV("actions", EconomyActionsJson(e.actions));
            one.pushKV("ciphertext_available", e.ciphertext_available);
            arr.push_back(one);
        } else {
            for (const auto& c : g_campaigns.List()) arr.push_back(CampaignToJson(c));
        }
        result.pushKV("campaigns", arr);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "pledgemodelrelease") {
        EnsureEconomy(cat);
        Digest48 id;
        if (!Digest48::FromHex(Arg(0).get_str(), id, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        const int64_t atoms = Arg(1).getInt<int64_t>();
        auto* c = const_cast<ReleaseCampaign*>(g_campaigns.GetByRelease(id));
        if (!c) {
            err_code = "NOT_FOUND";
            err = "unknown release";
            return false;
        }
        c->pledged_atoms += atoms;
        result = CampaignToJson(*c);
        g_feed.NoteFundingChanged(*c, ConnNowMs());
        LiveObserveCampaign(*c, FeedEventType::RELEASE_FUNDING_CHANGED);
        SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
        result.pushKV("note", "pledge is local accounting; send BTX with 0.34.6 HTLC separately. pledged is not funded.");
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "claimmodelrelease" || method == "refundmodelrelease") {
        EnsureEconomy(cat);
        result.pushKV("schema_version", 2);
        result.pushKV("use", method == "claimmodelrelease" ? "buildhtlcclaim" : "buildhtlcrefund");
        result.pushKV("template", "htlc_sha256");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "Monetary claim/refund is buildmodelhtlcclaim / buildmodelhtlcrefund. This RPC updates model-plane unlock state only.");
        Digest48 id;
        if (params.isArray() && params.size() > 0 && Arg(0).isStr()) {
            id = ResolveUserId(Arg(0).get_str(), err);
            if (id.IsNull() && !Digest48::FromHex(Arg(0).get_str(), id, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
        }
        ReleaseCampaign* c = const_cast<ReleaseCampaign*>(g_campaigns.GetByRelease(id));
        if (!c) c = const_cast<ReleaseCampaign*>(g_campaigns.GetByModel(id));
        if (method == "claimmodelrelease" && params.isArray() && params.size() > 1 && Arg(1).isStr()) {
            const auto secret = TryParseHex<unsigned char>(Arg(1).get_str());
            if (!secret || secret->size() != 32) {
                err_code = "INVALID_PARAMETER";
                err = "secret must be 32 bytes hex";
                return false;
            }
            if (!c) {
                err_code = "NOT_FOUND";
                err = "unknown release";
                return false;
            }
            if (ReleaseHash(Span<const unsigned char>{secret->data(), secret->size()}) != c->key_hash) {
                err_code = "INVALID_PARAMETER";
                err = "secret does not match SHA-256 key_hash";
                return false;
            }
            c->secret_disclosed = true;
            ModelSearchRecord rec;
            if (const auto* sr = g_search_idx.Get(c->model_id)) rec = *sr;
            rec.model_id = c->model_id;
            rec.release_id = c->release_id.Hex();
            rec.release_state = "SECRET_DISCLOSED";
            g_feed.NoteUnlock(c->model_id, c->release_id.Hex(), rec, ConnNowMs());
            {
                FeedEvent fe;
                fe.event_type = FeedEventType::MODEL_UNLOCKED;
                fe.model_id = c->model_id;
                fe.release_id = c->release_id.Hex();
                fe.rec = rec;
                LiveObserveFeed(fe);
            }
            CatalogEntry local;
            Digest48 cid = c->ciphertext_artifact_id.IsNull() ? c->artifact_id : c->ciphertext_artifact_id;
            bool unlocked = false;
            if (!cid.IsNull() && (cat.Find(cid, local) || cat.Find(c->model_id, local))) {
                std::vector<unsigned char> wrapped;
                if (ReadCatalogBytes(cat, local, wrapped, err) &&
                    LooksLikeBtxEnc2(Span<const unsigned char>{wrapped.data(), wrapped.size()})) {
                    std::vector<unsigned char> plain;
                    if (UnwrapBtxEnc2(Span<const unsigned char>{secret->data(), secret->size()},
                                       Span<const unsigned char>{wrapped.data(), wrapped.size()}, plain, err)) {
                        const fs::path tmp = HelperDir(cat) / "tmp-unlock.safetensors";
                        {
                            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                            out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(plain.size()));
                        }
                        CatalogEntry pub;
                        if (cat.ImportPath(fs::PathToString(tmp), /*pin=*/true, pub, err)) {
                            c->plaintext_verified = true;
                            unlocked = true;
                            cat.ApplyDemandSeed(pub.model_id, err);
                            result.pushKV("plaintext_model_id", pub.model_id.Hex());
                            result.pushKV("plaintext_artifact_id", pub.artifact_id.Hex());
                        }
                        fs::remove(tmp);
                    }
                } else {
                    cat.ApplyDemandSeed(local.model_id, err);
                    unlocked = true;
                }
            }
            SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
            PersistEconomy(cat);
            result.pushKV("secret_disclosed", true);
            result.pushKV("secret_retained", false);
            result.pushKV("unlocked_locally", unlocked);
            result.pushKV("plaintext_verified", c->plaintext_verified);
            result.pushKV("lifecycle_state", c->plaintext_verified ? "PUBLIC_RELEASED" : "SECRET_DISCLOSED");
            return true;
        }
        if (c && method == "refundmodelrelease") {
            result.pushKV("release_id", c->release_id.Hex());
            result.pushKV("refund_height", static_cast<int64_t>(c->refund_height));
        }
        CatalogEntry e;
        if (!id.IsNull() && cat.Find(id, e)) {
            cat.ApplyDemandSeed(e.model_id, err);
            result.pushKV("seeded", cat.Find(id, e) && e.seeded);
        }
        return true;
    }
    if (method == "resolveresource") {
        uint8_t kind = static_cast<uint8_t>(ResourceKind::MODEL);
        std::string digest;
        const UniValue& q = Arg(0);
        if (q.isObject()) {
            if (q.exists("kind") && !KindFromJson(q["kind"], kind, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (q.exists("digest48") && q["digest48"].isStr()) digest = q["digest48"].get_str();
            else if (q.exists("id") && q["id"].isStr()) digest = q["id"].get_str();
            else if (q.exists("uri") && q["uri"].isStr()) {
                Resource parsed;
                if (DecodeResource(q["uri"].get_str(), parsed, err)) {
                    kind = static_cast<uint8_t>(parsed.kind);
                    digest = parsed.digest.Hex();
                } else {
                    err_code = "INVALID_PARAMETER";
                    return false;
                }
            }
        } else if (q.isStr()) {
            Resource parsed;
            if (DecodeResource(q.get_str(), parsed, err)) {
                kind = static_cast<uint8_t>(parsed.kind);
                digest = parsed.digest.Hex();
            } else {
                digest = q.get_str();
                err.clear();
            }
        }
        result = TypedResolveJson(cat, kind, digest);
        return true;
    }
    if (method == "exportmodelpath") {
        const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
        CatalogEntry e;
        if (id.IsNull() || !cat.Find(id, e)) {
            err_code = "NOT_FOUND";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("model_id", e.model_id.Hex());
        result.pushKV("artifact_id", e.artifact_id.Hex());
        result.pushKV("store_root", fs::PathToString(cat.Store().Root()));
        result.pushKV("source_path", e.source_path);
        result.pushKV("inference", false);
        result.pushKV("runtime_started", false);
        result.pushKV("runtime_exec", false);
        UniValue files(UniValue::VARR);
        for (const auto& f : e.core.files) {
            UniValue one(UniValue::VOBJ);
            one.pushKV("path", f.path);
            one.pushKV("size", f.size);
            one.pushKV("sha384", f.sha384.Hex());
            files.push_back(one);
        }
        result.pushKV("files", files);
        result.pushKV("note", "Verified local files. This RPC never starts a runtime.");
        return true;
    }
    if (method == "getmodelpolicy" || method == "setmodelpolicy") {
        PreservationPolicy live = cat.Policy();
        if (method == "setmodelpolicy") {
            UniValue patch = Arg(0);
            if (!patch.isObject()) {
                err_code = "INVALID_PARAMETER";
                err = "policy object required";
                return false;
            }
            if (patch.exists("automatic_spend_atoms") && patch["automatic_spend_atoms"].getInt<int64_t>() != 0) {
                err_code = "INVALID_PARAMETER";
                err = "automatic spend remains 0; use EXPLICIT_PAID getmodel for a quote";
                return false;
            }
            if (patch.exists("auto_pay") && patch["auto_pay"].get_bool()) {
                err_code = "INVALID_PARAMETER";
                err = "auto_pay is refused; automatic spend is 0";
                return false;
            }
            if (!PolicyFromJson(patch, live, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            cat.SetPolicy(live);
            g_runtime.follow_peers = live.follow_configured_peers;
            g_runtime.preserve_rare = live.preserve_rare;
            const UniValue dumped = PolicyToJson(cat.Policy());
            if (!WriteJsonFile(HelperDir(cat) / "policy.json", dumped, err)) {
                err_code = "IO";
                return false;
            }
        }
        result = PolicyToJson(cat.Policy());
        result.pushKV("auto_pay", false);
        return true;
    }
    if (method == "listmodelidentities" || method == "createmodelidentity") {
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "identities.json", store);
        UniValue arr = store.exists("identities") ? store["identities"] : UniValue(UniValue::VARR);
        if (method == "createmodelidentity") {
            std::vector<unsigned char> pk, sk;
            if (!GenerateMlDsa44(pk, sk, err)) {
                err_code = "CRYPTO";
                return false;
            }
            UniValue id(UniValue::VOBJ);
            id.pushKV("id", PublisherId(pk).Hex());
            id.pushKV("label", Arg(0).isStr() ? Arg(0).get_str() : "");
            id.pushKV("pubkey_hex", HexStr(pk));
            id.pushKV("class", "RESEARCH_PUBLISHER");
            id.pushKV("trusted", false);
            arr.push_back(id);
            store.pushKV("identities", arr);
            if (!WriteJsonFile(HelperDir(cat) / "identities.json", store, err)) {
                err_code = "IO";
                return false;
            }
            const fs::path skpath = HelperDir(cat) / "tls" / fs::PathFromString("identity-" + PublisherId(pk).Hex().substr(0, 16) + ".sk");
            fs::create_directories(skpath.parent_path());
            std::ofstream skf(skpath, std::ios::binary);
            skf.write(reinterpret_cast<const char*>(sk.data()), static_cast<std::streamsize>(sk.size()));
            result = id;
            result.pushKV("schema_version", 2);
            result.pushKV("secret_path", fs::PathToString(skpath));
            result.pushKV("wallet_backed", false);
            result.pushKV("contains_wallet_material", false);
            result.pushKV("note", "identity-only; never a wallet key");
            return true;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("identities", arr);
        return true;
    }
    if (method == "getmodelreciprocity") {
        ReciprocityLedger led;
        UniValue snap;
        UniValue raw;
        ReadJsonFile(HelperDir(cat) / "reciprocity.json", raw);
        if (raw.isObject()) led.Load(raw, err);
        result = led.Snapshot();
        result.pushKV("schema_version", 2);
        result.pushKV("note", "local observations only; not money and not consensus");
        return true;
    }
    if (method == "exportmodelcontacts" || method == "exportmodelpeers") {
        result.pushKV("schema_version", 2);
        UniValue arr(UniValue::VARR);
        for (const auto& p : cat.Peers()) arr.push_back(p);
        result.pushKV("peers", arr);
        result.pushKV("note", "public endpoints only; no secret keys");
        return true;
    }
    if (method == "importmodelcontacts" || method == "importmodelpeers" || method == "importmodeltrust") {
        if (!Arg(0).isArray() && !Arg(0).isStr()) {
            err_code = "INVALID_PARAMETER";
            err = "peer list required";
            return false;
        }
        if (Arg(0).isStr()) cat.AddPeer(Arg(0).get_str());
        else {
            for (const auto& p : Arg(0).getValues()) {
                if (p.isStr()) cat.AddPeer(p.get_str());
            }
        }
        result.pushKV("schema_version", 2);
        result.pushKV("peers", static_cast<int>(cat.Peers().size()));
        return true;
    }
    if (method == "listmodelrules" || method == "setmodelrule" || method == "removemodelrule") {
        UniValue rules;
        ReadJsonFile(HelperDir(cat) / "acl.json", rules);
        if (!rules.isObject()) rules = UniValue(UniValue::VOBJ);
        if (method == "setmodelrule") {
            if (!Arg(0).isObject()) {
                err_code = "INVALID_PARAMETER";
                err = "rule object required";
                return false;
            }
            UniValue arr = rules.exists("rules") ? rules["rules"] : UniValue(UniValue::VARR);
            arr.push_back(Arg(0));
            rules.pushKV("rules", arr);
            WriteJsonFile(HelperDir(cat) / "acl.json", rules, err);
        } else if (method == "removemodelrule" && Arg(0).isNum()) {
            UniValue arr(UniValue::VARR);
            const int idx = Arg(0).getInt<int>();
            int i = 0;
            for (const auto& r : rules["rules"].getValues()) {
                if (i++ != idx) arr.push_back(r);
            }
            rules.pushKV("rules", arr);
            WriteJsonFile(HelperDir(cat) / "acl.json", rules, err);
        }
        result = rules;
        result.pushKV("schema_version", 2);
        result.pushKV("affects_banman", false);
        return true;
    }
    if (method == "joinmodelcircle" || method == "leavemodelcircle" || method == "subscribemodelcollection" ||
        method == "subscribemodelpolicy" || method == "unsubscribemodelcollection" || method == "unsubscribemodelpolicy") {
        UniValue store;
        ReadJsonFile(HelperDir(cat) / "community.json", store);
        const std::string key = (method.find("circle") != std::string::npos) ? "circles" : "subscriptions";
        UniValue arr = store.exists(key) ? store[key] : UniValue(UniValue::VARR);
        if (method.rfind("leave", 0) == 0 || method.rfind("unsub", 0) == 0) {
            UniValue keep(UniValue::VARR);
            const std::string id = Arg(0).get_str();
            for (const auto& x : arr.getValues()) {
                if (!x.isStr() || x.get_str() != id) keep.push_back(x);
            }
            arr = keep;
            RememberStoppedPreservation(store, id);
        } else if (Arg(0).isStr()) {
            arr.push_back(Arg(0).get_str());
            uint8_t kind = RECORD_PRESERVATION_CIRCLE;
            if (method.find("collection") != std::string::npos) kind = RECORD_COLLECTION;
            else if (method.find("policy") != std::string::npos) kind = RECORD_POLICY_BUNDLE;
            Digest48 mid = CommunityLocalId(Arg(0).get_str());
            std::string hex = mid.Hex();
            UniValue extra(UniValue::VOBJ);
            int64_t ttl = 0;
            if (kind == RECORD_COLLECTION) {
                extra.pushKV("title", "collection");
                extra.pushKV("description", "local");
                UniValue entries(UniValue::VARR);
                UniValue e(UniValue::VOBJ);
                e.pushKV("model_id", hex);
                e.pushKV("priority", 1);
                e.pushKV("retention_days", 7);
                entries.push_back(e);
                extra.pushKV("entries", entries);
            } else if (kind == RECORD_POLICY_BUNDLE) {
                extra.pushKV("title", "policy");
                UniValue recs(UniValue::VARR);
                UniValue rec(UniValue::VOBJ);
                rec.pushKV("target_kind", 0);
                rec.pushKV("target_id", hex);
                rec.pushKV("action", 3);
                rec.pushKV("ttl_seconds", DAY_SECONDS);
                rec.pushKV("reason", "preview");
                recs.push_back(rec);
                extra.pushKV("recommendations", recs);
                ttl = DAY_SECONDS;
            } else {
                extra.pushKV("title", "circle");
                extra.pushKV("description", "local");
                extra.pushKV("collection_id", hex);
                extra.pushKV("target_observed_groups", 2);
                extra.pushKV("suggested_storage_bytes", 0);
                extra.pushKV("suggested_lease_seconds", 300);
            }
            SignedRecordHint h;
            if (!IssueAndStoreRecord(cat, kind, extra, ttl, h, err)) {
                err_code = "RECORD";
                return false;
            }
            result.pushKV("signed_record_id", h.record_id.Hex());
            result.pushKV("kind", kind);
            result.pushKV("recorded", true);
        }
        store.pushKV(key, arr);
        WriteJsonFile(HelperDir(cat) / "community.json", store, err);
        result.pushKV("schema_version", 2);
        result.pushKV("on_chain_membership", false);
        result.pushKV("automatic_preservation", method.rfind("unsub", 0) != 0 && method.rfind("leave", 0) != 0);
        if (method.find("collection") != std::string::npos || method.find("policy") != std::string::npos) {
            uint64_t est_disk = 0;
            if (result.exists("kind") && result["kind"].getInt<int>() == RECORD_COLLECTION) {
                UniValue listed;
                cat.List(listed);
                if (listed.exists("models")) {
                    for (const auto& m : listed["models"].getValues()) {
                        if (m.exists("bytes")) est_disk += m["bytes"].getInt<uint64_t>();
                    }
                }
            }
            result.pushKV("impact", CollectionFollowImpactPreview(cat.QuotaBytes(), cat.UsedBytes(), est_disk, /*egress=*/0));
        }
        if (store.exists("circles")) result.pushKV("circles", store["circles"]);
        if (store.exists("subscriptions")) result.pushKV("subscriptions", store["subscriptions"]);
        return true;
    }
    if (method == "delegatemodelservice" || method == "revokemodelservice") {
        UniValue extra(UniValue::VOBJ);
        uint8_t kind = RECORD_SERVICE_DELEGATION;
        int64_t ttl = 7 * DAY_SECONDS;
        if (method == "revokemodelservice") {
            kind = RECORD_REVOCATION;
            ttl = 0;
            extra.pushKV("target_kind", 1);
            Digest48 tid;
            const UniValue& body = Arg(0);
            std::string hex;
            if (body.isStr()) {
                hex = body.get_str();
            } else if (body.isObject()) {
                if (body.exists("target_id") && body["target_id"].isStr()) hex = body["target_id"].get_str();
                else if (body.exists("delegation_id") && body["delegation_id"].isStr()) {
                    hex = body["delegation_id"].get_str();
                } else if (body.exists("record_id") && body["record_id"].isStr()) hex = body["record_id"].get_str();
            }
            if (!hex.empty() && Digest48::FromHex(hex, tid, err)) extra.pushKV("target_id", tid.Hex());
            else extra.pushKV("target_id", std::string(96, '0'));
            extra.pushKV("reason_code", 1);
            if (body.isObject() && body.exists("reason_code") && body["reason_code"].isNum()) {
                extra.pushKV("reason_code", body["reason_code"].getInt<int>());
            }
        } else {
            std::vector<unsigned char> pk, sk;
            Digest48 sid;
            if (!LoadOrCreateResearchIdentity(HelperDir(cat), pk, sk, sid, err)) {
                err_code = "CRYPTO";
                return false;
            }
            const UniValue& body = Arg(0);
            std::string dhex = HexStr(pk);
            uint32_t scopes = DELEGATE_ANNOUNCE | DELEGATE_SERVE;
            bool all_models = true;
            UniValue model_scope(UniValue::VARR);
            if (body.isObject()) {
                if (body.exists("delegate_pubkey") && body["delegate_pubkey"].isStr()) {
                    dhex = body["delegate_pubkey"].get_str();
                } else if (body.exists("service_pubkey") && body["service_pubkey"].isStr()) {
                    dhex = body["service_pubkey"].get_str();
                }
                if (body.exists("scopes") && body["scopes"].isNum()) {
                    scopes = static_cast<uint32_t>(body["scopes"].getInt<int64_t>());
                }
                if (body.exists("ttl") && body["ttl"].isNum()) {
                    ttl = body["ttl"].getInt<int64_t>();
                } else if (body.exists("expiry") && body["expiry"].isNum()) {
                    const int64_t exp = body["expiry"].getInt<int64_t>();
                    const int64_t now = static_cast<int64_t>(std::time(nullptr));
                    ttl = exp > now ? exp - now : 0;
                }
                if (body.exists("all_models") && body["all_models"].isBool()) {
                    all_models = body["all_models"].get_bool();
                }
                if (body.exists("model_scope") && body["model_scope"].isArray()) {
                    model_scope = body["model_scope"];
                    all_models = false;
                }
            } else if (body.isStr() && body.get_str().size() == MLDSA44_PK * 2) {
                dhex = body.get_str();
            }
            if ((scopes & ~DELEGATE_KNOWN_MASK) != 0) {
                err_code = "INVALID_PARAMETER";
                err = "delegation cannot authorize money, root actions, or unknown scopes";
                return false;
            }
            if (ttl <= 0 || ttl > MAX_DELEGATION_SECONDS) ttl = MAX_DELEGATION_SECONDS;
            extra.pushKV("delegate_pubkey", dhex);
            extra.pushKV("scopes", static_cast<int>(scopes));
            extra.pushKV("all_models", all_models);
            extra.pushKV("model_scope", model_scope);
        }
        SignedRecordHint h;
        if (!IssueAndStoreRecord(cat, kind, extra, ttl, h, err)) {
            err_code = "RECORD";
            return false;
        }
        result.pushKV("schema_version", 2);
        result.pushKV("recorded", true);
        result.pushKV("record_id", h.record_id.Hex());
        if (method == "revokemodelservice" && extra.exists("target_id")) {
            result.pushKV("target_id", extra["target_id"]);
        }
        result.pushKV("note", "typed root-authorized operation; never a money signature");
        return true;
    }
    if (method == "preparemodelfunding" || method == "signmodelfunding" || method == "submitmodelfunding" ||
        method == "exportmodelrecovery" || method == "buildmodelhtlcclaim" || method == "buildmodelhtlcrefund" ||
        method == "preparefundmodelrelease") {
        if (method == "preparefundmodelrelease") {
            EnsureEconomy(cat);
            UniValue opts = Arg(1).isObject() ? Arg(1) : UniValue(UniValue::VOBJ);
            if (params.isArray() && params.size() > 2 && Arg(2).isObject()) opts = Arg(2);
            if (params.isArray() && params.size() > 1 && Arg(1).isNum()) {
                opts.pushKV("amount_atoms", Arg(1).getInt<int64_t>());
            }
            opts.pushKV("automatic_spend_atoms", 0);
            opts.pushKV("auto_pay", false);
            const std::string rid = Arg(0).get_str();
            Digest48 id;
            const ReleaseCampaign* c = nullptr;
            if (Digest48::FromHex(rid, id, err)) c = g_campaigns.GetByRelease(id);
            if (!c) c = g_campaigns.GetByModel(IdFromUser(rid, err));
            if (c) {
                opts.pushKV("release_id", c->release_id.Hex());
                opts.pushKV("key_hash", c->key_hash.Hex());
                opts.pushKV("refund_height", static_cast<int64_t>(c->refund_height));
                opts.pushKV("hashlock_algorithm", "SHA256");
                opts.pushKV("assurance", "KEY_RELEASE_ONLY");
            }
            UniValue wrapped(UniValue::VARR);
            wrapped.push_back(opts);
            const bool ok = DispatchFundingRpc(cat, "preparemodelfunding", wrapped, result, err_code, err);
            if (ok) {
                result.pushKV("automatic_spend_atoms", 0);
                result.pushKV("wallet_authorization_required", true);
                result.pushKV("silently_spend", false);
            }
            return ok;
        }
        return DispatchFundingRpc(cat, method, params, result, err_code, err);
    }
    if (method == "getmodeleconomyentry" || method == "getmodelreleaseeconomics" || method == "getmodelfeed" ||
        method == "getreleasefeed" || method == "getmodelfeedstatus" || method == "getmodelfeedsequence" ||
        method == "getfundablemodels" || method == "getrecentlyunlockedmodels" || method == "cacheencryptedmodel" ||
        method == "ingestchainfundingobservation" || method == "setreleaseoutputscript") {
        EnsureSearchBound();
        EnsureEconomy(cat);
        std::unique_lock<std::mutex> lock(g_search_mu);
        IngestCatalogIntoSearch(cat);
        for (const auto& rec : g_search_idx.All()) AfterIndexPut(rec, ConnNowMs());
        auto decorate = [&](SearchHit h) {
            auto it = g_search_obs.find(h.rec.model_id.Hex());
            if (it != g_search_obs.end()) h.health = ComputeSwarmHealth(0, 0, it->second);
            CatalogEntry e;
            if (cat.Find(h.rec.model_id, e)) {
                h.local.known = true;
                h.local.seeded = e.seeded;
                h.local.pinned = e.pinned;
                h.local.partial = e.incomplete;
                h.local.downloaded = e.bytes_verified;
            }
            return EconomyForHit(h, &cat);
        };
        if (method == "setreleaseoutputscript") {
            if (!Arg(0).isObject() || !Arg(0).exists("release_id") || !Arg(0)["release_id"].isStr()) {
                err_code = "INVALID_PARAMETER";
                err = "release_id required";
                return false;
            }
            const std::string rid = Arg(0)["release_id"].get_str();
            Digest48 id;
            if (!Digest48::FromHex(rid, id, err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            auto* c = const_cast<ReleaseCampaign*>(g_campaigns.GetByRelease(id));
            if (!c) {
                err_code = "NOT_FOUND";
                err = "unknown release";
                return false;
            }
            if (Arg(0).exists("output_script") && Arg(0)["output_script"].isStr()) {
                c->output_script_hex = ToLower(Arg(0)["output_script"].get_str());
            }
            SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
            result.pushKV("accepted", true);
            result.pushKV("release_id", rid);
            result.pushKV("output_script", c->output_script_hex);
            return true;
        }
        if (method == "ingestchainfundingobservation") {
            if (!Arg(0).isObject()) {
                err_code = "INVALID_PARAMETER";
                err = "observation object";
                return false;
            }
            const UniValue& o = Arg(0);
            if (!(o.exists("confirmed_known") && o["confirmed_known"].isTrue()) ||
                !o.exists("funding_source") || o["funding_source"].get_str() != "CHAIN_OBSERVATION") {
                result.pushKV("accepted", false);
                result.pushKV("note", "remote unsigned funding claims are not ingested as confirmed");
                return true;
            }
            FundingObservation f;
            f.confirmed_known = true;
            f.funding_source = "CHAIN_OBSERVATION";
            if (o.exists("confirmed_funded_atoms")) f.confirmed_funded_atoms = o["confirmed_funded_atoms"].getInt<int64_t>();
            if (o.exists("pending_funded_atoms")) f.pending_funded_atoms = o["pending_funded_atoms"].getInt<int64_t>();
            if (o.exists("chain_height")) {
                f.chain_height = static_cast<uint32_t>(o["chain_height"].getInt<int64_t>());
                f.chain_height_known = true;
            }
            f.wallet_contributor = o.exists("wallet_contributor") && o["wallet_contributor"].get_bool();
            f.refund_available_locally = o.exists("refund_available_locally") && o["refund_available_locally"].get_bool();
            if (o.exists("claim_txid")) f.claim_txid = o["claim_txid"].get_str();
            std::string rid;
            if (o.exists("release_id")) rid = o["release_id"].get_str();
            if (rid.empty()) {
                err_code = "INVALID_PARAMETER";
                err = "release_id required";
                return false;
            }
            g_chain_obs[rid] = f;
            Digest48 id;
            if (Digest48::FromHex(rid, id, err)) {
                if (auto* c = const_cast<ReleaseCampaign*>(g_campaigns.GetByRelease(id))) {
                    c->funded_atoms = f.confirmed_funded_atoms;
                    if (f.chain_height_known) c->latest_funding_height = f.chain_height;
                    g_feed.NoteFundingChanged(*c, ConnNowMs());
                    LiveObserveCampaign(*c, FeedEventType::RELEASE_FUNDING_CHANGED);
                    SaveCampaigns(HelperDir(cat), g_campaigns.List(), err);
                }
            }
            result.pushKV("accepted", true);
            result.pushKV("release_id", rid);
            result.pushKV("confirmed_funded_atoms", f.confirmed_funded_atoms);
            result.pushKV("funding_source", "CHAIN_OBSERVATION");
            return true;
        }
        if (method == "getmodeleconomyentry" || method == "getmodelreleaseeconomics") {
            if (!params.isArray() || params.size() < 1 || !Arg(0).isStr()) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
            const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
            const ReleaseCampaign* c = g_campaigns.GetByRelease(id);
            if (!c) c = g_campaigns.GetByModel(id);
            if (!c && !Arg(0).get_str().empty()) c = g_campaigns.GetByReleaseHex(Arg(0).get_str());
            SearchHit h;
            Digest48 mid = c ? c->model_id : id;
            if (const auto* rec = g_search_idx.Get(mid)) h.rec = *rec;
            else h.rec.model_id = mid;
            auto e = ComposeEconomyEntry(h, c, ObservationFromHit(h, c, &cat));
            result = method == "getmodelreleaseeconomics" ? EconomyReleaseJson(e) : EconomyEntryToJson(e);
            result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
            result.pushKV("lifecycle_state", ModelLifecycleName(e.lifecycle));
            result.pushKV("automatic_spend_atoms", 0);
            return true;
        }
        if (method == "getmodelfeedstatus" || method == "getmodelfeedsequence") {
            int pub = 0, unrel = 0, unlocked = 0;
            for (const auto& rec : g_search_idx.All()) {
                if (rec.release_id.empty()) ++pub;
                else ++unrel;
            }
            FeedCoverage cov;
            result = g_feed.StatusJson(pub, static_cast<int>(g_campaigns.Size()), unrel, unlocked, cov);
            result.pushKV("feed_sequence", static_cast<int64_t>(g_feed.Sequence()));
            return true;
        }
        if (method == "getfundablemodels") {
            SearchQuery q;
            if (Arg(0).isObject()) ParseSearchQuery(Arg(0), q, err);
            q.filters.fundable_only = true;
            if (!Arg(0).isObject() || !Arg(0).exists("sort")) q.sort = SearchSort::NEARLY_FUNDED;
            std::vector<ModelEconomyEntry> camp;
            for (const auto& c : g_campaigns.List()) {
                SearchHit h;
                if (const auto* rec = g_search_idx.Get(c.model_id)) h.rec = *rec;
                else {
                    h.rec.model_id = c.model_id;
                    h.rec.release_id = c.release_id.Hex();
                    h.rec.release_state = "FUNDING";
                    h.rec.release_target_atoms = c.target_atoms;
                    h.rec.key_hash = c.key_hash;
                    h.rec.refund_height = c.refund_height;
                }
                auto e = ComposeEconomyEntry(h, &c, ObservationFromHit(h, &c, &cat));
                if (!e.fundable_now) continue;
                if (!MatchesEconomyFilters(e, q.filters)) continue;
                camp.push_back(std::move(e));
            }
            SortEconomyEntries(camp, q.sort);
            if (q.limit > 0 && static_cast<int>(camp.size()) > q.limit) camp.resize(q.limit);
            UniValue arr(UniValue::VARR);
            for (const auto& e : camp) arr.push_back(EconomySearchCard(e));
            result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
            result.pushKV("results", arr);
            result.pushKV("sort", SearchSortName(q.sort));
            result.pushKV("automatic_spend_atoms", 0);
            return true;
        }
        if (method == "getrecentlyunlockedmodels") {
            FeedQuery fq;
            fq.mode = FeedMode::JUST_UNLOCKED;
            fq.limit = 50;
            if (Arg(0).isObject()) {
                if (Arg(0).exists("limit")) fq.limit = Arg(0)["limit"].getInt<int>();
                if (Arg(0).exists("since")) fq.since = Arg(0)["since"].getInt<int64_t>();
            }
            std::string next;
            const auto items = g_feed.Query(fq, ConnNowMs(), next);
            UniValue arr(UniValue::VARR);
            for (const auto& ev : items) {
                SearchHit h;
                h.rec = ev.rec;
                arr.push_back(EconomySearchCard(decorate(h)));
            }
            result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
            result.pushKV("results", arr);
            result.pushKV("next_cursor", next);
            result.pushKV("feed_sequence", static_cast<int64_t>(g_feed.Sequence()));
            return true;
        }
        if (method == "cacheencryptedmodel") {
            result.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
            result.pushKV("action", "CACHE_ENCRYPTED");
            result.pushKV("plaintext_unavailable", true);
            result.pushKV("automatic_download", false);
            result.pushKV("automatic_spend_atoms", 0);
            if (!params.isArray() || params.size() < 1 || !Arg(0).isStr()) {
                err_code = "INVALID_PARAMETER";
                err = "release_id or model id required";
                return false;
            }
            const Digest48 id = ResolveUserId(Arg(0).get_str(), err);
            const ReleaseCampaign* c = g_campaigns.GetByRelease(id);
            if (!c) c = g_campaigns.GetByModel(id);
            if (!c) c = g_campaigns.GetByReleaseHex(Arg(0).get_str());
            Digest48 cid;
            if (c) {
                cid = c->ciphertext_artifact_id.IsNull() ? c->artifact_id : c->ciphertext_artifact_id;
                result.pushKV("release_id", c->release_id.Hex());
                result.pushKV("key_hash", c->key_hash.Hex());
            } else {
                cid = id;
            }
            if (cid.IsNull()) {
                err_code = "NOT_FOUND";
                err = "no ciphertext artifact for this campaign";
                return false;
            }
            result.pushKV("ciphertext_artifact_id", cid.Hex());
            CatalogEntry local;
            if (cat.Find(cid, local) || (c && cat.Find(c->model_id, local))) {
                std::vector<unsigned char> bytes;
                if (ReadCatalogBytes(cat, local, bytes, err) &&
                    LooksLikeBtxEnc2(Span<const unsigned char>{bytes.data(), bytes.size()})) {
                    result.pushKV("status", "local");
                    result.pushKV("verified_ciphertext", true);
                    result.pushKV("plaintext_unavailable", true);
                    if (cat.Policy().allow_encrypted) {
                        cat.ApplyDemandSeed(local.model_id, err);
                        result.pushKV("seeded_ciphertext", true);
                    }
                    return true;
                }
            }
            lock.unlock();
            const std::string job_id = EnqueueRetrieve(cat, cid, stop);
            result.pushKV("status", "running");
            result.pushKV("job_id", job_id);
            result.pushKV("note", "poll getmodeljob; ciphertext retrieve does not reveal plaintext");
            return true;
        }
        // getmodelfeed / getreleasefeed
        FeedQuery fq;
        fq.scope = SearchScope::NETWORK;
        if (Arg(0).isObject()) {
            if (Arg(0).exists("scope") && !ParseSearchScope(Arg(0)["scope"].get_str(), fq.scope)) {
                err_code = "INVALID_PARAMETER";
                err = "bad scope";
                return false;
            }
            if (Arg(0).exists("mode") && !ParseFeedMode(Arg(0)["mode"].get_str(), fq.mode)) {
                err_code = "INVALID_PARAMETER";
                err = "bad feed mode";
                return false;
            }
            if (Arg(0).exists("since")) fq.since = Arg(0)["since"].getInt<int64_t>();
            if (Arg(0).exists("since_sequence")) fq.since_sequence = Arg(0)["since_sequence"].getInt<int64_t>();
            if (Arg(0).exists("limit")) fq.limit = Arg(0)["limit"].getInt<int>();
            if (Arg(0).exists("cursor")) fq.cursor = Arg(0)["cursor"].get_str();
            if (Arg(0).exists("filters") && Arg(0)["filters"].isObject()) {
                UniValue wrap(UniValue::VOBJ);
                wrap.pushKV("filters", Arg(0)["filters"]);
                SearchQuery sq;
                ParseSearchQuery(wrap, sq, err);
                fq.filters = sq.filters;
            }
        }
        if (method == "getreleasefeed") {
            if (!Arg(0).isObject() || !Arg(0).exists("mode")) fq.mode = FeedMode::NEW_RELEASE_CAMPAIGNS;
        }
        lock.unlock();
        FeedCoverage cov;
        if (fq.scope != SearchScope::LOCAL) {
            std::vector<std::string> fanout;
            auto add_ep = [&](const std::string& ep) {
                if (ep.empty()) return;
                if (std::find(fanout.begin(), fanout.end(), ep) != fanout.end()) return;
                if (static_cast<int>(fanout.size()) >= SEARCH_FANOUT_MAX) return;
                fanout.push_back(ep);
            };
            {
                std::lock_guard<std::mutex> lk(g_search_mu);
                for (const auto& p : g_search_idx.IndexPeers()) add_ep(p);
                for (const auto& p : cat.Peers()) add_ep(p);
            }
            {
                std::lock_guard<std::mutex> plock(g_swarm.pex_mu);
                for (const auto& h : g_swarm.pex.Recent(ConnNowMs())) add_ep(h.endpoint);
            }
            Pq1Context pq;
            std::string tls_err;
            const fs::path pinfile = HelperDir(cat) / "tls" / "pins.json";
            const bool pq_ok = LoadPq1Identity(pq, HelperDir(cat), tls_err);
            UniValue body(UniValue::VOBJ);
            body.pushKV("mode", FeedModeName(fq.mode));
            body.pushKV("limit", fq.limit);
            for (const auto& ep : fanout) {
                if (!pq_ok) {
                    cov.timed_out += 1;
                    continue;
                }
                UniValue reply;
                bool timed = false;
                std::string perr;
                if (QueryExtPeer(pq, pinfile, ep, "ext/feed", body, reply, timed, perr) ||
                    QuerySearchPeer(pq, pinfile, ep, body, reply, timed, perr)) {
                    cov.responses_received += 1;
                    cov.peers_contributing += 1;
                    std::lock_guard<std::mutex> lk(g_search_mu);
                    if (reply.exists("records") && reply["records"].isArray()) {
                        for (const auto& recj : reply["records"].getValues()) {
                            ModelSearchRecord rec;
                            std::string ierr;
                            if (SearchRecordFromJson(recj, rec, ierr) && g_search_idx.Put(rec, ConnNowMs(), ierr)) {
                                AfterIndexPut(rec, ConnNowMs());
                            }
                        }
                    }
                    if (reply.exists("items") && reply["items"].isArray()) {
                        for (const auto& it : reply["items"].getValues()) {
                            if (it.isObject() && it.exists("entry") && it["entry"].isObject() &&
                                it["entry"].exists("model") && it["entry"]["model"].exists("model_id")) {
                                SearchHit h;
                                std::string herr;
                                SearchHitFromCard(it["entry"], h, herr);
                            }
                        }
                    }
                } else if (timed) {
                    cov.timed_out += 1;
                }
            }
            g_feed.NoteRefresh(ConnNowMs());
        }
        cov.last_network_refresh = g_feed.LastRefresh();
        lock.lock();
        std::string next;
        auto items = g_feed.Query(fq, ConnNowMs(), next);
        std::vector<ModelEconomyEntry> entries;
        if (fq.mode == FeedMode::NEARLY_FUNDED || fq.mode == FeedMode::FUNDED_AWAITING_RELEASE) {
            items.clear();
            std::vector<ModelEconomyEntry> camp;
            for (const auto& c : g_campaigns.List()) {
                SearchHit h;
                if (const auto* rec = g_search_idx.Get(c.model_id)) h.rec = *rec;
                else {
                    h.rec.model_id = c.model_id;
                    h.rec.release_id = c.release_id.Hex();
                    h.rec.release_state = "FUNDING";
                    h.rec.release_target_atoms = c.target_atoms;
                    h.rec.key_hash = c.key_hash;
                }
                auto e = ComposeEconomyEntry(h, &c, ObservationFromHit(h, &c, &cat));
                if (fq.mode == FeedMode::NEARLY_FUNDED && !e.fundable_now) continue;
                if (fq.mode == FeedMode::FUNDED_AWAITING_RELEASE &&
                    e.lifecycle != ModelLifecycle::FUNDED_AWAITING_RELEASE) {
                    continue;
                }
                if (!MatchesEconomyFilters(e, fq.filters)) continue;
                camp.push_back(std::move(e));
            }
            SortEconomyEntries(camp, fq.mode == FeedMode::NEARLY_FUNDED ? SearchSort::NEARLY_FUNDED : SearchSort::NEWEST);
            if (static_cast<int>(camp.size()) > fq.limit) camp.resize(fq.limit);
            entries = std::move(camp);
            for (const auto& e : entries) {
                FeedEvent ev;
                ev.event_type = FeedEventType::RELEASE_CAMPAIGN_CREATED;
                ev.model_id = e.hit.rec.model_id;
                ev.release_id = e.campaign.release_id.Hex();
                ev.rec = e.hit.rec;
                ev.event_id = e.hit.rec.model_id.Hex();
                items.push_back(ev);
            }
        } else {
            for (auto& ev : items) {
                SearchHit h;
                h.rec = ev.rec;
                if (h.rec.model_id.IsNull()) h.rec.model_id = ev.model_id;
                auto e = decorate(h);
                if (!MatchesEconomyFilters(e, fq.filters)) continue;
                entries.push_back(std::move(e));
            }
        }
        result = FeedPageJson(items, entries, fq, cov, g_feed.Sequence(), next);
        PersistEconomy(cat);
        return true;
    }
    err_code = "METHOD_NOT_FOUND";
    err = "unknown model RPC";
    return false;
    } catch (const std::exception&) {
        err_code = "INTERNAL";
        err = "malformed rpc fields";
        result = UniValue(UniValue::VOBJ);
        result.pushKV("automatic_spend_atoms", 0);
        return false;
    }
}

bool EnsureMlDsaTlsFiles(const fs::path& cert, const fs::path& key, std::string& err)
{
    if (fs::exists(cert) && fs::exists(key)) return true;
    fs::create_directories(cert.parent_path());
    const std::string cmd = strprintf(
        "%s req -x509 -new -newkey mldsa44 -keyout %s -out %s -nodes -subj '/CN=btx-modeld' -days 3650 >/dev/null 2>&1",
        QuoteShellArg(OpensslBin()), QuoteShellArg(fs::PathToString(key)), QuoteShellArg(fs::PathToString(cert)));
    const int rc = std::system(cmd.c_str());
    if (rc != 0 || !fs::exists(cert) || !fs::exists(key)) {
        err = "openssl mldsa44 certificate generation failed";
        return false;
    }
    return true;
}

bool LoadPq1Identity(Pq1Context& pq, const fs::path& modeldir, std::string& err)
{
    const fs::path cert = modeldir / "tls" / "cert.pem";
    const fs::path key = modeldir / "tls" / "key.pem";
    if (!EnsureMlDsaTlsFiles(cert, key, err)) return false;
    std::ifstream cf(cert), kf(key);
    const std::string cert_pem((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    const std::string key_pem((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
    return pq.LoadSelfSignedMlDsa(cert_pem, key_pem, err);
}

bool RetrieveFreeFromPeer(ModelCatalog& cat, Pq1Context& pq, const std::string& host, uint16_t port,
                          const Digest48& model_id, std::string& err, std::atomic<bool>* stop, const fs::path& pinfile,
                          RetrieveProgress* progress, const std::vector<std::string>& extra_peers)
{
    auto init_sess = [&](Pq1Session& sess) -> bool {
        sess.stop = stop;
        sess.pinfile = pinfile;
        return sess.Connect(pq, host, port, err);
    };
    Pq1Session sess;
    if (!init_sess(sess)) return false;
    NativeRequest req;
    NativeResponse resp;
    req.method = "POST";
    req.path = std::string(MODEL_HTTP_ROOT) + "hello";
    if (!sess.Request(req, resp, err) || resp.status != 200) {
        if (err.empty()) err = "hello failed";
        return false;
    }
    const std::string hello_body = resp.body;
    bool peer_file_stream = false;
    {
        UniValue helloj;
        if (helloj.read(hello_body) && helloj.isObject()) {
            if (helloj.exists("full_file_stream_v1") && helloj["full_file_stream_v1"].isTrue()) peer_file_stream = true;
            if (HelloHasCapability(helloj, FULL_FILE_STREAM_V1)) peer_file_stream = true;
        }
    }
    req.method = "GET";
    req.path = std::string(MODEL_HTTP_ROOT) + "manifests/" + model_id.Hex();
    req.body.clear();
    if (!sess.Request(req, resp, err) || resp.status != 200) {
        if (err.empty()) err = "manifest failed";
        return false;
    }
    UniValue man;
    if (!man.read(resp.body) || !man.isObject()) {
        err = "manifest json";
        return false;
    }
    VerifiedManifest vm;
    if (!VerifyManifestAgainstRequest(man, model_id, vm, err)) return false;
    const Digest48 artifact = vm.artifact_id;
    if (!man.exists("files") || !man["files"].isArray()) {
        err = "manifest files";
        return false;
    }
    uint64_t total = 0;
    for (const auto& f : man["files"].getValues()) {
        if (!f.isObject() || !f.exists("size")) {
            err = "manifest file size";
            return false;
        }
        const uint64_t sz = f["size"].getInt<uint64_t>();
        if (total > std::numeric_limits<uint64_t>::max() - sz) {
            err = "quota overflow";
            return false;
        }
        total += sz;
    }
    if (!cat.EnforceQuota(total, err)) return false;
    {
        std::string ierr;
        if (!cat.InstallFromManifest(man, ierr, /*complete=*/false)) {
            err = ierr.empty() ? "manifest admission" : ierr;
            return false;
        }
    }
    {
        NativeRequest pexreq;
        NativeResponse pexresp;
        pexreq.method = "POST";
        pexreq.path = std::string(MODEL_HTTP_ROOT) + "ext/pex";
        const int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        {
            std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
            pexreq.body = g_swarm.pex.Advertise(now, PEX_MAX_RECORDS_PER_MESSAGE).write();
        }
        std::string perr;
        if (sess.Request(pexreq, pexresp, perr) && pexresp.status == 200) {
            UniValue pexj;
            if (pexj.read(pexresp.body) && pexj.isObject()) {
                std::vector<ProviderHint> acc;
                std::string ierr;
                std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
                (void)g_swarm.pex.Ingest(host + ":" + std::to_string(port), pexj, now, acc, ierr);
                for (const auto& h : acc) cat.AddPeer(h.endpoint);
            }
        }
    }

    std::vector<std::string> extras = extra_peers;
    {
        const std::string self = host + ":" + std::to_string(port);
        for (const auto& p : cat.Peers()) {
            if (p != self && std::find(extras.begin(), extras.end(), p) == extras.end()) extras.push_back(p);
        }
    }

    std::vector<std::pair<std::string, std::string>> grant_headers;
    std::mutex grant_mu;
    auto issue_grant = [&](Pq1Session& s, uint32_t file_index, std::string& gerr) -> bool {
        std::lock_guard<std::mutex> lock(grant_mu);
        NativeRequest grant_req;
        NativeResponse grant_resp;
        grant_req.method = "POST";
        grant_req.path = std::string(MODEL_HTTP_ROOT) + "ext/free/grant";
        UniValue gb(UniValue::VOBJ);
        gb.pushKV("model_id", model_id.Hex());
        gb.pushKV("artifact_id", artifact.Hex());
        gb.pushKV("file_index", static_cast<int>(file_index));
        grant_req.body = gb.write();
        if (!(s.Request(grant_req, grant_resp, gerr) && grant_resp.status == 200)) {
            if (gerr.empty()) gerr = "missing FreeGrant";
            if (grant_resp.status != 0 && grant_resp.status != 200) {
                gerr += " HTTP " + std::to_string(grant_resp.status);
            }
            return false;
        }
        UniValue gj;
        if (!gj.read(grant_resp.body) || !gj.isObject() || !gj.exists("payload_hex") ||
            !gj.exists("sig_hex") || !gj.exists("pubkey_hex")) {
            gerr = "missing FreeGrant";
            return false;
        }
        grant_headers.clear();
        grant_headers.emplace_back("X-BTX-Grant-Payload", gj["payload_hex"].get_str());
        grant_headers.emplace_back("X-BTX-Grant-Sig", gj["sig_hex"].get_str());
        grant_headers.emplace_back("X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str());
        s.piece_headers = grant_headers;
        return true;
    };
    err.clear();

    auto parse_piece = [&](const NativeResponse& presp, uint64_t size, const Digest48& pieces_root,
                            std::vector<unsigned char>& raw, std::vector<Digest48>& proof, uint64_t& hdr_size,
                            Digest48& hdr_root, std::string& local_err) -> bool {
        if (!(presp.binary || presp.content_type.find("octet-stream") != std::string::npos)) {
            local_err = "piece is not application/octet-stream (hex JSON is not a legal 4 MiB piece body)";
            return false;
        }
        raw.assign(presp.body.begin(), presp.body.end());
        hdr_size = size;
        hdr_root = pieces_root;
        const auto szs = HeaderGet(presp, "X-BTX-File-Size");
        if (!szs.empty()) {
            const uint64_t claimed = std::strtoull(szs.c_str(), nullptr, 10);
            if (claimed != size) {
                local_err = "file size mismatch";
                return false;
            }
        }
        const auto rs = HeaderGet(presp, "X-BTX-Pieces-Root");
        if (!rs.empty()) {
            Digest48 claimed;
            if (!Digest48::FromHex(rs, claimed, local_err)) return false;
            if (claimed != pieces_root) {
                local_err = "pieces root mismatch";
                return false;
            }
        }
        const auto ps = HeaderGet(presp, "X-BTX-Proof");
        proof.clear();
        if (!ps.empty()) {
            size_t start = 0;
            while (start < ps.size()) {
                const auto comma = ps.find(',', start);
                const std::string part = TrimCopy(ps.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
                Digest48 d;
                if (!Digest48::FromHex(part, d, local_err)) return false;
                proof.push_back(d);
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
        }
        return true;
    };

    std::mutex store_mu;
    auto fetch_one = [&](Pq1Session& s, uint32_t file_index, uint64_t i, uint64_t size, const Digest48& pieces_root,
                          std::vector<unsigned char>& raw, std::vector<Digest48>& proof, uint64_t& hdr_size,
                          Digest48& hdr_root, std::string& local_err) -> bool {
        std::string skip_err;
        if (cat.Store().GetPiece(artifact, file_index, static_cast<uint32_t>(i), raw, skip_err)) {
            return true;
        }
        NativeRequest preq;
        NativeResponse presp;
        preq.method = "GET";
        preq.path = std::string(MODEL_HTTP_ROOT) + "transfers/" + artifact.Hex() + "/pieces/" +
                    std::to_string(file_index) + "/" + std::to_string(i);
        {
            std::lock_guard<std::mutex> lock(grant_mu);
            if (!s.piece_headers.empty()) preq.headers = s.piece_headers;
            else preq.headers = grant_headers;
        }
        int grant_refreshes = 0;
        for (int attempt = 0; attempt < PQ1_PIECE_RETRIES; ++attempt) {
            if (stop && stop->load()) {
                local_err = "stopped";
                return false;
            }
            if (ModelWorkMayStarveExactReplay()) {
                local_err = "model work must not starve ExactReplay";
                return false;
            }
            std::this_thread::yield();
            if (s.Request(preq, presp, local_err)) {
                if (presp.status == 200 &&
                    parse_piece(presp, size, pieces_root, raw, proof, hdr_size, hdr_root, local_err)) {
                    std::lock_guard<std::mutex> lock(store_mu);
                    if (cat.PutFetchedPiece(artifact, file_index, static_cast<uint32_t>(i), raw, proof, hdr_size, hdr_root, local_err)) {
                        return true;
                    }
                } else if (presp.status == 403 && presp.body.find("expired") != std::string::npos) {
                    // FreeGrant TTL is 600s (spec cap). A 4 GiB file on a slow WAN outlives one grant.
                    if (++grant_refreshes > 64) {
                        local_err = "grant refresh limit";
                        return false;
                    }
                    if (!issue_grant(s, file_index, local_err)) return false;
                    {
                        std::lock_guard<std::mutex> lock(grant_mu);
                        preq.headers = s.piece_headers.empty() ? grant_headers : s.piece_headers;
                    }
                    --attempt;
                    continue;
                } else if (presp.status != 200) {
                    const std::string body = presp.body.size() > 240 ? presp.body.substr(0, 240) : presp.body;
                    local_err = "piece HTTP " + std::to_string(presp.status) + " " + body;
                }
            }
            if (attempt + 1 == PQ1_PIECE_RETRIES) break;
            s.Close();
            s.stop = stop;
            s.pinfile = pinfile;
            if (!s.Connect(pq, s.host.empty() ? host : s.host, s.port ? s.port : port, local_err)) return false;
            {
                std::lock_guard<std::mutex> lock(grant_mu);
                preq.headers = s.piece_headers.empty() ? grant_headers : s.piece_headers;
            }
        }
        if (local_err.empty()) local_err = "piece fetch failed";
        return false;
    };

    if (progress) {
        NoteRetrieveBytes(progress, cat.UsedBytes());
        progress->pieces_committed.store(0);
    }

    // Whole-file stream is a single-origin shortcut. A live multi-peer swarm
    // must use the piece picker (rarity, diversity, inflight). extras is the
    // additional BTX providers already known to this catalog.
    if (peer_file_stream && extras.empty()) {
        bool stream_ok = true;
        const fs::path qdir = HelperDir(cat) / "peer-hydrate-q";
        fs::create_directories(qdir);
        ModelStore quarantine(qdir, cat.QuotaBytes() ? cat.QuotaBytes() : (64ull << 20));
        uint32_t fi = 0;
        for (const auto& f : man["files"].getValues()) {
            if (!f.isObject() || !f.exists("size")) {
                stream_ok = false;
                break;
            }
            const uint64_t size = f["size"].getInt<uint64_t>();
            if (size > (64ull << 20)) {
                stream_ok = false;
                break;
            }
            std::string gerr;
            if (!issue_grant(sess, fi, gerr)) {
                stream_ok = false;
                break;
            }
            NativeRequest freq;
            NativeResponse fresp;
            freq.method = "GET";
            freq.path = std::string(MODEL_HTTP_ROOT) + "files/" + artifact.Hex() + "/" + std::to_string(fi);
            {
                std::lock_guard<std::mutex> lock(grant_mu);
                freq.headers = sess.piece_headers.empty() ? grant_headers : sess.piece_headers;
            }
            if (!sess.Request(freq, fresp, gerr) || fresp.status != 200) {
                stream_ok = false;
                break;
            }
            FileStreamHydration hyd(artifact, fi, size, cat.Store(), quarantine);
            if (f.exists("sha384") && f["sha384"].isStr()) {
                Digest48 sha;
                if (Digest48::FromHex(f["sha384"].get_str(), sha, gerr)) hyd.SetExpectedSha384(sha);
            }
            if (f.exists("pieces_root") && f["pieces_root"].isStr()) {
                Digest48 root;
                if (Digest48::FromHex(f["pieces_root"].get_str(), root, gerr)) hyd.SetExpectedPiecesRoot(root);
            }
            const auto* raw = reinterpret_cast<const unsigned char*>(fresp.body.data());
            if (!hyd.Feed(Span<const unsigned char>{raw, fresp.body.size()}, gerr) || !hyd.Finish(gerr) ||
                !hyd.IsAdvertisable()) {
                stream_ok = false;
                break;
            }
            if (progress) {
                progress->file_index.store(fi);
                NoteRetrieveBytes(progress, cat.UsedBytes());
            }
            ++fi;
        }
        if (stream_ok && fi == static_cast<uint32_t>(man["files"].getValues().size())) {
            return cat.InstallFromManifest(man, err);
        }
    }

    uint32_t file_index = 0;
    for (const auto& f : man["files"].getValues()) {
        const uint64_t size = f["size"].getInt<uint64_t>();
        Digest48 pieces_root, sha;
        if (!Digest48::FromHex(f["pieces_root"].get_str(), pieces_root, err)) return false;
        if (!Digest48::FromHex(f["sha384"].get_str(), sha, err)) return false;
        const uint64_t n = size == 0 ? 0 : (size + PIECE_SIZE - 1) / PIECE_SIZE;
        if (progress) progress->file_index.store(file_index);
        if (!issue_grant(sess, file_index, err)) return false;
        sess.Close();
        std::vector<Digest48> leaves(n);
        std::vector<uint64_t> missing;
        missing.reserve(n);
        for (uint64_t i = 0; i < n; ++i) {
            if (stop && stop->load()) {
                err = "stopped";
                return false;
            }
            std::vector<unsigned char> raw;
            std::string skip_err;
            if (cat.Store().HasPiece(artifact, file_index, static_cast<uint32_t>(i)) &&
                cat.Store().GetPiece(artifact, file_index, static_cast<uint32_t>(i), raw, skip_err)) {
                leaves[i] = ChunkLeaf(i, raw);
                if (progress) {
                    progress->piece_index.store(static_cast<uint32_t>(i));
                    progress->pieces_committed.fetch_add(1);
                    NoteRetrieveBytes(progress, cat.UsedBytes());
                }
            } else {
                missing.push_back(i);
            }
        }
        TransferSession xfer(GlobalTransferCredits());
        std::mutex committed_mu;
        std::set<uint32_t> committed_pieces;
        auto note_piece_progress = [&](uint32_t idx) {
            bool first = false;
            {
                std::lock_guard<std::mutex> lock(committed_mu);
                first = committed_pieces.insert(idx).second;
            }
            if (!first || !progress) return;
            progress->piece_index.store(idx);
            progress->pieces_committed.fetch_add(1);
            NoteRetrieveBytes(progress, cat.UsedBytes());
        };
        ThreadJoin extra_join;
        std::atomic<int> extra_ok{0};
        std::mutex rid_mu;
        std::map<uint32_t, std::vector<uint64_t>> piece_rid;
        auto remember_rid = [&](uint32_t idx, uint64_t rid) {
            piece_rid[idx].push_back(rid);
        };
        auto note_ok = [&](uint32_t idx, uint64_t useful, const std::string& winner = {}) {
            std::lock_guard<std::mutex> lock(rid_mu);
            auto it = piece_rid.find(idx);
            if (it != piece_rid.end() && !it->second.empty()) {
                xfer.NoteCommitted(it->second.front(), useful);
                for (size_t i = 1; i < it->second.size(); ++i) xfer.NoteFailed(it->second[i]);
            }
            const auto cancels = CancelAfterCommit(xfer.Outstanding(), file_index, idx, winner);
            for (const auto& a : cancels) {
                (void)a;
            }
        };
        auto note_fail = [&](uint32_t idx) {
            std::lock_guard<std::mutex> lock(rid_mu);
            auto it = piece_rid.find(idx);
            if (it != piece_rid.end()) {
                for (uint64_t rid : it->second) xfer.NoteFailed(rid);
            }
        };
        auto observe_peer_fetch = [&](const std::string& ep, bool ok, uint64_t nbytes, const std::string& local_err) {
            PeerMetrics m;
            if (ok) {
                m.throughput_bps = std::max(1.0, double(nbytes) * 8.0);
                m.completed_pieces = 1;
            } else if (local_err.find("corrupt") != std::string::npos ||
                       local_err.find("proof") != std::string::npos) {
                m.invalid_piece_count = 1;
            } else {
                m.state = PeerXferState::FAILED;
                m.timeout_count = 1;
            }
            xfer.ObservePeer(ep, m);
        };
        std::vector<SourceAvailability> sources;
        if (!missing.empty() && !extras.empty()) {
            auto add_av = [&](const std::string& eh, uint16_t eport) {
                Pq1Session av;
                av.stop = stop;
                av.pinfile = pinfile;
                std::string aerr;
                if (!av.Connect(pq, eh, eport, aerr)) return;
                NativeRequest areq;
                NativeResponse aresp;
                areq.method = "POST";
                areq.path = std::string(MODEL_HTTP_ROOT) + "availability";
                areq.body = "{}";
                if (!av.Request(areq, aresp, aerr) || aresp.status != 200) return;
                UniValue aj;
                if (!aj.read(aresp.body)) return;
                PeerId pid;
                pid.endpoint = eh + ":" + std::to_string(eport);
                pid.netgroup = eh;
                if (aj.exists("service_id") && aj["service_id"].isStr()) {
                    pid.service_id = aj["service_id"].get_str();
                }
                std::string perr;
                (void)ParseAvailabilitySources(aj, pid.endpoint, pid, artifact, sources, perr, ConnNowMs());
            };
            add_av(host, port);
            for (const auto& ep : extras) {
                std::string eh;
                uint16_t eport = 0;
                if (SplitHostPort(ep, eh, eport)) add_av(eh, eport);
            }
            std::vector<uint32_t> miss32;
            for (auto i : missing) miss32.push_back(static_cast<uint32_t>(i));
            PickConfig pcfg;
            pcfg.rng_seed = static_cast<uint32_t>(file_index + 1) * 2654435761u;
            pcfg.max_assignments = static_cast<int>(missing.size() * 2 + 1);
            pcfg.credit = &GlobalTransferCredits();
            pcfg.now_ms = ConnNowMs();
            pcfg.max_per_netgroup = 8;
            {
                const auto existing = xfer.Metrics();
                for (const auto& src : sources) {
                    if (src.peer.endpoint.empty() || existing.count(src.peer.endpoint)) continue;
                    PeerMetrics seed;
                    xfer.ObservePeer(src.peer.endpoint, seed);
                }
            }
            const auto live_metrics = xfer.Metrics();
            const auto live_out = xfer.Outstanding();
            const auto picks = PickRarestFirst(file_index, static_cast<uint32_t>(n), miss32, sources, live_metrics, live_out, {}, pcfg);
            g_swarm.current_endgame.store(EndgameActive(missing.size(), missing.size() * PIECE_SIZE, pcfg));
            {
                std::vector<uint32_t> have;
                for (uint32_t i = 0; i < static_cast<uint32_t>(n); ++i) {
                    std::vector<unsigned char> raw;
                    std::string skip_err;
                    if (cat.Store().HasPiece(artifact, file_index, i) &&
                        cat.Store().GetPiece(artifact, file_index, i, raw, skip_err)) {
                        have.push_back(i);
                    }
                }
                const auto snap = SummarizeSwarm(file_index, static_cast<uint32_t>(n), have, sources, xfer.Metrics(), pcfg);
                g_swarm.min_rarity = snap.min_piece_sources;
                g_swarm.rare_1 = snap.pieces_with_1_source;
                g_swarm.rare_2 = snap.pieces_with_2_sources;
                std::lock_guard<std::mutex> lock(g_swarm.snap_mu);
                g_swarm.last_swarm_json = SwarmSnapshotJson(snap);
            }
            std::map<std::string, std::vector<uint64_t>> by_peer;
            for (const auto& a : picks) {
                uint64_t rid = 0;
                std::string rerr;
                if (!xfer.ReserveAndQueue(a.endpoint, file_index, a.piece_index, PIECE_SIZE, rid, rerr)) continue;
                xfer.NoteSent(rid);
                {
                    std::lock_guard<std::mutex> lock(rid_mu);
                    remember_rid(a.piece_index, rid);
                }
                by_peer[a.endpoint].push_back(a.piece_index);
                if (a.endgame_duplicate) g_swarm.duplicate_endgame_requests.fetch_add(1);
            }
            const std::string self = host + ":" + std::to_string(port);
            if (!by_peer.empty()) {
                std::set<uint64_t> extra_assigned;
                for (const auto& kv : by_peer) {
                    if (kv.first == self) continue;
                    for (uint64_t p : kv.second) extra_assigned.insert(p);
                }
                std::vector<uint64_t> leftover;
                leftover.reserve(missing.size());
                for (uint64_t i : missing) {
                    if (!extra_assigned.count(i)) leftover.push_back(i);
                }
                missing.swap(leftover);
                for (const auto& kv : by_peer) {
                    if (kv.first == self) continue;
                    std::string eh;
                    uint16_t eport = 0;
                    if (!SplitHostPort(kv.first, eh, eport)) continue;
                    extra_join.threads.emplace_back([&, eh, eport, assigned = kv.second, file_index, size, pieces_root]() {
                        Pq1Session xs;
                        xs.stop = stop;
                        xs.pinfile = pinfile;
                        std::string xerr;
                        if (stop && stop->load()) {
                            xfer.Cancel();
                            return;
                        }
                        if (!xs.Connect(pq, eh, eport, xerr)) {
                            for (uint64_t i : assigned) note_fail(static_cast<uint32_t>(i));
                            PeerMetrics failm;
                            failm.state = PeerXferState::FAILED;
                            failm.timeout_count = 1;
                            xfer.ObservePeer(eh + ":" + std::to_string(eport), failm);
                            return;
                        }
                        if (!issue_grant(xs, file_index, xerr)) {
                            for (uint64_t i : assigned) note_fail(static_cast<uint32_t>(i));
                            PeerMetrics failm;
                            failm.state = PeerXferState::FAILED;
                            failm.timeout_count = 1;
                            xfer.ObservePeer(eh + ":" + std::to_string(eport), failm);
                            return;
                        }
                        for (uint64_t i : assigned) {
                            if (stop && stop->load()) {
                                xfer.Cancel();
                                return;
                            }
                            std::vector<unsigned char> raw;
                            std::vector<Digest48> proof;
                            uint64_t hs = size;
                            Digest48 hr = pieces_root;
                            if (fetch_one(xs, file_index, i, size, pieces_root, raw, proof, hs, hr, xerr)) {
                                extra_ok.fetch_add(1);
                                leaves[i] = ChunkLeaf(i, raw);
                                const std::string winner = eh + ":" + std::to_string(eport);
                                observe_peer_fetch(winner, true, raw.size(), {});
                                note_ok(static_cast<uint32_t>(i), raw.size(), winner);
                                note_piece_progress(static_cast<uint32_t>(i));
                            } else {
                                note_fail(static_cast<uint32_t>(i));
                                observe_peer_fetch(eh + ":" + std::to_string(eport), false, 0, xerr);
                            }
                        }
                    });
                }
            }
        }
        if (!missing.empty()) {
            const std::string self = host + ":" + std::to_string(port);
            for (uint64_t i : missing) {
                std::lock_guard<std::mutex> lock(rid_mu);
                if (piece_rid.count(static_cast<uint32_t>(i))) continue;
                uint64_t rid = 0;
                std::string rerr;
                if (xfer.ReserveAndQueue(self, file_index, static_cast<uint32_t>(i), PIECE_SIZE, rid, rerr)) {
                    xfer.NoteSent(rid);
                    remember_rid(static_cast<uint32_t>(i), rid);
                }
            }
            std::vector<std::unique_ptr<Pq1Session>> pool;
            for (int k = 0; k < PQ1_INFLIGHT_PIECES; ++k) {
                auto s = std::make_unique<Pq1Session>();
                s->stop = stop;
                s->pinfile = pinfile;
                std::string cerr;
                if (s->Connect(pq, host, port, cerr)) {
                    pool.push_back(std::move(s));
                } else if (pool.empty()) {
                    if (k + 1 >= 3) {
                        err = cerr.empty() ? "connect failed" : cerr;
                        return false;
                    }
                } else {
                    break;
                }
            }
            if (pool.empty()) {
                err = err.empty() ? "connect failed" : err;
                return false;
            }
            if (progress) progress->inflight.store(static_cast<int>(pool.size()));
            std::atomic<size_t> next{0};
            std::atomic<bool> fail{false};
            std::mutex err_mu;
            auto worker = [&](Pq1Session& s) {
                while (!fail.load()) {
                    const size_t slot = next.fetch_add(1);
                    if (slot >= missing.size()) return;
                    const uint64_t i = missing[slot];
                    std::vector<unsigned char> raw;
                    std::vector<Digest48> proof;
                    uint64_t hs = size;
                    Digest48 hr = pieces_root;
                    std::string local_err;
                    try {
                        if (!fetch_one(s, file_index, i, size, pieces_root, raw, proof, hs, hr, local_err)) {
                            note_fail(static_cast<uint32_t>(i));
                            observe_peer_fetch(host + ":" + std::to_string(port), false, 0, local_err);
                            std::lock_guard<std::mutex> lock(err_mu);
                            if (!fail.exchange(true)) err = local_err.empty() ? "piece fetch failed" : local_err;
                            return;
                        }
                    } catch (const std::exception& ex) {
                        note_fail(static_cast<uint32_t>(i));
                        std::lock_guard<std::mutex> lock(err_mu);
                        if (!fail.exchange(true)) err = std::string("retrieve exception: ") + ex.what();
                        return;
                    } catch (...) {
                        note_fail(static_cast<uint32_t>(i));
                        std::lock_guard<std::mutex> lock(err_mu);
                        if (!fail.exchange(true)) err = "piece thread exception";
                        return;
                    }
                    leaves[i] = ChunkLeaf(i, raw);
                    note_ok(static_cast<uint32_t>(i), raw.size(), host + ":" + std::to_string(port));
                    note_piece_progress(static_cast<uint32_t>(i));
                }
            };
            std::vector<std::thread> threads;
            for (size_t k = 1; k < pool.size(); ++k) {
                Pq1Session* ps = pool[k].get();
                threads.emplace_back([worker, ps] { worker(*ps); });
            }
            worker(*pool[0]);
            for (auto& t : threads) t.join();
            if (progress) progress->inflight.store(0);
            if (fail.load()) {
                extra_join.Join();
                bool extras_have_rest = extra_ok.load() > 0;
                if (extras_have_rest) {
                    for (uint64_t i = 0; i < n; ++i) {
                        std::vector<unsigned char> raw;
                        std::string skip_err;
                        if (cat.Store().HasPiece(artifact, file_index, static_cast<uint32_t>(i)) &&
                            cat.Store().GetPiece(artifact, file_index, static_cast<uint32_t>(i), raw, skip_err)) {
                            leaves[i] = ChunkLeaf(i, raw);
                        } else {
                            extras_have_rest = false;
                            break;
                        }
                    }
                }
                if (extras_have_rest) {
                    if (progress) progress->peer_failovers.fetch_add(1);
                    err.clear();
                } else {
                    return false;
                }
            }
        }
        extra_join.Join();
        if (n > 0) {
            std::vector<uint32_t> leftover;
            for (uint64_t i = 0; i < n; ++i) {
                std::vector<unsigned char> raw;
                std::string skip_err;
                if (cat.Store().HasPiece(artifact, file_index, static_cast<uint32_t>(i)) &&
                    cat.Store().GetPiece(artifact, file_index, static_cast<uint32_t>(i), raw, skip_err)) {
                    leaves[i] = ChunkLeaf(i, raw);
                } else {
                    leftover.push_back(static_cast<uint32_t>(i));
                }
            }
            if (!leftover.empty()) {
                const std::string self = host + ":" + std::to_string(port);
                constexpr int kPickerReschedulePasses = modelnet::kPickerReschedulePasses;
                for (int pass = 0; pass < kPickerReschedulePasses && !leftover.empty(); ++pass) {
                PickConfig pcfg2;
                pcfg2.rng_seed = static_cast<uint32_t>(file_index + 3 + pass) * 2654435761u;
                pcfg2.max_assignments = static_cast<int>(leftover.size() * 2 + 1);
                pcfg2.credit = &GlobalTransferCredits();
                pcfg2.now_ms = ConnNowMs();
                pcfg2.max_per_netgroup = 8;
                const auto picks2 = PickRarestFirst(file_index, static_cast<uint32_t>(n), leftover, sources,
                                                    xfer.Metrics(), xfer.Outstanding(), {}, pcfg2);
                std::map<std::string, std::vector<uint32_t>> extra_left;
                for (const auto& a : picks2) {
                    if (a.endpoint.empty() || a.endpoint == self) continue;
                    extra_left[a.endpoint].push_back(a.piece_index);
                    uint64_t rid = 0;
                    std::string qerr;
                    if (xfer.ReserveAndQueue(a.endpoint, file_index, a.piece_index, PIECE_SIZE, rid, qerr)) {
                        xfer.NoteSent(rid);
                        std::lock_guard<std::mutex> lock(rid_mu);
                        remember_rid(a.piece_index, rid);
                    }
                }
                ThreadJoin left_join;
                const auto classified = xfer.Metrics();
                for (const auto& kv : extra_left) {
                    std::string eh;
                    uint16_t eport = 0;
                    if (!SplitHostPort(kv.first, eh, eport)) continue;
                    auto mit = classified.find(kv.first);
                    if (mit != classified.end()) {
                        const auto st = ClassifyPeer(mit->second);
                        if (st == PeerXferState::FAILED || st == PeerXferState::SNUBBED) continue;
                    }
                    left_join.threads.emplace_back([&, eh, eport, assigned = kv.second, file_index, size, pieces_root]() {
                        Pq1Session xs;
                        xs.stop = stop;
                        xs.pinfile = pinfile;
                        std::string xerr;
                        if (!xs.Connect(pq, eh, eport, xerr)) {
                            for (uint32_t i : assigned) note_fail(i);
                            PeerMetrics failm;
                            failm.state = PeerXferState::FAILED;
                            failm.timeout_count = 1;
                            xfer.ObservePeer(eh + ":" + std::to_string(eport), failm);
                            return;
                        }
                        if (!issue_grant(xs, file_index, xerr)) {
                            for (uint32_t i : assigned) note_fail(i);
                            return;
                        }
                        for (uint32_t i : assigned) {
                            std::vector<unsigned char> raw;
                            std::vector<Digest48> proof;
                            uint64_t hs = size;
                            Digest48 hr = pieces_root;
                            if (fetch_one(xs, file_index, i, size, pieces_root, raw, proof, hs, hr, xerr)) {
                                extra_ok.fetch_add(1);
                                leaves[i] = ChunkLeaf(i, raw);
                                const std::string winner = eh + ":" + std::to_string(eport);
                                observe_peer_fetch(winner, true, raw.size(), {});
                                note_ok(i, raw.size(), winner);
                                note_piece_progress(i);
                            } else {
                                note_fail(i);
                                observe_peer_fetch(eh + ":" + std::to_string(eport), false, 0, xerr);
                            }
                        }
                    });
                }
                left_join.Join();
                std::vector<uint32_t> still;
                for (uint32_t i : leftover) {
                    std::vector<unsigned char> raw;
                    std::string skip_err;
                    if (cat.Store().HasPiece(artifact, file_index, i) &&
                        cat.Store().GetPiece(artifact, file_index, i, raw, skip_err)) {
                        leaves[i] = ChunkLeaf(i, raw);
                    } else {
                        still.push_back(i);
                    }
                }
                leftover.swap(still);
                }
                if (!leftover.empty()) {
                    Pq1Session s2;
                    s2.stop = stop;
                    s2.pinfile = pinfile;
                    std::string rerr;
                    if (s2.Connect(pq, host, port, rerr) && issue_grant(s2, file_index, rerr)) {
                        for (uint32_t i : leftover) {
                            uint64_t rid = 0;
                            std::string qerr;
                            if (xfer.ReserveAndQueue(self, file_index, i, PIECE_SIZE, rid, qerr)) {
                                xfer.NoteSent(rid);
                                std::lock_guard<std::mutex> lock(rid_mu);
                                remember_rid(i, rid);
                            }
                            std::vector<unsigned char> raw;
                            std::vector<Digest48> proof;
                            uint64_t hs = size;
                            Digest48 hr = pieces_root;
                            std::string ferr;
                            if (fetch_one(s2, file_index, i, size, pieces_root, raw, proof, hs, hr, ferr)) {
                                leaves[i] = ChunkLeaf(i, raw);
                                note_ok(i, raw.size(), self);
                                observe_peer_fetch(self, true, raw.size(), {});
                                note_piece_progress(i);
                            } else {
                                note_fail(i);
                                observe_peer_fetch(self, false, 0, ferr);
                            }
                        }
                    }
                }
                {
                    PickConfig pcfg_end;
                    pcfg_end.now_ms = ConnNowMs();
                    std::vector<uint32_t> have;
                    for (uint32_t i = 0; i < static_cast<uint32_t>(n); ++i) {
                        std::vector<unsigned char> raw;
                        std::string skip_err;
                        if (cat.Store().HasPiece(artifact, file_index, i) &&
                            cat.Store().GetPiece(artifact, file_index, i, raw, skip_err)) {
                            have.push_back(i);
                        }
                    }
                    const auto snap = SummarizeSwarm(file_index, static_cast<uint32_t>(n), have, sources,
                                                    xfer.Metrics(), pcfg_end);
                    g_swarm.min_rarity = snap.min_piece_sources;
                    g_swarm.rare_1 = snap.pieces_with_1_source;
                    g_swarm.rare_2 = snap.pieces_with_2_sources;
                    std::lock_guard<std::mutex> lock(g_swarm.snap_mu);
                    g_swarm.last_swarm_json = SwarmSnapshotJson(snap);
                }
            }
        }
        if (size > 0) {
            size_t width = 1;
            while (width < n) width <<= 1;
            for (size_t i = n; i < width; ++i) leaves.push_back(ChunkPad(i));
            PieceIndex idx;
            idx.file_size = size;
            idx.pieces_root = pieces_root;
            idx.leaves = std::move(leaves);
            if (!cat.Store().SavePieceIndex(artifact, file_index, idx, err)) return false;
            if (!cat.VerifyFileDigest(artifact, file_index, sha, err)) return false;
        }
        ++file_index;
    }
    return cat.InstallFromManifest(man, err);
}

int UnixRpcReplyTimeoutMs(const std::string& method)
{
    if (method == "waitformodelevent" || method == "importmodel" || method == "hostmodel" ||
        method == "getmodel" || method == "scanmodelwatch" || method == "executemodelimport" ||
        method == "importbtxpackage") {
        return UNIX_RPC_LONG_REPLY_MS;
    }
    return UNIX_RPC_REPLY_MS;
}

bool HelperUnixMethodIsPublicSurface(const std::string& method)
{
    return method == "getmodelnetworkinfo" || method == "getmodelcryptoinfo" ||
           method == "getbtxpackagecapabilities" || method == "getsetupstatus" ||
           method == "checkmodelsetup" || method == "getevaluatedtransport" ||
           method == "hello";
}

bool JsonLeaksPrivateLocalState(const UniValue& v)
{
    if (v.isObject()) {
        for (const auto& k : v.getKeys()) {
            if (k == "local_paths" || k == "installation_directory" || k == "independent_trust_ref" ||
                k == "wallet_seed" || k == "hf_token" || k == "HUGGING_FACE_HUB_TOKEN" ||
                k == "aws_secret_access_key" || k == "secret_access_key") {
                return true;
            }
            if (JsonLeaksPrivateLocalState(v[k])) return true;
        }
    } else if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (JsonLeaksPrivateLocalState(e)) return true;
        }
    }
    return false;
}

bool CallUnixRpc(const fs::path& socket_path, const std::string& method, const UniValue& params, UniValue& result, std::string& err)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "unix socket";
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::string p = fs::PathToString(socket_path);
    if (p.size() >= sizeof(addr.sun_path)) {
        err = "unix path too long";
        close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "helper unix connect failed (btx-modeld not running)";
        close(fd);
        return false;
    }
    UniValue req(UniValue::VOBJ);
    req.pushKV("jsonrpc", "1.0");
    req.pushKV("id", "model");
    req.pushKV("method", method);
    req.pushKV("params", params);
    const std::string wire = req.write() + "\n";
    if (::send(fd, wire.data(), wire.size(), 0) < 0) {
        err = "unix write";
        close(fd);
        return false;
    }
    ::shutdown(fd, SHUT_WR);
    const std::string raw = RecvUntil(fd, MAX_RPC_BODY, nullptr, UnixRpcReplyTimeoutMs(method));
    close(fd);
    UniValue reply;
    if (!reply.read(raw) || !reply.isObject()) {
        err = "helper reply json";
        return false;
    }
    if (reply.exists("error") && !reply["error"].isNull()) {
        err = reply["error"].write();
        return false;
    }
    result = reply["result"];
    return true;
}

namespace {

void HandleUnixFd(int cfd, ModelCatalog& cat, std::atomic<bool>* stop)
{
    const std::string raw = RecvUntil(cfd, MAX_RPC_BODY, stop);
    std::string body = raw;
    NativeRequest http;
    std::string perr;
    if (raw.rfind("POST", 0) == 0 || raw.rfind("GET", 0) == 0) {
        if (ParseHttpRequest(raw, http, perr)) body = http.body;
    }
    UniValue req;
    UniValue reply(UniValue::VOBJ);
    reply.pushKV("jsonrpc", "1.0");
    if (!req.read(body)) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("code", "PARSE");
        e.pushKV("message", "invalid json");
        reply.pushKV("result", UniValue::VNULL);
        reply.pushKV("error", e);
    } else {
        if (req.exists("id")) reply.pushKV("id", req["id"]);
        UniValue result;
        std::string code, emsg;
        const std::string method = req.exists("method") && req["method"].isStr() ? req["method"].get_str() : "";
        if (DispatchHelperRpc(cat, req, result, code, emsg, stop)) {
            if (HelperUnixMethodIsPublicSurface(method) && JsonLeaksPrivateLocalState(result)) {
                UniValue e(UniValue::VOBJ);
                e.pushKV("code", "PRIVATE_STATE_DENIED");
                e.pushKV("message", "public unix surface must not leak private local state");
                reply.pushKV("result", UniValue::VNULL);
                reply.pushKV("error", e);
            } else {
                reply.pushKV("result", result);
                reply.pushKV("error", UniValue::VNULL);
            }
        } else {
            UniValue e(UniValue::VOBJ);
            e.pushKV("code", code);
            e.pushKV("message", emsg);
            e.pushKV("schema_version", 2);
            reply.pushKV("result", UniValue::VNULL);
            reply.pushKV("error", e);
        }
    }
    const std::string out = reply.write() + "\n";
    ::send(cfd, out.data(), out.size(), 0);
    close(cfd);
}

void HandlePq1Fd(int cfd, ModelCatalog& cat, Pq1Context& pq, std::atomic<bool>* stop, const fs::path& pinfile, uint32_t netgroup)
{
    SetPq1SocketOpts(cfd, true);
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(pq.SslCtx()));
    if (!ssl) {
        close(cfd);
        return;
    }
    SSL_set_fd(ssl, cfd);
    SSL_set_accept_state(ssl);
    std::string err;
    if (!SslHandshake(ssl, cfd, /*accept=*/true, PQ1_HANDSHAKE_MS, stop, err)) {
        CountUnauthAndBump(netgroup);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    NegotiatedPq1 n;
    InspectNegotiated(ssl, n);
    if (!IsStrictPq1(n)) {
        CountUnauthAndBump(netgroup);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    Digest48 pin;
    if (!ExtractPeerTransportPin(ssl, pin, err)) {
        CountUnauthAndBump(netgroup);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cfd);
        return;
    }
    (void)pin;
    (void)pinfile;
    // Inbound TOFU must not be keyed by IPv4 netgroup: every researcher
    // behind one NAT would collide and the server would close after
    // handshake (client sees truncated HTTP). Outbound clients still pin
    // host:port in Pq1Session::Connect.
    ClearUnauth(netgroup);
    for (;;) {
        if (stop && stop->load()) break;
        const std::string raw = SslReadHttp(ssl, cfd, MAX_RPC_BODY + 8192, PQ1_IDLE_MS, stop);
        if (raw.empty()) break;
        NativeRequest nreq;
        NativeResponse nresp;
        if (!ParseHttpRequest(raw, nreq, err)) {
            nresp.status = 400;
            nresp.body = JsonError("BAD_HTTP", err);
        } else {
            try {
                HandleNativeRequest(cat, nreq, nresp);
            } catch (const std::exception&) {
                nresp = {};
                nresp.status = 400;
                nresp.content_type = "application/json";
                nresp.body = JsonError("BAD_JSON", "malformed request fields");
            }
        }
        const int wto = (nreq.path.find("/pieces/") != std::string::npos || nresp.stream_verified_file)
                            ? PQ1_TRANSFER_MS : PQ1_IDLE_MS;
        if (!SslWriteAll(ssl, cfd, FormatHttpResponse(nresp), wto, stop, err)) break;
        if (nresp.stream_verified_file && nresp.body.empty() && nresp.status == 200 && nresp.stream_n_pieces > 0) {
            uint64_t sent = 0;
            bool stream_ok = true;
            for (uint32_t i = 0; i < nresp.stream_n_pieces; ++i) {
                if (stop && stop->load()) {
                    stream_ok = false;
                    break;
                }
                std::vector<unsigned char> bytes;
                std::vector<Digest48> proof;
                uint64_t fs = 0;
                std::string serr;
                if (!cat.GetVerifiedPiece(nresp.stream_artifact, nresp.stream_file_index, i, bytes, proof, fs, serr)) {
                    stream_ok = false;
                    break;
                }
                if (!AllowModelSeedBytes(cat, bytes.size())) {
                    stream_ok = false;
                    break;
                }
                if (!SslWriteAll(ssl, cfd, std::string(bytes.begin(), bytes.end()), PQ1_TRANSFER_MS, stop, err)) {
                    stream_ok = false;
                    break;
                }
                sent += bytes.size();
            }
            if (sent > 0) {
                std::string nerr;
                (void)cat.NoteUsefulBytes(nresp.stream_artifact, static_cast<int64_t>(sent), 0, nerr);
            }
            if (!stream_ok || sent != nresp.stream_file_size) break;
        }
        if (nresp.splice_tcp && !nresp.splice_host.empty() && nresp.splice_port) {
            int dfd = -1;
            addrinfo hints{};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family = AF_UNSPEC;
            addrinfo* res = nullptr;
            if (getaddrinfo(nresp.splice_host.c_str(), std::to_string(nresp.splice_port).c_str(), &hints, &res) == 0 && res) {
                dfd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (dfd >= 0 && ::connect(dfd, res->ai_addr, res->ai_addrlen) != 0) {
                    close(dfd);
                    dfd = -1;
                }
                freeaddrinfo(res);
            }
            if (dfd >= 0) {
                SetPq1SocketOpts(dfd, true);
                uint64_t moved = 0;
                while (!stop || !stop->load()) {
                    if (moved > (uint64_t{1} << 30)) break;
                    pollfd pf[2]{};
                    pf[0].fd = cfd;
                    pf[0].events = POLLIN;
                    pf[1].fd = dfd;
                    pf[1].events = POLLIN;
                    const int pr = poll(pf, 2, 15000);
                    if (pr <= 0) break;
                    unsigned char buf[16384];
                    if (pf[0].revents & POLLIN) {
                        const int n = SSL_read(ssl, buf, sizeof(buf));
                        if (n <= 0) break;
                        if (::send(dfd, buf, n, 0) != n) break;
                        moved += static_cast<uint64_t>(n);
                    }
                    if (pf[1].revents & POLLIN) {
                        const int n = ::recv(dfd, buf, sizeof(buf), 0);
                        if (n <= 0) break;
                        if (SSL_write(ssl, buf, n) != n) break;
                        moved += static_cast<uint64_t>(n);
                    }
                }
                close(dfd);
            }
            break;
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
}

struct WorkerJob {
    int fd{-1};
    bool unix_rpc{false};
    uint32_t netgroup{0};
};

} // namespace

static PreservationPolicy PolicyFromConfig(const HelperConfig& cfg)
{
    PreservationPolicy p;
    p.storage_quota_bytes = cfg.quota_bytes;
    if (!SeedModeFromName(cfg.seed, p.seed_mode)) p.seed_mode = SeedMode::AUTO;
    p.seed_upon_download = p.seed_mode == SeedMode::AUTO;
    p.preserve_rare = cfg.preserve_rare;
    p.follow_configured_peers = cfg.follow_peers;
    p.allow_encrypted = cfg.allow_encrypted;
    p.upload_bps = cfg.upload_bps;
    return p;
}

static bool CatalogHasVerifiedSeededRange(const ModelCatalog& cat)
{
    UniValue lst;
    if (!cat.List(lst) || !lst.exists("models") || !lst["models"].isArray()) return false;
    for (const auto& m : lst["models"].getValues()) {
        const bool seeded = m.exists("seeded") && m["seeded"].isBool() && m["seeded"].get_bool();
        const bool verified = m.exists("bytes_verified") && m["bytes_verified"].isBool() && m["bytes_verified"].get_bool();
        if (seeded && verified) return true;
    }
    return false;
}

static void RefreshAdvertisedHost(const ModelCatalog* cat)
{
    const uint64_t storage = g_runtime.effective_quota ? g_runtime.effective_quota :
                            (cat ? cat->QuotaBytes() : 0);
    const bool loopback = g_swarm.nat.status == ModelNatStatus::LOOPBACK;
    const bool host = g_swarm.host;
    const bool reach = g_swarm.reach.MayAdvertiseHost(host) ||
                        MayAdvertiseModelHost(host, g_runtime.public_host_reachable, loopback);
    const bool seeded = cat && CatalogHasVerifiedSeededRange(*cat);
    g_runtime.advertised_host = AutoHostShouldAdvertise(true, true, storage, seeded, reach);
    SetNodeModelHostAdvertised(g_runtime.advertised_host);
}

static void RefreshAutoStorage(HelperConfig& cfg, ModelCatalog* cat)
{
    g_runtime.storage_mode = cfg.storage_mode;
    g_runtime.demand_seed = cfg.seed == "auto";
    g_runtime.preserve_rare = cfg.preserve_rare;
    g_runtime.follow_peers = cfg.follow_peers;
    g_runtime.upload_bps = cfg.upload_bps;
    g_runtime.watch_dir = fs::PathToString(cfg.watch_dir);
    g_runtime.public_host_reachable = cfg.public_host_reachable;
    g_swarm.host = cfg.host;
    if (cfg.storage_mode == StorageMode::DISABLED) {
        cfg.quota_bytes = 0;
        g_runtime.effective_quota = 0;
        g_runtime.target_bytes = 0;
        if (cat) cat->SetQuotaBytes(0);
        RefreshAdvertisedHost(cat);
        return;
    }
    if (cfg.storage_mode == StorageMode::FIXED) {
        g_runtime.effective_quota = cfg.quota_bytes;
        g_runtime.target_bytes = cfg.quota_bytes;
        if (cat) cat->SetQuotaBytes(cfg.quota_bytes);
        RefreshAdvertisedHost(cat);
        return;
    }
    AutoStorageParams p;
    if (cfg.auto_cap_bytes) p.max_auto = cfg.auto_cap_bytes;
    if (cfg.free_space_reserve_bytes) p.reserve_override = cfg.free_space_reserve_bytes;
    FsStats fs;
    std::string err;
    if (!StatFilesystem(cfg.modeldir, fs, err)) {
        fs = {};
    }
    const AutoQuotaResult q = ComputeAutoQuota(fs, p);
    cfg.quota_bytes = q.effective_bytes;
    g_runtime.fs_capacity = fs.capacity;
    g_runtime.fs_available = fs.available;
    g_runtime.reserve_bytes = q.reserve_bytes;
    g_runtime.target_bytes = q.target_bytes;
    g_runtime.effective_quota = q.effective_bytes;
    if (cat) {
        cat->SetQuotaBytes(q.effective_bytes);
        std::string qerr;
        if (cat->UsedBytes() > q.effective_bytes) {
            (void)cat->EnforceQuota(0, qerr);
        }
    }
    RefreshAdvertisedHost(cat);
}

static void GossipPexOnSession(Pq1Session& sess, ModelCatalog& cat, const std::string& endpoint)
{
    NativeRequest pexreq;
    NativeResponse pexresp;
    pexreq.method = "POST";
    pexreq.path = std::string(MODEL_HTTP_ROOT) + "ext/pex";
    const int64_t now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    {
        std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
        pexreq.body = g_swarm.pex.Advertise(now, PEX_MAX_RECORDS_PER_MESSAGE).write();
    }
    std::string perr;
    if (!sess.Request(pexreq, pexresp, perr) || pexresp.status != 200) return;
    UniValue pexj;
    if (!pexj.read(pexresp.body) || !pexj.isObject()) return;
    std::vector<ProviderHint> acc;
    std::string ierr;
    {
        std::lock_guard<std::mutex> lock(g_swarm.pex_mu);
        (void)g_swarm.pex.Ingest(endpoint, pexj, now, acc, ierr);
        g_swarm.pex_received.store(g_swarm.pex.Stats().received);
        g_swarm.pex_accepted.store(g_swarm.pex.Stats().accepted);
        g_swarm.providers_known = static_cast<int>(g_swarm.pex.Recent(now).size());
    }
    for (const auto& h : acc) {
        if (!h.endpoint.empty()) cat.AddPeer(h.endpoint);
    }
}

static void TryPreserveRareTick(ModelCatalog& cat, Pq1Context& pq, const fs::path& pinfile, std::atomic<bool>* stop)
{
    const auto pol = cat.Policy();
    const bool follow = pol.follow_configured_peers && pol.seed_mode == SeedMode::AUTO && pol.storage_quota_bytes > 0;
    const bool rare = pol.preserve_rare && PreservationPermitted(cat);
    if (!follow && !rare) return;
    const uint64_t spare = pol.storage_quota_bytes > cat.UsedBytes() ? pol.storage_quota_bytes - cat.UsedBytes() : 0;
    if (spare == 0) return;
    RefreshLocalPex(cat);
    std::set<Digest48> local;
    UniValue listed;
    cat.List(listed);
    if (listed.exists("models")) {
        for (const auto& m : listed["models"].getValues()) {
            Digest48 id;
            std::string e;
            if (m.exists("model_id") && Digest48::FromHex(m["model_id"].get_str(), id, e)) local.insert(id);
        }
    }
    {
        UniValue comm;
        ReadJsonFile(HelperDir(cat) / "community.json", comm);
        if (comm.exists("stopped_preservation")) {
            for (const auto& x : comm["stopped_preservation"].getValues()) {
                if (!x.isStr()) continue;
                local.insert(CommunityLocalId(x.get_str()));
            }
        }
    }
    std::map<std::string, PreserveCandidate> seen;
    const std::vector<std::string> peers = cat.Peers();
    if (peers.empty()) return;
    static std::atomic<size_t> peer_cursor{0};
    const size_t n = peers.size();
    const size_t visit = std::min(n, PEX_MAX_RECORDS_PER_MESSAGE);
    const size_t start = peer_cursor.fetch_add(visit) % n;
    for (size_t i = 0; i < visit; ++i) {
        const std::string& endpoint = peers[(start + i) % n];
        if (stop && stop->load()) return;
        std::string host;
        uint16_t port = 0;
        if (!SplitHostPort(endpoint, host, port)) continue;
        Pq1Session sess;
        std::string err;
        sess.stop = stop;
        sess.pinfile = pinfile;
        if (!sess.Connect(pq, host, port, err)) continue;
        NativeRequest req;
        NativeResponse resp;
        req.method = "POST";
        req.path = std::string(MODEL_HTTP_ROOT) + "availability";
        req.body = "{}";
        if (!sess.Request(req, resp, err) || resp.status != 200) continue;
        GossipPexOnSession(sess, cat, endpoint);
        UniValue body;
        if (!body.read(resp.body) || !body.isObject()) continue;
        const UniValue models = (body.exists("local") && body["local"].exists("models")) ? body["local"]["models"] : UniValue(UniValue::VARR);
        for (const auto& m : models.getValues()) {
            if (!m.exists("model_id") || !m.exists("seeded") || !m["seeded"].get_bool()) continue;
            Digest48 id;
            std::string e;
            if (!Digest48::FromHex(m["model_id"].get_str(), id, e)) continue;
            const std::string adm = (m.exists("admission") && m["admission"].isStr()) ? m["admission"].get_str() : "";
            if (adm == "FAILED" || adm == "NOT_RUN_RESOURCE_LIMIT") continue;
            const std::string key = id.Hex();
            if (seen.count(key)) {
                seen[key].observed_sources += 1;
                continue;
            }
            PreserveCandidate c;
            c.model_id = id;
            c.bytes = m.exists("bytes") ? m["bytes"].getInt<uint64_t>() : 0;
            c.observed_sources = 1;
            c.peer = endpoint;
            c.admission = AdmissionLevel::BYTES_VERIFIED;
            c.encrypted = (adm == "ENCRYPTED_UNQUALIFIED");
            seen[key] = c;
        }
    }
    std::vector<PreserveCandidate> observed;
    observed.reserve(seen.size());
    for (auto& kv : seen) observed.push_back(kv.second);
    PreserveCandidate pick;
    bool got = false;
    if (follow) {
        got = SelectPeerFollow(observed, local, spare, pol, pick);
    }
    if (!got && rare) {
        got = SelectPreserveRare(observed, local, spare, pol, pick, static_cast<int64_t>(std::time(nullptr)));
    }
    if (!got) return;
    std::string host;
    uint16_t port = 0;
    std::string err;
    if (!SplitHostPort(pick.peer, host, port)) return;
    if (!cat.EnforceQuota(pick.bytes, err)) return;
    if (RetrieveFreeFromPeer(cat, pq, host, port, pick.model_id, err, stop, pinfile)) {
        cat.ApplyDemandSeed(pick.model_id, err);
    }
}

int RunModelDaemon(HelperConfig cfg, std::atomic<bool>* stop)
{
    std::signal(SIGPIPE, SIG_IGN);
    std::atomic<bool> local_stop{false};
    if (!stop) stop = &local_stop;
    fs::create_directories(cfg.modeldir);
    if (cfg.rpc_socket.empty()) cfg.rpc_socket = cfg.modeldir / "modeld.sock";
    if (cfg.tls_cert.empty()) cfg.tls_cert = cfg.modeldir / "tls" / "cert.pem";
    if (cfg.tls_key.empty()) cfg.tls_key = cfg.modeldir / "tls" / "key.pem";
    cfg.public_host_reachable = false;
    RefreshAutoStorage(cfg, nullptr);

    Pq1Context pq;
    if (!pq.Ready()) {
        std::cerr << "model subsystem fail-closed: strict PQ1 unavailable: " << pq.Error() << "\n";
        std::cerr << "monetary BTX remains independently operational.\n";
        return 2;
    }
    std::string err;
    if (!EnsureMlDsaTlsFiles(cfg.tls_cert, cfg.tls_key, err)) {
        std::cerr << "model subsystem fail-closed: " << err << "\n";
        return 2;
    }
    std::ifstream cf(cfg.tls_cert), kf(cfg.tls_key);
    const std::string cert_pem((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    const std::string key_pem((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
    if (!pq.LoadSelfSignedMlDsa(cert_pem, key_pem, err)) {
        std::cerr << "model subsystem fail-closed: " << err << "\n";
        return 2;
    }

    ModelCatalog cat(cfg.modeldir, cfg.quota_bytes);
    BindModelEventLayer(cfg.modeldir);
    EnsureCloudLoaded(cat);
    LoadRetrieveJobs(cat);
    StartRetrieveWorkers(cat);
    RefreshAutoStorage(cfg, &cat);
    for (const auto& p : cfg.peers) cat.AddPeer(p);
    cat.SetPolicy(PolicyFromConfig(cfg));
    {
        std::string perr;
        WriteJsonFile(cfg.modeldir / "policy.json", PolicyToJson(cat.Policy()), perr);
        std::vector<unsigned char> pk, sk;
        Digest48 publisher_id;
        (void)EnsureDefaultPublisherIdentity(cfg.modeldir, pk, sk, publisher_id, perr);
    }
    const int unix_fd = ListenUnix(cfg.rpc_socket, err);
    if (unix_fd < 0) {
        std::cerr << err << "\n";
        return 2;
    }
    int tcp_fd = -1;
    if (!cfg.bind.empty()) {
        tcp_fd = ListenTcp(cfg.bind, err);
        if (tcp_fd < 0) {
            std::cerr << "btx-modeld: PQ1 bind " << cfg.bind << " failed (" << err
                      << "); unix RPC continues, hosting stays NAT-limited\n";
            cfg.public_host_reachable = false;
            tcp_fd = -1;
            err.clear();
        }
    }
    g_swarm.bind = cfg.bind;
    g_swarm.relay = cfg.relay;
    g_swarm.host = cfg.host;
    g_swarm.pex.NoteSelf(cfg.bind);
    if (tcp_fd >= 0) {
        g_swarm.nat = AttemptModelPortMap(cfg.bind, true);
        const bool mapped = g_swarm.nat.status == ModelNatStatus::MAPPED;
        cfg.public_host_reachable = mapped;
        g_runtime.public_host_reachable = mapped;
        g_swarm.reach.SetListen(cfg.bind);
        if (mapped) g_swarm.reach.SetMapped(g_swarm.nat.external);
        RefreshAdvertisedHost(&cat);
    } else {
        g_swarm.nat.status = ModelNatStatus::DISABLED;
        cfg.public_host_reachable = false;
        RefreshAdvertisedHost(&cat);
    }
    const fs::path pinfile = cfg.modeldir / "tls" / "pins.json";
    std::mutex qmu;
    std::condition_variable qcv;
    std::queue<WorkerJob> jobs;
    auto enqueue = [&](WorkerJob job) -> bool {
        std::unique_lock<std::mutex> lock(qmu);
        if (jobs.size() >= static_cast<size_t>(PQ1_HTTP_QUEUE)) return false;
        jobs.push(job);
        qcv.notify_one();
        return true;
    };
    std::vector<std::thread> workers;
    workers.reserve(PQ1_HTTP_WORKERS);
    for (int i = 0; i < PQ1_HTTP_WORKERS; ++i) {
        workers.emplace_back([&] {
            while (!stop->load()) {
                WorkerJob job;
                {
                    std::unique_lock<std::mutex> lock(qmu);
                    qcv.wait_for(lock, std::chrono::milliseconds(250), [&] { return !jobs.empty() || stop->load(); });
                    if (jobs.empty()) continue;
                    job = jobs.front();
                    jobs.pop();
                }
                if (job.fd < 0) continue;
                if (job.unix_rpc) HandleUnixFd(job.fd, cat, stop);
                else {
                    HandlePq1Fd(job.fd, cat, pq, stop, pinfile, job.netgroup);
                    GlobalConnLimits().ReleaseInbound(job.netgroup);
                }
            }
        });
    }
    std::cout << "btx-modeld: PQ1 ready; unix=" << fs::PathToString(cfg.rpc_socket)
              << " storage=" << StorageModeName(cfg.storage_mode)
              << " quota=" << cfg.quota_bytes
              << " seed=" << cfg.seed
              << " preserve_rare=" << (cfg.preserve_rare ? "1" : "0")
              << " follow_peers=" << (cfg.follow_peers ? "1" : "0")
              << " automatic_spend=0"
              << " workers=" << PQ1_HTTP_WORKERS
              << (cfg.bind.empty() ? "" : " bind=" + cfg.bind)
              << (cfg.relay ? " relay" : "")
              << (cfg.host ? " host" : "")
              << (cfg.watch_dir.empty() ? "" : " watch=" + fs::PathToString(cfg.watch_dir))
              << "\n";
    std::cout.flush();

    // Preserve-rare: first tick immediately, then every 5s (fail-fast e2e; not a 60s stall).
    auto last_preserve = std::chrono::steady_clock::now() - std::chrono::seconds(5);
    auto last_quota = std::chrono::steady_clock::now();
    auto last_watch = std::chrono::steady_clock::now() - std::chrono::seconds(5);
    while (!stop->load()) {
        pollfd fds[2]{};
        nfds_t nf = 1;
        fds[0].fd = unix_fd;
        fds[0].events = POLLIN;
        if (tcp_fd >= 0) {
            fds[1].fd = tcp_fd;
            fds[1].events = POLLIN;
            nf = 2;
        }
        const int pr = poll(fds, nf, 250);
        if (cfg.storage_mode == StorageMode::AUTO &&
            std::chrono::steady_clock::now() - last_quota >= std::chrono::seconds(60)) {
            RefreshAutoStorage(cfg, &cat);
            last_quota = std::chrono::steady_clock::now();
        }
        if ((cat.Policy().preserve_rare ||
             (cat.Policy().follow_configured_peers && cat.Policy().seed_mode == SeedMode::AUTO)) &&
            std::chrono::steady_clock::now() - last_preserve >= std::chrono::seconds(5)) {
            TryPreserveRareTick(cat, pq, pinfile, stop);
            last_preserve = std::chrono::steady_clock::now();
        }
        if (!g_runtime.watch_dir.empty() &&
            std::chrono::steady_clock::now() - last_watch >= std::chrono::seconds(5)) {
            UniValue wres;
            std::string werr;
            ScanWatchDir(cat, wres, werr);
            last_watch = std::chrono::steady_clock::now();
        }
        if (pr <= 0) continue;
        if (fds[0].revents & POLLIN) {
            const int c = accept(unix_fd, nullptr, nullptr);
            if (c >= 0) {
                WorkerJob job;
                job.fd = c;
                job.unix_rpc = true;
                if (!enqueue(job)) close(c);
            }
        }
        if (tcp_fd >= 0 && (fds[1].revents & POLLIN)) {
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const int c = accept(tcp_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (c >= 0) {
                const uint32_t ng = Ipv4Netgroup(reinterpret_cast<sockaddr*>(&peer), plen);
                if (UnauthCount(ng) >= PQ1_UNAUTH_HANDSHAKE_LIMIT) {
                    close(c);
                    continue;
                }
                if (!GlobalConnLimits().TryInbound(ng)) {
                    close(c);
                    continue;
                }
                WorkerJob job;
                job.fd = c;
                job.unix_rpc = false;
                job.netgroup = ng;
                if (!enqueue(job)) {
                    GlobalConnLimits().ReleaseInbound(ng);
                    close(c);
                }
            }
        }
    }
    qcv.notify_all();
    for (auto& w : workers) w.join();
    JoinRetrieveJobs();
    close(unix_fd);
    if (tcp_fd >= 0) close(tcp_fd);
    ReleaseModelPortMap(g_swarm.nat);
    ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    return 0;
}

} // namespace modelnet
