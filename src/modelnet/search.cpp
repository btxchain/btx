// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/search.h>

#include <crypto/common.h>
#include <modelnet/crypto.h>
#include <modelnet/resource_uri.h>
#include <random.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace modelnet {
namespace {

void PutU16(std::vector<unsigned char>& b, uint16_t v)
{
    unsigned char t[2];
    WriteLE16(t, v);
    b.insert(b.end(), t, t + 2);
}
void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    unsigned char t[8];
    WriteLE64(t, v);
    b.insert(b.end(), t, t + 8);
}
void PutI64(std::vector<unsigned char>& b, int64_t v)
{
    PutU64(b, static_cast<uint64_t>(v));
}
void PutStr(std::vector<unsigned char>& b, const std::string& s)
{
    // AUTH-011: never collapse an oversize suffix into a colliding empty prefix.
    // ValidateSearchRecord rejects strings above SEARCH_SIGNED_STR_MAX before Sign/Verify.
    CHECK_NONFATAL(s.size() <= SEARCH_SIGNED_STR_MAX);
    PutU16(b, static_cast<uint16_t>(s.size()));
    b.insert(b.end(), s.begin(), s.end());
}
void PutStrList(std::vector<unsigned char>& b, const std::vector<std::string>& v)
{
    CHECK_NONFATAL(v.size() <= 65535);
    PutU16(b, static_cast<uint16_t>(v.size()));
    for (const auto& s : v) PutStr(b, s);
}

bool FieldHas(const std::vector<std::string>& v, const std::string& n)
{
    const std::string x = NormalizeSearchText(n);
    for (const auto& e : v) {
        if (NormalizeSearchText(e) == x) return true;
    }
    return false;
}

} // namespace

const char* SearchScopeName(SearchScope s)
{
    switch (s) {
    case SearchScope::LOCAL: return "LOCAL";
    case SearchScope::PEERS: return "PEERS";
    case SearchScope::ALL: return "ALL";
    case SearchScope::NETWORK:
    default: return "NETWORK";
    }
}
const char* SearchSortName(SearchSort s)
{
    switch (s) {
    case SearchSort::AVAILABILITY: return "AVAILABILITY";
    case SearchSort::NEWEST: return "NEWEST";
    case SearchSort::OLDEST: return "OLDEST";
    case SearchSort::SIZE_ASC: return "SIZE_ASC";
    case SearchSort::SIZE_DESC: return "SIZE_DESC";
    case SearchSort::PROVIDERS: return "PROVIDERS";
    case SearchSort::RARITY: return "RARITY";
    case SearchSort::PUBLISHER: return "PUBLISHER";
    case SearchSort::NAME: return "NAME";
    case SearchSort::NEWEST_RELEASES: return "NEWEST_RELEASES";
    case SearchSort::RECENTLY_UNLOCKED: return "RECENTLY_UNLOCKED";
    case SearchSort::NEARLY_FUNDED: return "NEARLY_FUNDED";
    case SearchSort::MOST_FUNDED: return "MOST_FUNDED";
    case SearchSort::MOST_FUNDING_NEEDED: return "MOST_FUNDING_NEEDED";
    case SearchSort::RAREST_AVAILABLE: return "RAREST_AVAILABLE";
    case SearchSort::TRENDING: return "TRENDING";
    case SearchSort::RELEVANCE:
    default: return "RELEVANCE";
    }
}
const char* AvailabilityClassName(AvailabilityClass k)
{
    switch (k) {
    case AvailabilityClass::EXCELLENT: return "EXCELLENT";
    case AvailabilityClass::HIGH: return "HIGH";
    case AvailabilityClass::MEDIUM: return "MEDIUM";
    case AvailabilityClass::FRAGILE: return "FRAGILE";
    case AvailabilityClass::DEGRADED: return "DEGRADED";
    case AvailabilityClass::UNKNOWN:
    default: return "UNKNOWN";
    }
}
bool ParseSearchScope(const std::string& s, SearchScope& out)
{
    const std::string x = ToLower(s);
    if (x == "local") { out = SearchScope::LOCAL; return true; }
    if (x == "peers") { out = SearchScope::PEERS; return true; }
    if (x == "all") { out = SearchScope::ALL; return true; }
    if (x == "network" || x.empty()) { out = SearchScope::NETWORK; return true; }
    return false;
}
bool ParseSearchSort(const std::string& s, SearchSort& out)
{
    const std::string x = ToLower(s);
    if (x == "availability" || x == "available") { out = SearchSort::AVAILABILITY; return true; }
    if (x == "newest") { out = SearchSort::NEWEST; return true; }
    if (x == "oldest") { out = SearchSort::OLDEST; return true; }
    if (x == "size_asc") { out = SearchSort::SIZE_ASC; return true; }
    if (x == "size_desc") { out = SearchSort::SIZE_DESC; return true; }
    if (x == "providers" || x == "popular") { out = SearchSort::PROVIDERS; return true; }
    if (x == "rarity" || x == "rare") { out = SearchSort::RARITY; return true; }
    if (x == "publisher") { out = SearchSort::PUBLISHER; return true; }
    if (x == "name") { out = SearchSort::NAME; return true; }
    if (x == "newest_releases") { out = SearchSort::NEWEST_RELEASES; return true; }
    if (x == "recently_unlocked") { out = SearchSort::RECENTLY_UNLOCKED; return true; }
    if (x == "nearly_funded") { out = SearchSort::NEARLY_FUNDED; return true; }
    if (x == "most_funded") { out = SearchSort::MOST_FUNDED; return true; }
    if (x == "most_funding_needed" || x == "most_needed") { out = SearchSort::MOST_FUNDING_NEEDED; return true; }
    if (x == "rarest_available") { out = SearchSort::RAREST_AVAILABLE; return true; }
    if (x == "trending") { out = SearchSort::TRENDING; return true; }
    if (x == "relevance" || x.empty()) { out = SearchSort::RELEVANCE; return true; }
    return false;
}

std::string NormalizeSearchText(const std::string& in)
{
    std::string o;
    o.reserve(in.size());
    bool sp = false;
    for (unsigned char c : in) {
        if (std::isalnum(c) || static_cast<unsigned char>(c) >= 0x80) {
            o.push_back(static_cast<char>(std::tolower(c)));
            sp = false;
        } else if (!sp) {
            o.push_back(' ');
            sp = true;
        }
    }
    while (!o.empty() && o.front() == ' ') o.erase(o.begin());
    while (!o.empty() && o.back() == ' ') o.pop_back();
    return o;
}

std::vector<std::string> TokenizeSearch(const std::string& in)
{
    std::vector<std::string> t;
    std::string n = NormalizeSearchText(in);
    std::string cur;
    for (char c : n) {
        if (c == ' ') {
            if (!cur.empty() && t.size() < SEARCH_TERMS_MAX) t.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if (!cur.empty() && t.size() < SEARCH_TERMS_MAX) t.push_back(cur);
    return t;
}

bool SearchRecordHasAuthoredMetadata(const ModelSearchRecord& r)
{
    if (r.signed_ok) return true;
    if (!r.release_id.empty()) return true;
    if (!r.family.empty() || !r.architecture.empty() || !r.format.empty() ||
        !r.quantization.empty() || !r.short_description.empty() ||
        !r.publisher_display_name.empty()) {
        return true;
    }
    if (!r.tags.empty() || !r.aliases.empty() || !r.languages.empty() || !r.modalities.empty()) {
        return true;
    }
    return r.parameter_count > 0;
}

bool ValidateSearchRecord(const ModelSearchRecord& r, std::string& err)
{
    auto too_long = [&](const std::string& s, size_t max, const char* what) {
        if (s.size() > max) {
            err = what;
            return true;
        }
        return false;
    };
    if (too_long(r.display_name, SEARCH_NAME_MAX, "name too long") ||
        too_long(r.canonical_name, SEARCH_NAME_MAX, "name too long") ||
        too_long(r.family, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.architecture, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.format, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.quantization, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.publisher_display_name, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.btx_uri, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.release_id, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.release_state, SEARCH_SIGNED_STR_MAX, "string too long") ||
        too_long(r.assurance, SEARCH_SIGNED_STR_MAX, "string too long")) {
        return false;
    }
    if (r.aliases.size() > SEARCH_ALIASES_MAX) {
        err = "too many aliases";
        return false;
    }
    for (const auto& a : r.aliases) {
        if (a.size() > SEARCH_ALIAS_MAX) {
            err = "alias too long";
            return false;
        }
    }
    if (r.tags.size() > SEARCH_TAGS_MAX || r.languages.size() > SEARCH_LANGS_MAX ||
        r.modalities.size() > SEARCH_MODALITIES_MAX) {
        err = "tag/lang bound";
        return false;
    }
    for (const auto& t : r.tags) {
        if (too_long(t, SEARCH_SIGNED_STR_MAX, "string too long")) return false;
    }
    for (const auto& t : r.languages) {
        if (too_long(t, SEARCH_SIGNED_STR_MAX, "string too long")) return false;
    }
    for (const auto& t : r.modalities) {
        if (too_long(t, SEARCH_SIGNED_STR_MAX, "string too long")) return false;
    }
    if (r.short_description.size() > SEARCH_DESC_MAX || r.description.size() > SEARCH_DESC_MAX) {
        err = "description too long";
        return false;
    }
    if (r.short_description.find('<') != std::string::npos || r.display_name.find('<') != std::string::npos) {
        err = "html not permitted";
        return false;
    }
    if (!r.btx_uri.empty()) {
        Resource decoded;
        std::string uri_err;
        if (!DecodeResource(r.btx_uri, decoded, uri_err) || decoded.kind != ResourceKind::MODEL ||
            decoded.digest != r.model_id) {
            err = "uri mismatch";
            return false;
        }
    }
    if (SearchRecordToJson(r).write().size() > SEARCH_RECORD_MAX) {
        err = "record too large";
        return false;
    }
    return true;
}

std::vector<unsigned char> SearchRecordPreimageV1(const ModelSearchRecord& r)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), r.model_id.data.begin(), r.model_id.data.end());
    b.insert(b.end(), r.artifact_id.data.begin(), r.artifact_id.data.end());
    PutU64(b, r.metadata_sequence);
    PutStr(b, r.canonical_name);
    PutStr(b, r.display_name);
    PutU16(b, static_cast<uint16_t>(r.aliases.size()));
    for (const auto& a : r.aliases) PutStr(b, a);
    PutStr(b, r.family);
    PutStr(b, r.architecture);
    PutStr(b, r.format);
    PutStr(b, r.quantization);
    PutStr(b, r.short_description);
    PutU64(b, r.size_bytes);
    PutU64(b, static_cast<uint64_t>(r.expires_at));
    b.push_back(r.tombstone ? 1 : 0);
    return b;
}

std::vector<unsigned char> SearchRecordPreimageV2(const ModelSearchRecord& r)
{
    std::vector<unsigned char> b = SearchRecordPreimageV1(r);
    b.insert(b.end(), r.publisher_identity.data.begin(), r.publisher_identity.data.end());
    PutStr(b, r.publisher_display_name);
    PutI64(b, r.parameter_count);
    PutStrList(b, r.languages);
    PutStrList(b, r.modalities);
    PutStrList(b, r.tags);
    PutI64(b, r.file_count);
    PutI64(b, r.published_at);
    PutI64(b, r.updated_at);
    PutStr(b, r.release_id);
    PutStr(b, r.release_state);
    PutI64(b, r.release_target_atoms);
    b.insert(b.end(), r.key_hash.data.begin(), r.key_hash.data.end());
    PutU64(b, r.refund_height);
    PutI64(b, r.campaign_created_at);
    b.insert(b.end(), r.ciphertext_artifact_id.data.begin(), r.ciphertext_artifact_id.data.end());
    PutStr(b, r.assurance);
    PutStr(b, r.btx_uri);
    return b;
}

std::vector<unsigned char> SearchRecordPreimage(const ModelSearchRecord& r)
{
    return r.record_version >= 2 ? SearchRecordPreimageV2(r) : SearchRecordPreimageV1(r);
}

bool PublisherFieldCoveredByV1(const std::string& field)
{
    const std::string x = ToLower(field);
    return x == "model_id" || x == "artifact_id" || x == "metadata_sequence" || x == "canonical_name" ||
           x == "display_name" || x == "aliases" || x == "family" || x == "architecture" || x == "format" ||
           x == "quantization" || x == "short_description" || x == "size_bytes" || x == "expires_at" ||
           x == "tombstone";
}

bool SignSearchRecord(ModelSearchRecord& r, Span<const unsigned char> sk, std::string& err)
{
    if (!ValidateSearchRecord(r, err)) return false;
    if (r.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    r.record_version = 2;
    r.signer_id = ResearchIdentityId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()});
    if (r.publisher_identity.IsNull()) r.publisher_identity = r.signer_id;
    if (r.btx_uri.empty()) EncodeResource(ResourceKind::MODEL, r.model_id, r.btx_uri, err);
    const auto pre = SearchRecordPreimageV2(r);
    const Digest48 h = DomainHash("BTX/ModelSearchRecord/v2", Span<const unsigned char>{pre.data(), pre.size()});
    return SignMlDsa44(sk, Span<const unsigned char>{h.data.data(), h.data.size()}, r.sig, err);
}

bool VerifySearchRecord(const ModelSearchRecord& r, int64_t now_ms, std::string& err)
{
    if (r.expires_at > 0 && r.expires_at <= now_ms) {
        err = "expired";
        return false;
    }
    if (r.pubkey.empty() || r.sig.empty()) {
        err = "unsigned";
        return false;
    }
    if (!ValidateSearchRecord(r, err)) return false;
    const Digest48 sid = ResearchIdentityId(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()});
    if (sid != r.signer_id) {
        err = "wrong signer";
        return false;
    }
    const bool v2 = r.record_version >= 2;
    const auto pre = v2 ? SearchRecordPreimageV2(r) : SearchRecordPreimageV1(r);
    const char* domain = v2 ? "BTX/ModelSearchRecord/v2" : "BTX/ModelSearchRecord/v1";
    const Digest48 h = DomainHash(domain, Span<const unsigned char>{pre.data(), pre.size()});
    if (!VerifyMlDsa44(Span<const unsigned char>{r.pubkey.data(), r.pubkey.size()},
                        Span<const unsigned char>{h.data.data(), h.data.size()},
                        Span<const unsigned char>{r.sig.data(), r.sig.size()})) {
        err = "bad signature";
        return false;
    }
    return true;
}

UniValue SearchRecordToJson(const ModelSearchRecord& r)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", r.schema_version);
    o.pushKV("type", "btx-model-search-v1");
    o.pushKV("record_version", r.record_version);
    o.pushKV("signing_domain", r.record_version >= 2 ? "BTX/ModelSearchRecord/v2" : "BTX/ModelSearchRecord/v1");
    o.pushKV("model_id", r.model_id.Hex());
    o.pushKV("artifact_id", r.artifact_id.Hex());
    o.pushKV("uri", r.btx_uri);
    o.pushKV("canonical_name", r.canonical_name);
    o.pushKV("display_name", r.display_name);
    UniValue al(UniValue::VARR);
    for (const auto& a : r.aliases) al.push_back(a);
    o.pushKV("aliases", al);
    o.pushKV("publisher_identity", r.publisher_identity.Hex());
    o.pushKV("publisher_display_name", r.publisher_display_name);
    o.pushKV("family", r.family);
    o.pushKV("architecture", r.architecture);
    o.pushKV("parameter_count", r.parameter_count);
    o.pushKV("format", r.format);
    o.pushKV("quantization", r.quantization);
    UniValue langs(UniValue::VARR);
    for (const auto& x : r.languages) langs.push_back(x);
    o.pushKV("languages", langs);
    UniValue mods(UniValue::VARR);
    for (const auto& x : r.modalities) mods.push_back(x);
    o.pushKV("modalities", mods);
    UniValue tags(UniValue::VARR);
    for (const auto& x : r.tags) tags.push_back(x);
    o.pushKV("tags", tags);
    o.pushKV("short_description", r.short_description);
    o.pushKV("size_bytes", r.size_bytes);
    o.pushKV("file_count", r.file_count);
    o.pushKV("published_at", r.published_at);
    o.pushKV("updated_at", r.updated_at);
    o.pushKV("release_id", r.release_id);
    o.pushKV("release_state", r.release_state);
    o.pushKV("release_target_atoms", r.release_target_atoms);
    o.pushKV("key_hash", r.key_hash.IsNull() ? "" : r.key_hash.Hex());
    o.pushKV("refund_height", static_cast<int64_t>(r.refund_height));
    o.pushKV("campaign_created_at", r.campaign_created_at);
    o.pushKV("ciphertext_artifact_id", r.ciphertext_artifact_id.Hex());
    o.pushKV("assurance", r.assurance.empty() ? "KEY_RELEASE_ONLY" : r.assurance);
    o.pushKV("metadata_sequence", static_cast<int64_t>(r.metadata_sequence));
    o.pushKV("expires_at", r.expires_at);
    o.pushKV("signer_id", r.signer_id.Hex());
    o.pushKV("pubkey", HexStr(r.pubkey));
    o.pushKV("signature", HexStr(r.sig));
    o.pushKV("signed_metadata", r.signed_ok);
    o.pushKV("tombstone", r.tombstone);
    o.pushKV("object_kind", r.object_kind.empty() ? "MODEL" : r.object_kind);
    if (!r.bounty_id.empty()) o.pushKV("bounty_id", r.bounty_id);
    if (!r.description.empty()) o.pushKV("description", r.description);
    if (!r.network_id.empty()) o.pushKV("network_id", r.network_id);
    return o;
}

bool SearchRecordFromJson(const UniValue& o, ModelSearchRecord& r, std::string& err)
{
    r = {};
    if (!o.isObject()) {
        err = "object";
        return false;
    }
    if (o.exists("type") && o["type"].get_str() != "btx-model-search-v1" &&
        o["type"].get_str() != "btx-model-search-v2") {
        err = "unknown record type";
        return false;
    }
    if (o.exists("record_version")) r.record_version = o["record_version"].getInt<int>();
    if (o.exists("model_id") && !Digest48::FromHex(o["model_id"].get_str(), r.model_id, err)) return false;
    if (o.exists("artifact_id") && !o["artifact_id"].get_str().empty() &&
        !Digest48::FromHex(o["artifact_id"].get_str(), r.artifact_id, err)) return false;
    auto S = [&](const char* k, std::string& dst) {
        if (o.exists(k)) dst = o[k].get_str();
    };
    S("uri", r.btx_uri);
    S("canonical_name", r.canonical_name);
    S("display_name", r.display_name);
    S("publisher_display_name", r.publisher_display_name);
    S("family", r.family);
    S("architecture", r.architecture);
    S("format", r.format);
    S("quantization", r.quantization);
    S("short_description", r.short_description);
    S("release_id", r.release_id);
    S("release_state", r.release_state);
    S("assurance", r.assurance);
    if (o.exists("publisher_identity") && !o["publisher_identity"].get_str().empty()) {
        if (!Digest48::FromHex(o["publisher_identity"].get_str(), r.publisher_identity, err)) return false;
    }
    if (o.exists("signer_id") && !o["signer_id"].get_str().empty()) {
        if (!Digest48::FromHex(o["signer_id"].get_str(), r.signer_id, err)) return false;
    }
    if (o.exists("aliases") && o["aliases"].isArray()) {
        for (const auto& a : o["aliases"].getValues()) {
            if (a.isStr()) r.aliases.push_back(a.get_str());
        }
    }
    if (o.exists("languages") && o["languages"].isArray()) {
        for (const auto& a : o["languages"].getValues()) {
            if (a.isStr()) r.languages.push_back(a.get_str());
        }
    }
    if (o.exists("modalities") && o["modalities"].isArray()) {
        for (const auto& a : o["modalities"].getValues()) {
            if (a.isStr()) r.modalities.push_back(a.get_str());
        }
    }
    if (o.exists("tags") && o["tags"].isArray()) {
        for (const auto& a : o["tags"].getValues()) {
            if (a.isStr()) r.tags.push_back(a.get_str());
        }
    }
    if (o.exists("size_bytes")) r.size_bytes = o["size_bytes"].getInt<int64_t>();
    if (o.exists("file_count")) r.file_count = o["file_count"].getInt<int>();
    if (o.exists("parameter_count")) r.parameter_count = o["parameter_count"].getInt<int64_t>();
    if (o.exists("published_at")) r.published_at = o["published_at"].getInt<int64_t>();
    if (o.exists("updated_at")) r.updated_at = o["updated_at"].getInt<int64_t>();
    if (o.exists("metadata_sequence")) r.metadata_sequence = o["metadata_sequence"].getInt<int64_t>();
    if (o.exists("expires_at")) r.expires_at = o["expires_at"].getInt<int64_t>();
    if (o.exists("release_target_atoms")) r.release_target_atoms = o["release_target_atoms"].getInt<int64_t>();
    if (o.exists("refund_height")) r.refund_height = static_cast<uint32_t>(o["refund_height"].getInt<int64_t>());
    if (o.exists("campaign_created_at")) r.campaign_created_at = o["campaign_created_at"].getInt<int64_t>();
    if (o.exists("key_hash") && o["key_hash"].isStr() && !o["key_hash"].get_str().empty()) {
        if (!Hash32::FromHex(o["key_hash"].get_str(), r.key_hash, err)) return false;
    }
    if (o.exists("ciphertext_artifact_id") && o["ciphertext_artifact_id"].isStr() &&
        !o["ciphertext_artifact_id"].get_str().empty()) {
        if (!Digest48::FromHex(o["ciphertext_artifact_id"].get_str(), r.ciphertext_artifact_id, err)) return false;
    }
    if (o.exists("tombstone")) r.tombstone = o["tombstone"].get_bool();
    if (o.exists("pubkey")) r.pubkey = ParseHex(o["pubkey"].get_str());
    if (o.exists("signature")) r.sig = ParseHex(o["signature"].get_str());
    r.signed_ok = false;
    if (o.exists("object_kind") && o["object_kind"].isStr()) r.object_kind = o["object_kind"].get_str();
    if (o.exists("bounty_id") && o["bounty_id"].isStr()) r.bounty_id = o["bounty_id"].get_str();
    if (o.exists("description") && o["description"].isStr()) r.description = o["description"].get_str();
    if (o.exists("network_id") && o["network_id"].isStr()) r.network_id = o["network_id"].get_str();
    return ValidateSearchRecord(r, err);
}

bool ParseSearchQuery(const UniValue& o, SearchQuery& q, std::string& err)
{
    q = {};
    if (o.isStr()) {
        q.text = o.get_str();
        return true;
    }
    if (!o.isObject()) {
        err = "query object";
        return false;
    }
    if (o.exists("text")) q.text = o["text"].get_str();
    else if (o.exists("query")) q.text = o["query"].get_str();
    if (o.exists("format") && !o.exists("filters")) q.filters.format = o["format"].get_str();
    if (o.write().size() > SEARCH_QUERY_BYTES_MAX) {
        err = "query too large";
        return false;
    }
    if (o.exists("limit")) q.limit = o["limit"].getInt<int>();
    if (q.limit <= 0) q.limit = 50;
    if (q.limit > static_cast<int>(SEARCH_PAGE_MAX)) q.limit = SEARCH_PAGE_MAX;
    if (o.exists("offset")) q.offset = o["offset"].getInt<int>();
    if (o.exists("cursor")) q.cursor = o["cursor"].get_str();
    if (o.exists("scope") && !ParseSearchScope(o["scope"].get_str(), q.scope)) {
        err = "bad scope";
        return false;
    }
    if (o.exists("sort") && !ParseSearchSort(o["sort"].get_str(), q.sort)) {
        err = "bad sort";
        return false;
    }
    UniValue filters_obj(UniValue::VOBJ);
    if (o.exists("filters") && o["filters"].isObject()) {
        filters_obj = o["filters"];
    } else if (o.exists("filter") && o["filter"].isObject()) {
        filters_obj = o["filter"];
    }
    if (filters_obj.isObject() && !filters_obj.getKeys().empty()) {
        const UniValue& f = filters_obj;
        auto FS = [&](const char* k, std::string& dst) {
            if (f.exists(k)) dst = f[k].get_str();
        };
        FS("publisher_id", q.filters.publisher_id);
        FS("publisher_name", q.filters.publisher_name);
        FS("family", q.filters.family);
        FS("architecture", q.filters.architecture);
        FS("format", q.filters.format);
        FS("quantization", q.filters.quantization);
        FS("object_kind", q.filters.object_kind);
        if (f.exists("min_size_bytes")) q.filters.min_size_bytes = f["min_size_bytes"].getInt<int64_t>();
        if (f.exists("max_size_bytes")) q.filters.max_size_bytes = f["max_size_bytes"].getInt<int64_t>();
        if (f.exists("min_parameters")) q.filters.min_parameters = f["min_parameters"].getInt<int64_t>();
        if (f.exists("max_parameters")) q.filters.max_parameters = f["max_parameters"].getInt<int64_t>();
        if (f.exists("license") && f["license"].isStr()) q.filters.license = f["license"].get_str();
        if (f.exists("public_only")) q.filters.public_only = f["public_only"].get_bool();
        if (f.exists("min_provider_count")) q.filters.min_provider_count = f["min_provider_count"].getInt<int>();
        if (f.exists("pinned")) q.filters.pinned = f["pinned"].get_bool();
        if (f.exists("seeded")) q.filters.seeded = f["seeded"].get_bool();
        if (f.exists("locally_verified")) q.filters.locally_verified = f["locally_verified"].get_bool();
        if (f.exists("funding_only")) q.filters.funding_only = f["funding_only"].get_bool();
        if (f.exists("released_only")) q.filters.released_only = f["released_only"].get_bool();
        if (f.exists("unreleased_only")) q.filters.unreleased_only = f["unreleased_only"].get_bool();
        if (f.exists("fundable_only")) q.filters.fundable_only = f["fundable_only"].get_bool();
        if (f.exists("refund_available")) q.filters.refund_available = f["refund_available"].get_bool();
        if (f.exists("ciphertext_available")) q.filters.ciphertext_available = f["ciphertext_available"].get_bool();
        if (f.exists("min_funded_percent")) q.filters.min_funded_percent = f["min_funded_percent"].getInt<int64_t>();
        if (f.exists("max_funded_percent")) q.filters.max_funded_percent = f["max_funded_percent"].getInt<int64_t>();
        if (f.exists("max_remaining_atoms")) q.filters.max_remaining_atoms = f["max_remaining_atoms"].getInt<int64_t>();
        if (f.exists("release_created_after")) q.filters.release_created_after = f["release_created_after"].getInt<int64_t>();
        if (f.exists("release_created_before")) q.filters.release_created_before = f["release_created_before"].getInt<int64_t>();
        if (f.exists("unlocked_after")) q.filters.unlocked_after = f["unlocked_after"].getInt<int64_t>();
        if (f.exists("min_ciphertext_provider_count")) {
            q.filters.min_ciphertext_provider_count = f["min_ciphertext_provider_count"].getInt<int>();
        }
        if (f.exists("lifecycle_state") && f["lifecycle_state"].isArray()) {
            for (const auto& x : f["lifecycle_state"].getValues()) {
                if (x.isStr()) q.filters.lifecycle_state.push_back(x.get_str());
            }
        }
        if (f.exists("state") && f["state"].isStr()) {
            q.filters.lifecycle_state.push_back(f["state"].get_str());
        }
        if (f.exists("modalities") && f["modalities"].isArray()) {
            for (const auto& x : f["modalities"].getValues()) {
                if (x.isStr()) q.filters.modalities.push_back(x.get_str());
            }
        }
        if (f.exists("language") && f["language"].isArray()) {
            for (const auto& x : f["language"].getValues()) {
                if (x.isStr()) q.filters.language.push_back(x.get_str());
            }
        }
        if (f.exists("tags") && f["tags"].isArray()) {
            for (const auto& x : f["tags"].getValues()) {
                if (x.isStr()) q.filters.tags.push_back(x.get_str());
            }
        }
    }
    return true;
}

UniValue AppliedFiltersJson(const SearchFilters& f)
{
    UniValue a(UniValue::VARR);
    auto add = [&](const std::string& n) { a.push_back(n); };
    if (!f.publisher_id.empty()) add("publisher_id");
    if (!f.publisher_name.empty()) add("publisher_name");
    if (!f.family.empty()) add("family");
    if (!f.architecture.empty()) add("architecture");
    if (!f.format.empty()) add("format");
    if (!f.quantization.empty()) add("quantization");
    if (f.min_size_bytes >= 0) add("min_size_bytes");
    if (f.max_size_bytes >= 0) add("max_size_bytes");
    if (f.min_parameters >= 0) add("min_parameters");
    if (f.max_parameters >= 0) add("max_parameters");
    if (!f.license.empty()) add("license");
    if (f.locally_verified) add("locally_verified");
    return a;
}

bool UnionCoversAll(uint32_t pieces_total, const std::vector<std::vector<PieceRange>>& providers)
{
    if (pieces_total == 0) return true;
    std::vector<uint8_t> have(pieces_total, 0);
    for (const auto& ranges : providers) {
        for (const auto& r : ranges) {
            for (uint32_t i = 0; i < r.count; ++i) {
                const uint32_t idx = r.first + i;
                if (idx < pieces_total) have[idx] = 1;
            }
        }
    }
    return std::all_of(have.begin(), have.end(), [](uint8_t x) { return x != 0; });
}

SwarmHealth ComputeSwarmHealth(uint32_t pieces_total, uint32_t pieces_local,
                               const std::vector<ProviderObservation>& obs)
{
    SwarmHealth h;
    h.pieces_total = pieces_total;
    h.pieces_local = pieces_local;
    std::set<std::string> ids;
    std::vector<std::vector<PieceRange>> ranges;
    int min_src = pieces_total == 0 ? 0 : 1000000;
    int z0 = 0, z1 = 0, z2 = 0;
    for (const auto& o : obs) {
        const std::string k = o.provider_id.empty() ? o.endpoint : o.provider_id;
        if (!ids.insert(k).second) continue;
        h.providers_observed += 1;
        if (o.complete) ++h.providers_complete;
        else ++h.providers_partial;
        if (o.direct) ++h.reachable_direct;
        if (o.relayed) ++h.reachable_relay;
        ranges.push_back(o.ranges);
    }
    if (pieces_total > 0) {
        h.reconstructable_known = true;
        h.reconstructable = UnionCoversAll(pieces_total, ranges);
        uint32_t missing = 0;
        for (uint32_t i = 0; i < pieces_total; ++i) {
            int src = 0;
            for (const auto& ranges_i : ranges) {
                for (const auto& r : ranges_i) {
                    if (RangeCovers(r, i)) {
                        ++src;
                        break;
                    }
                }
            }
            if (src == 0) ++z0;
            else if (src == 1) ++z1;
            else if (src == 2) ++z2;
            if (src < min_src) min_src = src;
            if (src == 0) ++missing;
        }
        h.min_piece_sources = min_src == 1000000 ? 0 : min_src;
        h.pieces_with_0_sources = z0;
        h.pieces_with_1_source = z1;
        h.pieces_with_2_sources = z2;
        h.missing_piece_count = missing;
        h.fragile = z1 > 0;
        if (obs.empty()) h.klass = AvailabilityClass::UNKNOWN;
        else if (!h.reconstructable) h.klass = AvailabilityClass::DEGRADED;
        else if (h.fragile) h.klass = AvailabilityClass::FRAGILE;
        else if (h.providers_complete >= 3 && h.min_piece_sources >= 3) h.klass = AvailabilityClass::EXCELLENT;
        else if (h.providers_complete >= 1) h.klass = AvailabilityClass::HIGH;
        else h.klass = AvailabilityClass::MEDIUM;
    } else {
        h.klass = AvailabilityClass::UNKNOWN;
        h.reconstructable = false;
        h.reconstructable_known = false;
    }
    return h;
}

int DiversityAwareProviderScore(const std::vector<ProviderObservation>& obs)
{
    std::set<std::string> ids, ngs, eps;
    for (const auto& o : obs) {
        ids.insert(o.provider_id.empty() ? o.endpoint : o.provider_id);
        if (!o.netgroup.empty()) ngs.insert(o.netgroup);
        if (!o.endpoint.empty()) eps.insert(o.endpoint);
    }
    const int raw = static_cast<int>(ids.size());
    const int div = std::max(1, static_cast<int>(ngs.empty() ? eps.size() : ngs.size()));
    return std::min(raw, div * 4);
}

int RelevanceScore(const ModelSearchRecord& r, const std::vector<std::string>& terms)
{
    if (terms.empty()) return 1;
    int s = 0;
    const std::string cn = NormalizeSearchText(r.canonical_name);
    const std::string dn = NormalizeSearchText(r.display_name);
    const std::string joined = NormalizeSearchText(r.canonical_name + " " + r.display_name);
    const std::string q = [&] {
        std::string o;
        for (size_t i = 0; i < terms.size(); ++i) {
            if (i) o += " ";
            o += terms[i];
        }
        return o;
    }();
    if (cn == q || dn == q) s += 1000;
    for (const auto& a : r.aliases) {
        if (NormalizeSearchText(a) == q) s += 800;
    }
    for (const auto& t : terms) {
        if (cn.find(t) != std::string::npos || dn.find(t) != std::string::npos) s += 200;
        if (NormalizeSearchText(r.family).find(t) != std::string::npos) s += 120;
        if (NormalizeSearchText(r.architecture).find(t) != std::string::npos) s += 80;
        for (const auto& tag : r.tags) {
            if (NormalizeSearchText(tag).find(t) != std::string::npos) s += 60;
        }
        if (NormalizeSearchText(r.short_description).find(t) != std::string::npos) s += 20;
        if (NormalizeSearchText(r.description).find(t) != std::string::npos) s += 20;
        if (NormalizeSearchText(r.publisher_display_name).find(t) != std::string::npos) s += 90;
        for (const auto& lang : r.languages) {
            if (NormalizeSearchText(lang).find(t) != std::string::npos) s += 40;
        }
        for (const auto& m : r.modalities) {
            if (NormalizeSearchText(m).find(t) != std::string::npos) s += 50;
        }
        (void)joined;
    }
    if (s == 0) return 0;
    if (r.signed_ok) s += 50;
    return s;
}

UniValue AvailabilityJson(const SwarmHealth& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("providers_total", h.providers_observed);
    o.pushKV("providers_complete", h.providers_complete);
    o.pushKV("providers_partial", h.providers_partial);
    o.pushKV("min_piece_sources", h.min_piece_sources);
    o.pushKV("pieces_with_0_sources", h.pieces_with_0_sources);
    o.pushKV("pieces_with_1_source", h.pieces_with_1_source);
    o.pushKV("pieces_with_2_sources", h.pieces_with_2_sources);
    o.pushKV("reconstructable", h.reconstructable);
    o.pushKV("reconstructable_known", h.reconstructable_known);
    o.pushKV("missing_piece_count", static_cast<int>(h.missing_piece_count));
    o.pushKV("fragile", h.fragile);
    o.pushKV("class", AvailabilityClassName(h.klass));
    o.pushKV("observed_provider_count", h.providers_observed);
    o.pushKV("global_complete", false);
    return o;
}

UniValue PeerCountJson(const SwarmHealth& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("total", h.providers_observed);
    o.pushKV("complete", h.providers_complete);
    o.pushKV("partial", h.providers_partial);
    o.pushKV("reachable_direct", h.reachable_direct);
    o.pushKV("reachable_relay", h.reachable_relay);
    o.pushKV("observed_provider_count", h.providers_observed);
    o.pushKV("note", "this node's current network view; not a global census");
    return o;
}

UniValue SearchResultCard(const SearchHit& h)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("model_id", h.rec.model_id.Hex());
    o.pushKV("artifact_id", h.rec.artifact_id.Hex());
    o.pushKV("uri", h.rec.btx_uri);
    o.pushKV("name", h.rec.display_name.empty() ? h.rec.canonical_name : h.rec.display_name);
    UniValue al(UniValue::VARR);
    for (const auto& a : h.rec.aliases) al.push_back(a);
    o.pushKV("aliases", al);
    UniValue pub(UniValue::VOBJ);
    pub.pushKV("id", h.rec.publisher_identity.Hex());
    pub.pushKV("display_name", h.rec.publisher_display_name);
    o.pushKV("publisher", pub);
    o.pushKV("family", h.rec.family);
    o.pushKV("architecture", h.rec.architecture);
    o.pushKV("parameters", h.rec.parameter_count);
    o.pushKV("format", h.rec.format);
    o.pushKV("quantization", h.rec.quantization);
    UniValue langs(UniValue::VARR);
    for (const auto& x : h.rec.languages) langs.push_back(x);
    o.pushKV("languages", langs);
    UniValue tags(UniValue::VARR);
    for (const auto& x : h.rec.tags) tags.push_back(x);
    o.pushKV("tags", tags);
    UniValue mods(UniValue::VARR);
    for (const auto& x : h.rec.modalities) mods.push_back(x);
    o.pushKV("modalities", mods);
    o.pushKV("description", h.rec.short_description);
    o.pushKV("size_bytes", h.rec.size_bytes);
    o.pushKV("file_count", h.rec.file_count);
    o.pushKV("published_at", h.rec.published_at);
    o.pushKV("availability", AvailabilityJson(h.health));
    UniValue loc(UniValue::VOBJ);
    loc.pushKV("known", h.local.known);
    loc.pushKV("downloaded", h.local.downloaded);
    loc.pushKV("partial", h.local.partial);
    loc.pushKV("seeded", h.local.seeded);
    loc.pushKV("pinned", h.local.pinned);
    loc.pushKV("qualification", h.local.qualification);
    o.pushKV("local", loc);
    UniValue rel(UniValue::VOBJ);
    rel.pushKV("id", h.rec.release_id);
    rel.pushKV("state", h.rec.release_state.empty() ? "PUBLIC" : h.rec.release_state);
    o.pushKV("release", rel);
    UniValue se(UniValue::VOBJ);
    se.pushKV("score", h.score);
    o.pushKV("sources", h.sources);
    se.pushKV("metadata_verified", h.rec.signed_ok);
    UniValue prov(UniValue::VARR);
    for (const auto& p : h.provenance) prov.push_back(p);
    se.pushKV("provenance", prov);
    o.pushKV("search", se);
    UniValue share(UniValue::VOBJ);
    share.pushKV("uri", h.rec.btx_uri);
    std::string copy = h.rec.btx_uri;
    if (!h.rec.family.empty()) copy += " family=" + h.rec.family;
    if (!h.rec.format.empty()) copy += " format=" + h.rec.format;
    if (!h.rec.quantization.empty()) copy += " quant=" + h.rec.quantization;
    share.pushKV("copy_text", copy);
    share.pushKV("family", h.rec.family);
    share.pushKV("format", h.rec.format);
    share.pushKV("quantization", h.rec.quantization);
    share.pushKV("signed", h.rec.signed_ok);
    o.pushKV("share", share);
    UniValue actions(UniValue::VARR);
    actions.push_back("getmodelsharecard");
    actions.push_back("getmodel FREE_ONLY");
    actions.push_back("showmodel");
    actions.push_back("automatic_spend_atoms stays 0");
    o.pushKV("next_actions", actions);
    return o;
}

UniValue DirectoryEntryJson(const SearchHit& h)
{
    UniValue o = SearchResultCard(h);
    o.pushKV("metadata", SearchRecordToJson(h.rec));
    o.pushKV("swarm", AvailabilityJson(h.health));
    return o;
}

bool SearchIndex::Put(const ModelSearchRecord& r, int64_t now_ms, std::string& err)
{
    const bool has_sig = !r.sig.empty();
    bool verified = false;
    if (has_sig || r.tombstone) {
        if (!VerifySearchRecord(r, now_ms, err)) {
            if (r.tombstone) {
                err = err.empty() ? "unsigned tombstone" : err;
            }
            return false;
        }
        verified = true;
    } else {
        if (!ValidateSearchRecord(r, err)) return false;
    }
    const std::string key = r.model_id.Hex();
    auto it = m_by_model.find(key);
    if (it != m_by_model.end()) {
        if (it->second.signed_ok) {
            if (!verified) {
                err = "unsigned cannot override signed";
                return false;
            }
            if (r.signer_id != it->second.signer_id) {
                err = "wrong signer";
                return false;
            }
            if (r.metadata_sequence < it->second.metadata_sequence) {
                err = "sequence rollback";
                return false;
            }
            if (r.metadata_sequence == it->second.metadata_sequence) {
                const auto a = SearchRecordToJson(it->second).write();
                ModelSearchRecord tmp = r;
                tmp.signed_ok = it->second.signed_ok;
                if (SearchRecordToJson(tmp).write() != a && !r.tombstone) {
                    err = "same sequence conflict";
                    return false;
                }
            }
        }
    }
    if (m_by_model.size() >= m_cap && it == m_by_model.end()) {
        err = "index cap";
        return false;
    }
    const std::string pub = r.publisher_identity.Hex();
    if (!pub.empty() && !r.publisher_identity.IsNull()) {
        if (m_pub_window[pub] > 64) {
            err = "publisher spam";
            return false;
        }
        if (it == m_by_model.end()) m_pub_window[pub] += 1;
    }
    m_by_model[key] = r;
    m_by_model[key].signed_ok = verified;
    if (r.tombstone) m_by_model[key].tombstone = true;
    ++m_seq;
    return true;
}

bool SearchIndex::Tombstone(const Digest48& model_id, uint64_t seq, int64_t now_ms, std::string& err)
{
    (void)seq;
    (void)now_ms;
    (void)model_id;
    err = "unsigned tombstone rejected; supply a signed tombstone record via Put";
    return false;
}

const ModelSearchRecord* SearchIndex::Get(const Digest48& model_id) const
{
    auto it = m_by_model.find(model_id.Hex());
    if (it == m_by_model.end()) return nullptr;
    return &it->second;
}

const ModelSearchRecord* SearchIndex::FindByAlias(const std::string& alias) const
{
    if (alias.empty()) return nullptr;
    const std::string needle = ToLower(alias);
    const ModelSearchRecord* ci = nullptr;
    for (const auto& kv : m_by_model) {
        if (kv.second.tombstone) continue;
        for (const auto& a : kv.second.aliases) {
            if (a == alias) return &kv.second;
            if (!ci && ToLower(a) == needle) ci = &kv.second;
        }
    }
    return ci;
}

std::vector<ModelSearchRecord> SearchIndex::List(int64_t updated_after, const std::string& cursor, int limit) const
{
    std::vector<ModelSearchRecord> out;
    bool skip = !cursor.empty();
    for (const auto& kv : m_by_model) {
        if (kv.second.updated_at < updated_after) continue;
        if (skip) {
            if (kv.first == cursor) skip = false;
            continue;
        }
        out.push_back(kv.second);
        if (static_cast<int>(out.size()) >= limit) break;
    }
    return out;
}

std::vector<SearchHit> SearchIndex::Search(const SearchQuery& q, int64_t now_ms) const
{
    const auto terms = TokenizeSearch(q.text);
    std::vector<SearchHit> hits;
    for (const auto& kv : m_by_model) {
        const auto& r = kv.second;
        if (r.tombstone) continue;
        if (r.expires_at > 0 && r.expires_at <= now_ms) continue;
        if (m_hidden.count(r.model_id.Hex())) continue;
        if (m_muted_publishers.count(r.publisher_identity.Hex())) continue;
        if (!q.filters.publisher_id.empty() && r.publisher_identity.Hex() != q.filters.publisher_id) continue;
        if (!q.filters.publisher_name.empty() &&
            NormalizeSearchText(r.publisher_display_name).find(NormalizeSearchText(q.filters.publisher_name)) ==
                std::string::npos) {
            continue;
        }
        if (!q.filters.family.empty() && NormalizeSearchText(r.family) != NormalizeSearchText(q.filters.family)) continue;
        if (!q.filters.architecture.empty() &&
            NormalizeSearchText(r.architecture) != NormalizeSearchText(q.filters.architecture)) continue;
        if (!q.filters.format.empty() && NormalizeSearchText(r.format) != NormalizeSearchText(q.filters.format)) continue;
        if (!q.filters.quantization.empty() &&
            NormalizeSearchText(r.quantization) != NormalizeSearchText(q.filters.quantization)) continue;
        if (q.filters.min_size_bytes >= 0 && static_cast<int64_t>(r.size_bytes) < q.filters.min_size_bytes) continue;
        if (q.filters.max_size_bytes >= 0 && static_cast<int64_t>(r.size_bytes) > q.filters.max_size_bytes) continue;
        if (q.filters.min_parameters >= 0 && r.parameter_count < q.filters.min_parameters) continue;
        if (q.filters.max_parameters >= 0 && (r.parameter_count <= 0 || r.parameter_count > q.filters.max_parameters)) continue;
        if (q.filters.locally_verified && !r.signed_ok) continue;
        if (!q.filters.license.empty()) {
            const std::string tagged = std::string("license:") + q.filters.license;
            if (!FieldHas(r.tags, q.filters.license) && !FieldHas(r.tags, tagged)) continue;
        }
        if (!q.filters.language.empty()) {
            bool ok = false;
            for (const auto& l : q.filters.language) {
                if (FieldHas(r.languages, l)) ok = true;
            }
            if (!ok) continue;
        }
        if (!q.filters.tags.empty()) {
            bool ok = false;
            for (const auto& t : q.filters.tags) {
                if (FieldHas(r.tags, t)) ok = true;
            }
            if (!ok) continue;
        }
        if (q.filters.public_only && !r.release_id.empty() && ToUpper(r.release_state) != "PUBLIC" &&
            ToUpper(r.release_state) != "PUBLIC_RELEASED" && !r.release_state.empty()) {
            continue;
        }
        if (q.filters.funding_only && r.release_id.empty()) continue;
        if (q.filters.released_only && !r.release_id.empty() && ToUpper(r.release_state) != "PUBLIC" &&
            ToUpper(r.release_state) != "PUBLIC_RELEASED" && ToUpper(r.release_state) != "SECRET_DISCLOSED") {
            continue;
        }
        if (q.filters.unreleased_only && (r.release_id.empty() || ToUpper(r.release_state) == "PUBLIC" ||
                                            ToUpper(r.release_state) == "PUBLIC_RELEASED")) {
            continue;
        }
        if (!q.filters.lifecycle_state.empty()) {
            bool ok = false;
            const std::string st = r.release_state.empty() ? "PUBLIC" : ToUpper(r.release_state);
            for (const auto& ls : q.filters.lifecycle_state) {
                if (ToUpper(ls) == st) ok = true;
            }
            if (!ok) continue;
        }
        if (!q.filters.object_kind.empty() &&
            NormalizeSearchText(r.object_kind) != NormalizeSearchText(q.filters.object_kind)) {
            continue;
        }
        if (!terms.empty()) {
            if (RelevanceScore(r, terms) <= 0) continue;
        }
        SearchHit hit;
        hit.rec = r;
        hit.score = RelevanceScore(r, terms);
        hit.provenance.push_back("local_index");
        hits.push_back(hit);
    }
    SortHits(hits, q.sort);
    if (q.offset > 0 && q.offset < static_cast<int>(hits.size())) {
        hits.erase(hits.begin(), hits.begin() + q.offset);
    } else if (q.offset >= static_cast<int>(hits.size())) {
        hits.clear();
    }
    if (static_cast<int>(hits.size()) > q.limit) hits.resize(q.limit);
    return hits;
}

void SearchIndex::Hide(const Digest48& model_id, bool on)
{
    if (on) m_hidden.insert(model_id.Hex());
    else m_hidden.erase(model_id.Hex());
}
void SearchIndex::MutePublisher(const std::string& publisher_hex, bool on)
{
    if (on) m_muted_publishers.insert(publisher_hex);
    else m_muted_publishers.erase(publisher_hex);
}
bool SearchIndex::Hidden(const Digest48& model_id) const
{
    return m_hidden.count(model_id.Hex()) > 0;
}
bool SearchIndex::Muted(const std::string& publisher_hex) const
{
    return m_muted_publishers.count(publisher_hex) > 0;
}
void SearchIndex::AddIndexPeer(const std::string& endpoint)
{
    if (endpoint.empty()) return;
    if (std::find(m_index_peers.begin(), m_index_peers.end(), endpoint) == m_index_peers.end()) {
        m_index_peers.push_back(endpoint);
    }
}
void SearchIndex::RemoveIndexPeer(const std::string& endpoint)
{
    m_index_peers.erase(std::remove(m_index_peers.begin(), m_index_peers.end(), endpoint), m_index_peers.end());
}
UniValue SearchIndex::ExportSince(uint64_t since, int limit) const
{
    UniValue arr(UniValue::VARR);
    int n = 0;
    uint64_t seq = 0;
    for (const auto& kv : m_by_model) {
        ++seq;
        if (seq <= since) continue;
        arr.push_back(SearchRecordToJson(kv.second));
        if (++n >= limit) break;
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("sequence", static_cast<int64_t>(m_seq));
    o.pushKV("records", arr);
    return o;
}
UniValue SearchIndex::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("search_records_known", static_cast<int>(m_by_model.size()));
    o.pushKV("index_peers", static_cast<int>(m_index_peers.size()));
    o.pushKV("sequence", static_cast<int64_t>(m_seq));
    o.pushKV("global_complete", false);
    o.pushKV("authoritative", false);
    return o;
}

bool SearchIndex::Save(const fs::path& path, std::string& err) const
{
    const UniValue snap = ExportSince(0, static_cast<int>(std::min(m_by_model.size(), size_t{100000})));
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        err = "search-index write";
        return false;
    }
    out << snap.write() << "\n";
    return true;
}

bool SearchIndex::Load(const fs::path& path, int64_t now_ms, std::string& err)
{
    if (!fs::exists(path)) return true;
    std::ifstream in(path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(raw) || !o.isObject() || !o.exists("records")) return true;
    for (const auto& recj : o["records"].getValues()) {
        ModelSearchRecord rec;
        std::string ierr;
        if (!SearchRecordFromJson(recj, rec, ierr)) continue;
        (void)Put(rec, now_ms, err);
    }
    if (o.exists("sequence")) m_seq = std::max(m_seq, static_cast<uint64_t>(o["sequence"].getInt<int64_t>()));
    return true;
}

void SearchIndex::Clear()
{
    m_by_model.clear();
    m_hidden.clear();
    m_muted_publishers.clear();
    m_pub_window.clear();
    m_seq = 0;
}

std::vector<ModelSearchRecord> SearchIndex::All() const
{
    std::vector<ModelSearchRecord> out;
    out.reserve(m_by_model.size());
    for (const auto& kv : m_by_model) {
        if (!kv.second.tombstone) out.push_back(kv.second);
    }
    return out;
}

bool QueryDedupe::Admit(const std::string& query_id)
{
    if (query_id.empty() || query_id.size() > 128) return false;
    if (seen.count(query_id)) return false;
    if (seen.size() >= 4096) seen.clear();
    seen.insert(query_id);
    return true;
}

bool ShouldForwardSearch(int ttl, int hop)
{
    if (ttl <= 0) return false;
    if (hop >= SEARCH_TTL_MAX) return false;
    if (ttl > SEARCH_TTL_MAX) return false;
    return true;
}

SearchRequest ParseSearchRequest(const UniValue& o, std::string& err)
{
    SearchRequest r;
    if (!o.isObject()) {
        err = "object";
        return r;
    }
    if (o.exists("query_id")) r.query_id = o["query_id"].get_str();
    if (o.exists("ttl")) r.ttl = o["ttl"].getInt<int>();
    if (r.ttl > SEARCH_TTL_MAX) r.ttl = SEARCH_TTL_MAX;
    if (o.exists("limit")) r.limit = o["limit"].getInt<int>();
    if (o.exists("text") && o["text"].isStr()) r.text_terms = TokenizeSearch(o["text"].get_str());
    if (o.exists("text_terms") && o["text_terms"].isArray()) {
        for (const auto& t : o["text_terms"].getValues()) {
            if (t.isStr()) r.text_terms.push_back(NormalizeSearchText(t.get_str()));
        }
    }
    if (o.exists("sort_hint") && o["sort_hint"].isStr()) ParseSearchSort(o["sort_hint"].get_str(), r.sort_hint);
    if (o.exists("sort") && o["sort"].isStr()) ParseSearchSort(o["sort"].get_str(), r.sort_hint);
    if (o.exists("filters") && o["filters"].isObject()) {
        SearchQuery q;
        UniValue wrap(UniValue::VOBJ);
        wrap.pushKV("filters", o["filters"]);
        std::string perr;
        ParseSearchQuery(wrap, q, perr);
        r.filters = q.filters;
    }
    return r;
}

UniValue SearchResponseJson(const std::string& query_id, const std::string& responder,
                            const std::vector<SearchHit>& hits, bool truncated)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("query_id", query_id);
    o.pushKV("responder_id", responder);
    UniValue arr(UniValue::VARR);
    for (const auto& h : hits) arr.push_back(SearchResultCard(h));
    o.pushKV("results", arr);
    UniValue recs(UniValue::VARR);
    for (const auto& h : hits) recs.push_back(SearchRecordToJson(h.rec));
    o.pushKV("records", recs);
    o.pushKV("truncated", truncated);
    o.pushKV("coverage_hint", "incomplete");
    return o;
}

bool SearchPeerTimedOut(int64_t elapsed_ms, int timeout_ms)
{
    return elapsed_ms >= timeout_ms;
}

void NoteSearchPeerTimeout(SearchCoverage& cov)
{
    cov.timed_out += 1;
    cov.complete = false;
}

bool SearchHitFromCard(const UniValue& card, SearchHit& out, std::string& err)
{
    out = {};
    if (!card.isObject() || !card.exists("model_id") || !card["model_id"].isStr()) {
        err = "card";
        return false;
    }
    if (!Digest48::FromHex(card["model_id"].get_str(), out.rec.model_id, err)) return false;
    if (card.exists("artifact_id") && card["artifact_id"].isStr() && !card["artifact_id"].get_str().empty()) {
        if (!Digest48::FromHex(card["artifact_id"].get_str(), out.rec.artifact_id, err)) return false;
    }
    if (card.exists("name") && card["name"].isStr()) {
        out.rec.display_name = card["name"].get_str();
        out.rec.canonical_name = out.rec.display_name;
    }
    if (card.exists("uri") && card["uri"].isStr()) out.rec.btx_uri = card["uri"].get_str();
    if (card.exists("description") && card["description"].isStr()) out.rec.short_description = card["description"].get_str();
    if (card.exists("family") && card["family"].isStr()) out.rec.family = card["family"].get_str();
    if (card.exists("release") && card["release"].isObject()) {
        const UniValue& rel = card["release"];
        if (rel.exists("id") && rel["id"].isStr()) out.rec.release_id = rel["id"].get_str();
        if (rel.exists("release_id") && rel["release_id"].isStr()) out.rec.release_id = rel["release_id"].get_str();
        if (rel.exists("state") && rel["state"].isStr()) out.rec.release_state = rel["state"].get_str();
    }
    out.provenance.push_back("peer");
    return true;
}

void SortHits(std::vector<SearchHit>& hits, SearchSort sort)
{
    std::sort(hits.begin(), hits.end(), [&](const SearchHit& a, const SearchHit& b) {
        switch (sort) {
        case SearchSort::NAME:
            return a.rec.display_name < b.rec.display_name;
        case SearchSort::NEWEST:
            return a.rec.published_at > b.rec.published_at;
        case SearchSort::OLDEST:
            return a.rec.published_at < b.rec.published_at;
        case SearchSort::SIZE_ASC:
            return a.rec.size_bytes < b.rec.size_bytes;
        case SearchSort::SIZE_DESC:
            return a.rec.size_bytes > b.rec.size_bytes;
        case SearchSort::PUBLISHER:
            return a.rec.publisher_display_name < b.rec.publisher_display_name;
        case SearchSort::PROVIDERS:
        case SearchSort::AVAILABILITY:
        case SearchSort::RARITY:
            if (a.health.providers_observed != b.health.providers_observed)
                return a.health.providers_observed > b.health.providers_observed;
            return a.score > b.score;
        case SearchSort::RELEVANCE:
        default:
            if (a.score != b.score) return a.score > b.score;
            return a.rec.model_id.Hex() < b.rec.model_id.Hex();
        }
    });
}

void MergeRemoteSearchHits(SearchJob& job, std::vector<SearchHit> extra)
{
    std::map<std::string, SearchHit> merged;
    for (auto& h : job.hits) merged[h.rec.model_id.Hex()] = std::move(h);
    for (auto& h : extra) {
        const std::string key = h.rec.model_id.Hex();
        auto it = merged.find(key);
        if (it == merged.end()) {
            h.sources = 1;
            merged[key] = std::move(h);
        } else {
            it->second.sources += 1;
            it->second.provenance.insert(it->second.provenance.end(), h.provenance.begin(), h.provenance.end());
        }
    }
    job.hits.clear();
    for (auto& kv : merged) job.hits.push_back(std::move(kv.second));
    SortHits(job.hits, job.q.sort);
    if (job.q.limit > 0 && static_cast<int>(job.hits.size()) > job.q.limit) {
        job.hits.resize(job.q.limit);
    }
    job.coverage.complete = false;
}

SearchJob SearchRuntime::Start(const SearchQuery& q, const std::vector<SearchIndex*>& extras, int64_t now_ms)
{
    SearchJob job;
    job.query_id = NewSearchQueryId();
    job.q = q;
    job.started_ms = now_ms;
    job.coverage.local = true;
    job.coverage.complete = false;
    std::map<std::string, SearchHit> merged;
    auto ingest = [&](SearchIndex* idx, const std::string& src, bool remote) {
        if (!idx) return;
        const auto hits = idx->Search(q, now_ms);
        if (remote) {
            job.coverage.responses_received += 1;
            const auto peers = idx->IndexPeers();
            if (std::find(peers.begin(), peers.end(), src) != peers.end() ||
                src.find("index") != std::string::npos) {
                job.coverage.index_peers_queried += 1;
            } else {
                job.coverage.connected_peers_queried += 1;
            }
        }
        for (auto h : hits) {
            h.provenance.push_back(src);
            auto it = merged.find(h.rec.model_id.Hex());
            if (it == merged.end()) {
                h.sources = 1;
                merged[h.rec.model_id.Hex()] = h;
            } else {
                it->second.sources += 1;
                it->second.health.providers_observed =
                    std::max(it->second.health.providers_observed, h.health.providers_observed);
            }
        }
    };
    ingest(m_idx, "local", false);
    if (q.scope != SearchScope::LOCAL) {
        for (auto* e : extras) ingest(e, "peer", true);
    }
    for (auto& kv : merged) job.hits.push_back(kv.second);
    SortHits(job.hits, q.sort);
    const int seen = static_cast<int>(job.hits.size());
    if (static_cast<int>(job.hits.size()) > q.limit) job.hits.resize(q.limit);
    job.state = (q.scope == SearchScope::LOCAL && extras.empty()) ? SearchJobState::COMPLETE : SearchJobState::RUNNING;
    job.elapsed_ms = 0;
    job.coverage.complete = false;
    m_jobs[job.query_id] = job;
    if (job.state == SearchJobState::COMPLETE) ++m_completed;
    else ++m_running;
    (void)seen;
    return job;
}

bool SearchRuntime::Status(const std::string& query_id, SearchJob& out) const
{
    auto it = m_jobs.find(query_id);
    if (it == m_jobs.end()) return false;
    out = it->second;
    return true;
}
bool SearchRuntime::Cancel(const std::string& query_id)
{
    auto it = m_jobs.find(query_id);
    if (it == m_jobs.end()) return false;
    if (it->second.state == SearchJobState::RUNNING && m_running > 0) --m_running;
    it->second.state = SearchJobState::CANCELLED;
    return true;
}

bool SearchRuntime::IsCancelled(const std::string& query_id) const
{
    auto it = m_jobs.find(query_id);
    return it != m_jobs.end() && it->second.state == SearchJobState::CANCELLED;
}

void SearchRuntime::Finish(SearchJob& job)
{
    if (job.state == SearchJobState::RUNNING) job.state = SearchJobState::COMPLETE;
    m_jobs[job.query_id] = job;
    if (m_running > 0) --m_running;
    ++m_completed;
}

bool UnsignedCannotOverrideSigned()
{
    return true;
}
bool SearchTouchesMonetaryConsensus()
{
    return false;
}
std::string NewSearchQueryId()
{
    unsigned char b[8];
    GetStrongRandBytes(Span<unsigned char>{b, sizeof(b)});
    return HexStr(Span<const unsigned char>{b, sizeof(b)});
}

} // namespace modelnet
