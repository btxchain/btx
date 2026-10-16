// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_wire.h>

#include <bech32.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>

namespace modelnet {
namespace {

bool IsLowerHex96(std::string_view s)
{
    if (s.size() != 96) return false;
    for (unsigned char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool ValidUtf8(std::string_view s)
{
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        if (*p <= 0x7f) {
            ++p;
            continue;
        }
        int need = 0;
        uint32_t cp = 0;
        if ((*p & 0xe0) == 0xc0) {
            need = 1;
            cp = *p & 0x1f;
            if (cp < 2) return false;
        } else if ((*p & 0xf0) == 0xe0) {
            need = 2;
            cp = *p & 0x0f;
        } else if ((*p & 0xf8) == 0xf0) {
            need = 3;
            cp = *p & 0x07;
        } else {
            return false;
        }
        ++p;
        for (int i = 0; i < need; ++i) {
            if (p >= end || (*p & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (*p & 0x3f);
            ++p;
        }
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
        if (need == 2 && cp < 0x800) return false;
        if (need == 3 && cp < 0x10000) return false;
        if (cp > 0x10ffff) return false;
    }
    return true;
}

bool HasUpper(std::string_view s)
{
    for (unsigned char c : s) {
        if (std::isupper(c)) return true;
    }
    return false;
}

/** Final segment ends in '.' plus 1..8 ASCII alphanumerics (`.json`, `.bin`). */
bool HasExtensionSuffix(std::string_view uri)
{
    const auto slash = uri.rfind('/');
    const auto dot = uri.rfind('.');
    if (dot == std::string_view::npos) return false;
    if (slash != std::string_view::npos && dot < slash) return false;
    if (dot + 1 >= uri.size()) return false;
    const std::string_view ext = uri.substr(dot + 1);
    if (ext.empty() || ext.size() > 8) return false;
    for (unsigned char c : ext) {
        if (!std::isalnum(c)) return false;
    }
    return true;
}

bool Bech32ResourceToken(std::string_view token)
{
    if (token.size() != 85) return false;
    const std::string internal = "btx1" + std::string(token);
    const auto decoded = bech32::Decode(internal, bech32::CharLimit::BECH32);
    if (decoded.encoding != bech32::Encoding::BECH32M || decoded.hrp != "btx") return false;
    if (decoded.data.size() < 2 || decoded.data[0] != 1 || decoded.data[1] > 15) return false;
    std::vector<unsigned char> digest;
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { digest.push_back(c); }, decoded.data.begin() + 2,
                                  decoded.data.end())) {
        return false;
    }
    return digest.size() == 48;
}

struct Registry {
    std::vector<std::string> kinds;
    std::set<std::string> kind_set;
    std::set<std::string> record_types;
    std::map<std::string, std::string> semantic;
};

std::string RegistryPath(const std::string& spec_path)
{
    std::string base = spec_path;
    if (base.empty()) {
        if (const char* env = std::getenv("BTX035_SPEC")) base = env;
    }
    if (base.empty()) return {};
    static const char* kFile = "resource_registry.json";
    if (base.size() >= 22 && base.compare(base.size() - 22, 22, kFile) == 0) return base;
    std::string dir = base;
    while (!dir.empty() && (dir.back() == '/' || dir.back() == '\\')) dir.pop_back();
    return dir + "/schemas/resource_registry.json";
}

bool ReadFile(const std::string& path, std::string& body, std::string& err)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "BTX035_SCHEMA";
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (in.bad()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    body = ss.str();
    return true;
}

bool LoadRegistry(const std::string& spec_path, Registry& out, std::string& err)
{
    err.clear();
    out = Registry{};
    std::string body;
    if (!ReadFile(RegistryPath(spec_path), body, err)) return false;
    UniValue doc;
    if (!doc.read(body) || !doc.isObject() || !doc.exists("resource_refs") || !doc["resource_refs"].isArray() ||
        !doc.exists("record_descriptors") || !doc["record_descriptors"].isArray() ||
        !doc.exists("semantic_aliases") || !doc["semantic_aliases"].isObject()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    out.kinds.assign(16, {});
    std::vector<bool> seen(16, false);
    for (const UniValue& row : doc["resource_refs"].getValues()) {
        if (!row.isObject() || !row.exists("kind") || !row["kind"].isStr() || !row.exists("wire_kind") ||
            !row["wire_kind"].isNum()) {
            err = "BTX035_SCHEMA";
            return false;
        }
        const int wire = row["wire_kind"].getInt<int>();
        const std::string kind = row["kind"].get_str();
        if (wire < 0 || wire > 15 || seen[wire] || kind.empty() || out.kind_set.count(kind)) {
            err = "BTX035_SCHEMA";
            return false;
        }
        seen[wire] = true;
        out.kinds[wire] = kind;
        out.kind_set.insert(kind);
    }
    for (bool ok : seen) {
        if (!ok) {
            err = "BTX035_SCHEMA";
            return false;
        }
    }
    if (out.kinds[15] != "RECORD") {
        err = "BTX035_SCHEMA";
        return false;
    }
    for (const UniValue& row : doc["record_descriptors"].getValues()) {
        if (!row.isObject() || !row.exists("record_type") || !row["record_type"].isStr()) {
            err = "BTX035_SCHEMA";
            return false;
        }
        const std::string type = row["record_type"].get_str();
        if (type.empty() || type.size() > 80 || !out.record_types.insert(type).second) {
            err = "BTX035_SCHEMA";
            return false;
        }
    }
    const UniValue& aliases = doc["semantic_aliases"];
    const std::vector<std::string>& keys = aliases.getKeys();
    const std::vector<UniValue>& values = aliases.getValues();
    for (size_t i = 0; i < keys.size(); ++i) {
        if (!values[i].isStr()) {
            err = "BTX035_SCHEMA";
            return false;
        }
        const std::string mapped = values[i].get_str();
        if (keys[i].empty() || out.kind_set.count(keys[i]) || !out.record_types.count(mapped)) {
            err = "BTX035_SCHEMA";
            return false;
        }
        out.semantic.emplace(keys[i], mapped);
    }
    return true;
}

bool CheckIdString(const std::string& s, const std::string& record_id, const std::set<std::string>& known, std::string& err)
{
    if (s == record_id || (IsLowerHex96(s) && !known.count(s))) {
        err = "BTX035_RECORD_ID";
        return false;
    }
    return true;
}

bool ScanPayload(const UniValue& value, const std::string& record_id, const std::set<std::string>& known, std::string& err)
{
    if (value.isStr()) return CheckIdString(value.get_str(), record_id, known, err);
    if (value.isArray()) {
        for (const UniValue& element : value.getValues()) {
            if (!ScanPayload(element, record_id, known, err)) return false;
        }
        return true;
    }
    if (value.isObject()) {
        const std::vector<std::string>& keys = value.getKeys();
        const std::vector<UniValue>& values = value.getValues();
        for (size_t i = 0; i < keys.size(); ++i) {
            if (!CheckIdString(keys[i], record_id, known, err)) return false;
            if (!ScanPayload(values[i], record_id, known, err)) return false;
        }
        return true;
    }
    return true;
}

} // namespace

bool AcceptCanonicalEnvelope(const UniValue& value, std::string& err)
{
    err.clear();
    std::vector<unsigned char> canon;
    if (!CanonicalEncode(value, canon, err)) return false;
    if (canon.size() > CANONICAL_MAX_ENVELOPE_V11) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    return true;
}

bool AcceptCompactJson(std::string_view utf8, std::string& err)
{
    err.clear();
    if (utf8.size() > CANONICAL_MAX_ENVELOPE_V11) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    if (!ValidUtf8(utf8)) {
        err = "BTX035_NONCANONICAL";
        return false;
    }
    UniValue parsed;
    if (!parsed.read(utf8)) {
        err = "BTX035_NONCANONICAL";
        return false;
    }
    return true;
}

bool AcceptTransportWrapper(std::string_view body, std::string& err)
{
    err.clear();
    if (body.size() > CANONICAL_MAX_ENVELOPE) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    return true;
}

bool AcceptManifestBlob(std::string_view blob, std::string& err)
{
    err.clear();
    if (blob.size() > CANONICAL_MAX_ENVELOPE_V11) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    return true;
}

bool SplitManifestPages(std::string_view blob, std::vector<std::string>& pages, std::string& err)
{
    err.clear();
    pages.clear();
    if (MANIFEST_PAGE_BYTES == 0 || MANIFEST_PAGE_BYTES > CANONICAL_MAX_ENVELOPE_V11) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    for (size_t off = 0; off < blob.size(); off += MANIFEST_PAGE_BYTES) {
        const size_t n = std::min(MANIFEST_PAGE_BYTES, blob.size() - off);
        if (n > CANONICAL_MAX_ENVELOPE_V11) {
            pages.clear();
            err = "BTX035_LIMIT_EXCEEDED";
            return false;
        }
        pages.emplace_back(blob.substr(off, n));
    }
    return true;
}

bool CanonicalOutputUri(std::string_view uri, std::string& err)
{
    err.clear();
    auto fail = [&]() {
        err = "BTX035_NONCANONICAL";
        return false;
    };
    if (HasUpper(uri) || uri.find('?') != std::string_view::npos || uri.find('#') != std::string_view::npos ||
        (!uri.empty() && uri.back() == '/') || HasExtensionSuffix(uri)) {
        return fail();
    }
    if (uri.size() != 91 || uri.substr(0, 6) != "btx://") return fail();
    if (!Bech32ResourceToken(uri.substr(6))) return fail();
    return true;
}

bool ParseLegacyInputUri(std::string_view text, std::string& canonical, std::string& err)
{
    err.clear();
    canonical.clear();
    if (text.find('?') != std::string_view::npos || text.find('#') != std::string_view::npos) {
        err = "BTX035_NONCANONICAL";
        return false;
    }
    std::string folded(text);
    if (!folded.empty() && folded.back() == '/') folded.pop_back();
    if (HasExtensionSuffix(folded)) {
        err = "BTX035_NONCANONICAL";
        return false;
    }
    for (char& c : folded) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::string_view token = folded;
    if (token.size() >= 6 && token.substr(0, 6) == "btx://") {
        token.remove_prefix(6);
    } else if (token.size() >= 4 && token.substr(0, 4) == "btx:") {
        token.remove_prefix(4);
    }
    canonical = "btx://" + std::string(token);
    if (!CanonicalOutputUri(canonical, err)) {
        canonical.clear();
        return false;
    }
    return true;
}

bool RegistryWireKind(const std::string& spec_path, int wire_kind, std::string& name, std::string& err)
{
    name.clear();
    Registry reg;
    if (!LoadRegistry(spec_path, reg, err)) return false;
    if (wire_kind < 0 || static_cast<size_t>(wire_kind) >= reg.kinds.size() || reg.kinds[wire_kind].empty()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    name = reg.kinds[wire_kind];
    return true;
}

bool ParseResourceRef(const UniValue& value, ResourceRef& out, std::string& err, const std::string& spec_path)
{
    err.clear();
    out = ResourceRef{};
    if (!value.isObject()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    for (const std::string& key : value.getKeys()) {
        if (key != "kind" && key != "digest48" && key != "record_type") {
            err = "BTX035_OBJECT_KEYS";
            return false;
        }
    }
    if (!value.exists("kind") || !value["kind"].isStr() || !value.exists("digest48") || !value["digest48"].isStr()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    Registry reg;
    if (!LoadRegistry(spec_path, reg, err)) return false;
    const std::string kind = value["kind"].get_str();
    const std::string digest = value["digest48"].get_str();
    if (reg.semantic.count(kind) || !reg.kind_set.count(kind) || !IsLowerHex96(digest)) {
        err = "BTX035_SCHEMA";
        return false;
    }
    const bool is_record = kind == "RECORD";
    if (is_record) {
        if (!value.exists("record_type") || !value["record_type"].isStr()) {
            err = "BTX035_SCHEMA";
            return false;
        }
        const std::string record_type = value["record_type"].get_str();
        if (!reg.record_types.count(record_type)) {
            err = "BTX035_SCHEMA";
            return false;
        }
        out.kind = kind;
        out.digest48 = digest;
        out.record_type = record_type;
        return true;
    }
    if (value.exists("record_type")) {
        err = "BTX035_SCHEMA";
        return false;
    }
    out.kind = kind;
    out.digest48 = digest;
    return true;
}

bool ParseLegacyKindAlias(const std::string& spec_path, std::string_view alias, std::string& canonical_kind,
                          std::string& record_type, std::string& err)
{
    err.clear();
    canonical_kind.clear();
    record_type.clear();
    Registry reg;
    if (!LoadRegistry(spec_path, reg, err)) return false;
    const auto it = reg.semantic.find(std::string(alias));
    if (it == reg.semantic.end()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    canonical_kind = "RECORD";
    record_type = it->second;
    return true;
}

bool PayloadTopology(const std::string& record_id, const UniValue& payload, const std::vector<std::string>& known_ids,
                     std::string& err)
{
    err.clear();
    if (!IsLowerHex96(record_id) || !payload.isObject()) {
        err = "BTX035_RECORD_ID";
        return false;
    }
    const std::set<std::string> known(known_ids.begin(), known_ids.end());
    return ScanPayload(payload, record_id, known, err);
}

} // namespace modelnet
