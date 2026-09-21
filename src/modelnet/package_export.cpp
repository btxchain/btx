// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_export.h>

#include <modelnet/package_bundle.h>

#include <cstring>

namespace modelnet {
namespace {

constexpr int kMaxJsonDepth = 32;

std::string NormalizeKey(std::string k)
{
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (c == '-') c = '_';
    }
    return k;
}

std::string CompactKey(const std::string& k)
{
    std::string c;
    c.reserve(k.size());
    for (char ch : k) {
        if (ch != '_') c.push_back(ch);
    }
    return c;
}

bool ScanPublic(const UniValue& v, std::string& err, int depth)
{
    if (depth > kMaxJsonDepth) {
        err = "nesting";
        return false;
    }
    if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (!ScanPublic(e, err, depth + 1)) return false;
        }
        return true;
    }
    if (!v.isObject()) return true;
    for (const auto& key : v.getKeys()) {
        if (PublicExportKeyForbidden(key)) {
            err = "secret-bearing key: " + key;
            return false;
        }
        if (!ScanPublic(v[key], err, depth + 1)) return false;
    }
    return true;
}

bool CopyOptionalStr(const UniValue& fields, const char* key, UniValue& out)
{
    if (!fields.exists(key) || !fields[key].isStr()) return true;
    out.pushKV(key, fields[key].get_str());
    return true;
}

} // namespace

bool PublicExportKeyForbidden(const std::string& key)
{
    const std::string k = NormalizeKey(key);
    const std::string c = CompactKey(k);
    if (k == "seed" || k == "seeds" || c == "seed" || c == "seeds") return true;
    if (k == "credential_ref" || k == "credential_refs" || c == "credentialref" || c == "credentialrefs") {
        return true;
    }
    auto has = [&](const char* n, const char* compact) {
        return k.find(n) != std::string::npos || c.find(compact) != std::string::npos;
    };
    return has("private_key", "privatekey") || has("password", "password") || has("passwd", "passwd") ||
           has("secret", "secret") || has("api_key", "apikey") || has("session_token", "sessiontoken") ||
           has("auth_token", "authtoken") || has("mnemonic", "mnemonic") || has("passkey", "passkey") ||
           has("presigned", "presigned") || has("credential_ref", "credentialref") ||
           has("wallet_seed", "walletseed");
}

bool PublicExportObjectAllowed(const UniValue& value, std::string& err)
{
    if (!value.isObject()) {
        err = "package must be object";
        return false;
    }
    return ScanPublic(value, err, 0);
}

bool UriQueryHasDn(const std::string& uri)
{
    const auto q = uri.find('?');
    if (q == std::string::npos) return false;
    size_t i = q + 1;
    while (i < uri.size()) {
        const size_t amp = uri.find('&', i);
        const size_t hash = uri.find('#', i);
        size_t end = uri.size();
        if (amp != std::string::npos && amp < end) end = amp;
        if (hash != std::string::npos && hash < end) end = hash;
        const std::string pair = uri.substr(i, end - i);
        if (pair == "dn" || pair.rfind("dn=", 0) == 0) return true;
        if (amp == std::string::npos || (hash != std::string::npos && hash < amp)) break;
        i = amp + 1;
    }
    return false;
}

bool LooksLikeBtxBundle(Span<const unsigned char> data)
{
    return data.size() >= 8 && std::memcmp(data.data(), BTXPKG_MAGIC, 8) == 0;
}

bool IsMagnetAnalogObject(const UniValue& value)
{
    if (!value.isObject()) return false;
    if (!value.exists("uri") || !value["uri"].isStr()) return false;
    if (!value.exists("copy_text") || !value["copy_text"].isStr()) return false;
    if (!value.exists("schema_version")) return false;
    return true;
}

bool EncodeMagnetAnalog(const UniValue& fields, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    if (!PublicExportObjectAllowed(fields, err)) return false;
    if (!fields.exists("uri") || !fields["uri"].isStr() || fields["uri"].get_str().empty()) {
        err = "uri required";
        return false;
    }
    const std::string uri = fields["uri"].get_str();
    if (UriQueryHasDn(uri)) {
        err = "dn= stays on copy_text only";
        return false;
    }
    if (fields.exists("automatic_spend_atoms")) {
        if (!fields["automatic_spend_atoms"].isNum() ||
            fields["automatic_spend_atoms"].getInt<int64_t>() != 0) {
            err = "spend mandate forbidden";
            return false;
        }
    }
    out.pushKV("schema_version", 2);
    if (fields.exists("kind") && fields["kind"].isStr() && !fields["kind"].get_str().empty()) {
        out.pushKV("kind", fields["kind"].get_str());
    } else {
        out.pushKV("kind", "MODEL");
    }
    out.pushKV("uri", uri);
    std::string copy = uri;
    if (fields.exists("copy_text") && fields["copy_text"].isStr() && !fields["copy_text"].get_str().empty()) {
        copy = fields["copy_text"].get_str();
    }
    out.pushKV("copy_text", copy);
    CopyOptionalStr(fields, "family", out);
    CopyOptionalStr(fields, "format", out);
    CopyOptionalStr(fields, "quantization", out);
    if (fields.exists("signed") && fields["signed"].isBool()) out.pushKV("signed", fields["signed"].get_bool());
    return true;
}

bool ParseMagnetAnalog(const UniValue& json, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    if (!PublicExportObjectAllowed(json, err)) return false;
    if (!IsMagnetAnalogObject(json)) {
        err = "magnet analog";
        return false;
    }
    if (UriQueryHasDn(json["uri"].get_str())) {
        err = "dn= stays on copy_text only";
        return false;
    }
    return EncodeMagnetAnalog(json, out, err);
}

bool EncodePublicBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (!PublicExportObjectAllowed(value, err)) return false;
    return EncodeBtxBundle(value, out, err);
}

bool DecodePublicBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    if (!DecodeBtxBundle(data, out, err)) return false;
    if (!PublicExportObjectAllowed(out, err)) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    return true;
}

bool EncodeLegacyAcquisitionExport(const UniValue& value, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    UniValue stripped(UniValue::VOBJ);
    if (value.isObject()) {
        for (const auto& k : value.getKeys()) {
            if (k == "agent_handoff") continue;
            if (k == "core" && value[k].isObject()) {
                UniValue core(UniValue::VOBJ);
                for (const auto& ck : value[k].getKeys()) {
                    if (ck == "agent_handoff") continue;
                    core.pushKV(ck, value[k][ck]);
                }
                stripped.pushKV("core", core);
                continue;
            }
            stripped.pushKV(k, value[k]);
        }
        stripped.pushKV("legacy_acquisition_export", true);
    } else {
        stripped = value;
    }
    return EncodePublicBtxBundle(stripped, out, err);
}

} // namespace modelnet
