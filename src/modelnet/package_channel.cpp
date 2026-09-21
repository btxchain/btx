// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_channel.h>

#include <modelnet/package_core.h>
#include <modelnet/package_economy.h>
#include <modelnet/package_export.h>
#include <modelnet/types.h>
#include <util/fs.h>

#include <fstream>
#include <iterator>
#include <set>
#include <string>

namespace modelnet {
namespace {

const std::set<std::string> kRequired{
    "schema_version",
    "network",
    "publisher_id",
    "channel",
    "sequence",
    "target_package_core_id",
    "target_resource_ids",
    "issued_at_ms",
    "expires_at_ms",
    "signature_record_ref",
};

const std::set<std::string> kAllowed = [] {
    auto s = kRequired;
    s.insert("previous_statement_id");
    return s;
}();

void Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
}

bool CanonicalUnsignedDecimal(const std::string& s)
{
    if (s.empty() || s.size() > 20) return false;
    if (s[0] == '0') return s.size() == 1;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

int CompareUnsignedDecimal(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

bool ChannelNameOk(const std::string& s)
{
    if (s.empty() || s.size() > 64) return false;
    auto alnum = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    };
    if (!alnum(s[0])) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        const char c = s[i];
        if (!alnum(c) && c != '_' && c != '.' && c != '-') return false;
    }
    return true;
}

bool RequireHex96(const UniValue& v, const char* field, std::string& err_code, std::string& err)
{
    if (!v.exists(field) || !v[field].isStr()) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(field) + " required");
        return false;
    }
    Digest48 d;
    std::string hex_err;
    if (!Digest48::FromHex(v[field].get_str(), d, hex_err)) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(field) + " digest");
        return false;
    }
    return true;
}

bool RequireDecimal(const UniValue& v, const char* field, std::string& err_code, std::string& err)
{
    if (!v.exists(field) || !v[field].isStr() || !CanonicalUnsignedDecimal(v[field].get_str())) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", std::string(field) + " unsigned decimal");
        return false;
    }
    return true;
}

bool CopyStr(const UniValue& json, UniValue& out, const char* key)
{
    out.pushKV(key, json[key].get_str());
    return true;
}

} // namespace

bool ParseChannelStatement(const UniValue& json, UniValue& out, std::string& err_code, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    err_code.clear();
    err.clear();
    if (!json.isObject()) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "ChannelStatement object");
        return false;
    }
    for (const auto& key : json.getKeys()) {
        if (PublicExportKeyForbidden(key)) {
            Fail(err_code, err, "NONCANONICAL_PAYLOAD", "secret-bearing key: " + key);
            return false;
        }
        if (!kAllowed.count(key)) {
            Fail(err_code, err, "NONCANONICAL_PAYLOAD", "unknown ChannelStatement field");
            return false;
        }
    }
    for (const auto& key : kRequired) {
        if (!json.exists(key)) {
            Fail(err_code, err, "NONCANONICAL_PAYLOAD", "missing " + key);
            return false;
        }
    }
    if (!json["schema_version"].isNum() || json["schema_version"].getInt<int>() != 1) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "schema_version");
        return false;
    }
    if (!json["network"].isStr()) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "network");
        return false;
    }
    const std::string network = json["network"].get_str();
    if (network != "MAINNET" && network != "TESTNET" && network != "REGTEST") {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "network");
        return false;
    }
    if (!json["channel"].isStr() || !ChannelNameOk(json["channel"].get_str())) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "channel");
        return false;
    }
    if (!RequireHex96(json, "publisher_id", err_code, err)) return false;
    if (!RequireDecimal(json, "sequence", err_code, err)) return false;
    if (!RequireHex96(json, "target_package_core_id", err_code, err)) return false;
    if (!json["target_resource_ids"].isArray()) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "target_resource_ids");
        return false;
    }
    const auto& resources = json["target_resource_ids"].getValues();
    if (resources.size() > 256) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "target_resource_ids count");
        return false;
    }
    std::set<std::string> seen;
    UniValue ids(UniValue::VARR);
    for (const auto& item : resources) {
        if (!item.isStr()) {
            Fail(err_code, err, "NONCANONICAL_PAYLOAD", "target_resource_ids item");
            return false;
        }
        Digest48 d;
        std::string hex_err;
        if (!Digest48::FromHex(item.get_str(), d, hex_err) || !seen.insert(item.get_str()).second) {
            Fail(err_code, err, "NONCANONICAL_PAYLOAD", "target_resource_ids digest");
            return false;
        }
        ids.push_back(item.get_str());
    }
    if (!RequireDecimal(json, "issued_at_ms", err_code, err)) return false;
    if (!RequireDecimal(json, "expires_at_ms", err_code, err)) return false;
    if (CompareUnsignedDecimal(json["expires_at_ms"].get_str(), json["issued_at_ms"].get_str()) < 0) {
        Fail(err_code, err, "NONCANONICAL_PAYLOAD", "expires_at_ms before issued_at_ms");
        return false;
    }
    if (json.exists("previous_statement_id")) {
        if (!RequireHex96(json, "previous_statement_id", err_code, err)) return false;
    }
    if (!RequireHex96(json, "signature_record_ref", err_code, err)) return false;

    // ChannelStatement is coordination: it may name a core, never rewrite one.
    out.pushKV("schema_version", 1);
    CopyStr(json, out, "network");
    CopyStr(json, out, "publisher_id");
    CopyStr(json, out, "channel");
    CopyStr(json, out, "sequence");
    CopyStr(json, out, "target_package_core_id");
    out.pushKV("target_resource_ids", ids);
    CopyStr(json, out, "issued_at_ms");
    CopyStr(json, out, "expires_at_ms");
    if (json.exists("previous_statement_id")) CopyStr(json, out, "previous_statement_id");
    CopyStr(json, out, "signature_record_ref");
    return true;
}

bool ChannelRollback(const std::string& previous_seq, const std::string& next_seq)
{
    // Fail closed: non-canonical sequences are not a valid advance.
    if (!CanonicalUnsignedDecimal(previous_seq) || !CanonicalUnsignedDecimal(next_seq)) return true;
    return CompareUnsignedDecimal(next_seq, previous_seq) < 0;
}

bool ChannelEquivocation(const UniValue& a, const UniValue& b)
{
    UniValue pa, pb;
    std::string code, err;
    if (!ParseChannelStatement(a, pa, code, err) || !ParseChannelStatement(b, pb, code, err)) {
        return true;
    }
    if (pa["network"].get_str() != pb["network"].get_str()) return false;
    if (pa["publisher_id"].get_str() != pb["publisher_id"].get_str()) return false;
    if (pa["channel"].get_str() != pb["channel"].get_str()) return false;
    if (pa["sequence"].get_str() != pb["sequence"].get_str()) return false;
    return pa["target_package_core_id"].get_str() != pb["target_package_core_id"].get_str();
}

bool ChannelMutatesStaticCommitments(const UniValue& pinned_core, const UniValue& statement)
{
    UniValue parsed;
    std::string code, err;
    if (!ParseChannelStatement(statement, parsed, code, err)) return true;
    if (!pinned_core.isObject()) return true;
    Digest48 pinned_id;
    if (!PackageCoreId(pinned_core, pinned_id, err)) return true;
    if (parsed["target_package_core_id"].get_str() != pinned_id.Hex()) {
        // Distinct package core: the already-signed pin is unchanged.
        return false;
    }
    std::set<std::string> core_resources;
    if (pinned_core.exists("resources") && pinned_core["resources"].isArray()) {
        for (const auto& r : pinned_core["resources"].getValues()) {
            if (r.isObject() && r.exists("id") && r["id"].isStr()) {
                core_resources.insert(r["id"].get_str());
            }
        }
    }
    for (const auto& id : parsed["target_resource_ids"].getValues()) {
        if (!id.isStr() || !core_resources.count(id.get_str())) return true;
    }
    return false;
}

bool ChannelEconomicsStale(const UniValue& observation, int64_t now_ms, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    if (!observation.isObject() || !observation.exists("expires_at_ms") || !observation["expires_at_ms"].isStr()) {
        err_code = "STALE_ECONOMICS";
        err = "observation";
        return true;
    }
    if (!CanonicalUnsignedDecimal(observation["expires_at_ms"].get_str())) {
        err_code = "STALE_ECONOMICS";
        err = "expires_at_ms";
        return true;
    }
    if (CompareUnsignedDecimal(observation["expires_at_ms"].get_str(), std::to_string(now_ms < 0 ? 0 : now_ms)) < 0) {
        err_code = "STALE_ECONOMICS";
        err = "expired reward/terms";
        return true;
    }
    return false;
}

bool PackageTelemetryForbidden(const UniValue& core, std::string& err)
{
    auto scan = [&](auto&& self, const UniValue& v) -> bool {
        if (v.isStr()) {
            const std::string s = v.get_str();
            if (s.find("telemetry") != std::string::npos) {
                err = "telemetry sentinel";
                return true;
            }
        } else if (v.isArray()) {
            for (const auto& e : v.getValues()) {
                if (self(self, e)) return true;
            }
        } else if (v.isObject()) {
            for (const auto& k : v.getKeys()) {
                if (k.find("telemetry") != std::string::npos) {
                    err = "telemetry field";
                    return true;
                }
                if (self(self, v[k])) return true;
            }
        }
        return false;
    };
    return scan(scan, core);
}

bool ChannelHostnameIsPublisherTrust(const std::string& hostname)
{
    (void)hostname;
    return false;
}

bool PinChannelPackageBytes(Span<const unsigned char> bytes, Digest48& pinned_core_id, std::string& err)
{
    pinned_core_id = {};
    DecodedBtxPackage pkg;
    if (!DecodeBtxPackage(bytes, pkg, err)) return false;
    pinned_core_id = pkg.package_core_id;
    return true;
}

bool SaveChannelWatch(const std::string& path, const UniValue& statement, std::string& err_code, std::string& err)
{
    UniValue parsed;
    if (!ParseChannelStatement(statement, parsed, err_code, err)) return false;
    const fs::path p = fs::PathFromString(path);
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) {
        err_code = "IO_ERROR";
        err = "channel watch write";
        return false;
    }
    const std::string body = parsed.write() + "\n";
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
    return true;
}

bool LoadChannelWatch(const std::string& path, UniValue& out, std::string& err_code, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    std::ifstream in(fs::PathFromString(path), std::ios::binary);
    if (!in) {
        err_code = "IO_ERROR";
        err = "channel watch read";
        return false;
    }
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue json;
    if (!json.read(raw) || !json.isObject()) {
        err_code = "NONCANONICAL_PAYLOAD";
        err = "channel watch json";
        return false;
    }
    return ParseChannelStatement(json, out, err_code, err);
}

bool ChannelFollowIsExplicit(const UniValue& user_policy)
{
    return user_policy.isObject() && user_policy.exists("follow_channel") && user_policy["follow_channel"].isTrue();
}

} // namespace modelnet
