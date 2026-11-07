// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/profile.h>

#include <modelnet/policy.h>
#include <modelnet/auto_storage.h>
#include <univalue.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <set>

namespace modelnet {
namespace {

std::mutex g_host_bit_mu;
std::mutex g_profile_file_mu;
std::function<void(bool)> g_host_bit_hook;
std::atomic<bool> g_host_advertised{false};

std::string Lower(const std::string& in)
{
    return ToLower(in);
}

ProfilePolicy PersonalPreset()
{
    ProfilePolicy p;
    p.relay = false;
    p.index = false;
    p.host_mode = HostMode::AUTO;
    p.storage_arg = "auto";
    p.auto_cap_bytes = PERSONAL_AUTO_CAP_BYTES;
    p.upload_bps = PERSONAL_UPLOAD_BPS;
    p.follow_peers = true;
    p.preserve_rare = false;
    p.seed = "auto";
    return p;
}

ProfilePolicy InfrastructurePreset()
{
    ProfilePolicy p;
    p.relay = true;
    p.index = true;
    p.host_mode = HostMode::AUTO;
    p.storage_arg = "auto";
    p.auto_cap_bytes = INFRASTRUCTURE_AUTO_CAP_BYTES;
    p.upload_bps = INFRASTRUCTURE_UPLOAD_BPS;
    p.follow_peers = true;
    p.preserve_rare = true;
    p.seed = "auto";
    return p;
}

ProfilePolicy MirrorPreset()
{
    ProfilePolicy p;
    p.relay = true;
    p.index = true;
    p.host_mode = HostMode::AUTO;
    p.storage_arg = "auto";
    p.auto_cap_bytes = MIRROR_AUTO_CAP_BYTES;
    p.upload_bps = MIRROR_UPLOAD_BPS;
    p.follow_peers = true;
    p.preserve_rare = true;
    p.seed = "auto";
    return p;
}

bool JsonBool(const UniValue& obj, const char* key, bool& out)
{
    if (!obj.exists(key)) return true;
    const UniValue& v = obj[key];
    if (v.isBool()) {
        out = v.get_bool();
        return true;
    }
    if (v.isNum()) {
        out = v.getInt<int>() != 0;
        return true;
    }
    if (v.isStr()) {
        const std::string s = Lower(v.get_str());
        if (s == "1" || s == "true" || s == "yes" || s == "on") {
            out = true;
            return true;
        }
        if (s == "0" || s == "false" || s == "no" || s == "off") {
            out = false;
            return true;
        }
        return false;
    }
    return false;
}

} // namespace

const char* OperatorProfileName(OperatorProfile p)
{
    switch (p) {
    case OperatorProfile::PERSONAL: return "personal";
    case OperatorProfile::INFRASTRUCTURE: return "infrastructure";
    case OperatorProfile::MIRROR: return "mirror";
    case OperatorProfile::CUSTOM: return "custom";
    }
    return "custom";
}

bool ParseOperatorProfile(const std::string& in, OperatorProfile& out)
{
    const std::string s = Lower(in);
    if (s == "personal") {
        out = OperatorProfile::PERSONAL;
        return true;
    }
    if (s == "infrastructure") {
        out = OperatorProfile::INFRASTRUCTURE;
        return true;
    }
    if (s == "mirror") {
        out = OperatorProfile::MIRROR;
        return true;
    }
    if (s == "custom") {
        out = OperatorProfile::CUSTOM;
        return true;
    }
    return false;
}

const char* HostModeName(HostMode m)
{
    switch (m) {
    case HostMode::OFF: return "off";
    case HostMode::ON: return "on";
    case HostMode::AUTO: return "auto";
    }
    return "off";
}

bool ParseHostMode(const std::string& in, HostMode& out)
{
    const std::string s = Lower(in);
    if (s == "auto") {
        out = HostMode::AUTO;
        return true;
    }
    if (s == "1" || s == "true" || s == "on" || s == "yes") {
        out = HostMode::ON;
        return true;
    }
    if (s.empty() || s == "0" || s == "false" || s == "off" || s == "no") {
        out = HostMode::OFF;
        return true;
    }
    return false;
}

ProfilePolicy ApplyProfileOverrides(ProfilePolicy policy, const ProfileOverrides& existing)
{
    if (existing.relay) policy.relay = *existing.relay;
    if (existing.index) policy.index = *existing.index;
    if (existing.host_mode) policy.host_mode = *existing.host_mode;
    if (existing.storage_arg) policy.storage_arg = *existing.storage_arg;
    if (existing.auto_cap_bytes) policy.auto_cap_bytes = *existing.auto_cap_bytes;
    if (existing.upload_bps) policy.upload_bps = *existing.upload_bps;
    if (existing.follow_peers) policy.follow_peers = *existing.follow_peers;
    if (existing.preserve_rare) policy.preserve_rare = *existing.preserve_rare;
    if (existing.seed) policy.seed = *existing.seed;
    return policy;
}

ProfileOverrides OverridesFromPolicy(const ProfilePolicy& policy)
{
    ProfileOverrides o;
    o.relay = policy.relay;
    o.index = policy.index;
    o.host_mode = policy.host_mode;
    o.storage_arg = policy.storage_arg;
    o.auto_cap_bytes = policy.auto_cap_bytes;
    o.upload_bps = policy.upload_bps;
    o.follow_peers = policy.follow_peers;
    o.preserve_rare = policy.preserve_rare;
    o.seed = policy.seed;
    return o;
}

ProfilePolicy ResolveProfile(OperatorProfile profile, const ProfileOverrides& existing)
{
    ProfilePolicy p;
    switch (profile) {
    case OperatorProfile::PERSONAL:
        p = PersonalPreset();
        break;
    case OperatorProfile::INFRASTRUCTURE:
        p = InfrastructurePreset();
        break;
    case OperatorProfile::MIRROR:
        p = MirrorPreset();
        break;
    case OperatorProfile::CUSTOM:
        p = ProfilePolicy{};
        break;
    }
    return ApplyProfileOverrides(p, existing);
}

bool ParseProfileOverridesJson(const UniValue& value, ProfileOverrides& out, std::string& err)
{
    out = {};
    err.clear();
    if (!value.isObject()) { err = "overrides must be an object"; return false; }
    const std::set<std::string> allowed{"profile", "automatic_spend_atoms", "relay", "index", "host_mode",
        "storage_arg", "storage_bytes", "auto_cap_bytes", "upload_bps", "follow_peers", "preserve_rare", "seed"};
    std::set<std::string> seen;
    for (const auto& key : value.getKeys()) {
        if (!allowed.count(key) || !seen.insert(key).second) { err = "unknown or duplicate profile field: " + key; return false; }
    }
    auto boolean = [&](const char* key, std::optional<bool>& dest) {
        if (!value.exists(key)) return true;
        if (!value[key].isBool()) { err = std::string(key) + " must be boolean"; return false; }
        dest = value[key].get_bool(); return true;
    };
    auto count = [&](const char* key, std::optional<uint64_t>& dest) {
        if (!value.exists(key)) return true;
        uint64_t number = 0;
        if (value[key].isStr()) {
            if (!ParseModelBytes(value[key].get_str(), number, err)) return false;
        } else if (value[key].isNum()) {
            number = value[key].getInt<uint64_t>();
        } else { err = std::string(key) + " must be a nonnegative integer or byte-size string"; return false; }
        dest = number; return true;
    };
    try {
        if (value.exists("automatic_spend_atoms") &&
            !((value["automatic_spend_atoms"].isStr() && value["automatic_spend_atoms"].get_str() == "0") ||
              (value["automatic_spend_atoms"].isNum() && value["automatic_spend_atoms"].getValStr() == "0"))) {
            err = "automatic_spend_atoms must remain zero"; return false;
        }
        if (value.exists("profile") && !value["profile"].isStr()) { err = "profile must be a string"; return false; }
        if (!boolean("relay", out.relay) || !boolean("index", out.index) ||
            !boolean("follow_peers", out.follow_peers) || !boolean("preserve_rare", out.preserve_rare) ||
            !count("auto_cap_bytes", out.auto_cap_bytes) || !count("upload_bps", out.upload_bps)) return false;
        if (value.exists("host_mode")) {
            HostMode host;
            if (!value["host_mode"].isStr() || !ParseHostMode(value["host_mode"].get_str(), host)) {
                err = "host_mode must be auto, on, or off"; return false;
            }
            out.host_mode = host;
        }
        if (value.exists("storage_arg") && value.exists("storage_bytes")) {
            err = "supply only one of storage_arg and storage_bytes"; return false;
        }
        if (value.exists("storage_arg") || value.exists("storage_bytes")) {
            const auto& storage = value.exists("storage_arg") ? value["storage_arg"] : value["storage_bytes"];
            std::string text;
            if (storage.isNull() && value.exists("storage_bytes")) text = "auto";
            else if (storage.isStr()) text = storage.get_str();
            else if (storage.isNum()) text = std::to_string(storage.getInt<uint64_t>());
            else { err = "storage must be auto, a byte-size string, a nonnegative integer, or storage_bytes:null"; return false; }
            StorageMode mode;
            uint64_t bytes;
            if (!ParseModelStorage(text, mode, bytes, err)) return false;
            out.storage_arg = mode == StorageMode::AUTO ? "auto" : std::to_string(bytes);
        }
        if (value.exists("seed")) {
            SeedMode seed;
            if (!value["seed"].isStr() || !SeedModeFromName(value["seed"].get_str(), seed)) {
                err = "seed must be auto, manual, or off"; return false;
            }
            out.seed = SeedModeName(seed);
        }
    } catch (const std::exception& e) { err = e.what(); return false; }
    return true;
}

uint64_t EffectiveHostUploadBps(uint64_t profile_upload_bps, int64_t governor_upload_bps,
                                bool seeding_allowed)
{
    if (!seeding_allowed) return 0;
    if (governor_upload_bps <= 0) return 0;
    const uint64_t gov = static_cast<uint64_t>(governor_upload_bps);
    if (profile_upload_bps == 0) return gov;
    return profile_upload_bps < gov ? profile_upload_bps : gov;
}

fs::path OperatorProfilePath(const fs::path& modeldir)
{
    return modeldir / "operator_profile.json";
}

UniValue OperatorProfileToJson(OperatorProfile profile, const ProfilePolicy& policy)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("profile", OperatorProfileName(profile));
    o.pushKV("relay", policy.relay);
    o.pushKV("index", policy.index);
    o.pushKV("host_mode", HostModeName(policy.host_mode));
    o.pushKV("storage_arg", policy.storage_arg);
    o.pushKV("auto_cap_bytes", policy.auto_cap_bytes);
    o.pushKV("upload_bps", policy.upload_bps);
    o.pushKV("follow_peers", policy.follow_peers);
    o.pushKV("preserve_rare", policy.preserve_rare);
    o.pushKV("seed", policy.seed);
    return o;
}

bool LoadOperatorProfile(const fs::path& path, OperatorProfile& profile, ProfilePolicy& policy, std::string& err)
{
    profile = OperatorProfile::CUSTOM;
    policy = ProfilePolicy{};
    const auto [ok, raw] = ReadBinaryFile(path, /*maxsize=*/65536);
    if (!ok || raw.empty()) {
        err = "no operator profile";
        return false;
    }
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject()) {
        err = "invalid operator profile";
        return false;
    }
    try {
        if (obj.exists("profile") && obj["profile"].isStr()) {
            if (!ParseOperatorProfile(obj["profile"].get_str(), profile)) {
                err = "unknown profile name";
                return false;
            }
        }
        if (!JsonBool(obj, "relay", policy.relay)) {
            err = "relay";
            return false;
        }
        if (!JsonBool(obj, "index", policy.index)) {
            err = "index";
            return false;
        }
        if (obj.exists("host_mode") && obj["host_mode"].isStr()) {
            if (!ParseHostMode(obj["host_mode"].get_str(), policy.host_mode)) {
                err = "host_mode";
                return false;
            }
        }
        if (obj.exists("storage_arg") && obj["storage_arg"].isStr()) {
            policy.storage_arg = obj["storage_arg"].get_str();
        }
        if (obj.exists("auto_cap_bytes")) {
            const UniValue& v = obj["auto_cap_bytes"];
            if (v.isStr()) {
                uint64_t n = 0;
                if (!ParseModelBytes(v.get_str(), n, err)) return false;
                policy.auto_cap_bytes = n;
            } else {
                policy.auto_cap_bytes = v.getInt<uint64_t>();
            }
        }
        if (obj.exists("upload_bps")) {
            const UniValue& v = obj["upload_bps"];
            if (v.isStr()) {
                uint64_t n = 0;
                if (!ParseModelBytes(v.get_str(), n, err)) return false;
                policy.upload_bps = n;
            } else {
                policy.upload_bps = v.getInt<uint64_t>();
            }
        }
        if (!JsonBool(obj, "follow_peers", policy.follow_peers)) {
            err = "follow_peers";
            return false;
        }
        if (!JsonBool(obj, "preserve_rare", policy.preserve_rare)) {
            err = "preserve_rare";
            return false;
        }
        if (obj.exists("seed") && obj["seed"].isStr()) {
            policy.seed = obj["seed"].get_str();
        }
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return true;
}

bool SaveOperatorProfile(const fs::path& path, OperatorProfile profile, const ProfilePolicy& policy, std::string& err)
{
    std::lock_guard<std::mutex> file_lock(g_profile_file_mu);
    try {
        if (!TryCreateDirectories(path.parent_path()) && !fs::exists(path.parent_path())) {
            err = "cannot create operator profile directory";
            return false;
        }
    } catch (const fs::filesystem_error& e) {
        err = e.what();
        return false;
    }
    const fs::path temporary = path.parent_path() / fs::u8path(fs::PathToString(path.filename()) + ".tmp");
    if (IsSymlink(path) || IsSymlink(temporary)) {
        err = "operator profile paths must not be symbolic links";
        return false;
    }
    const std::string bytes = OperatorProfileToJson(profile, policy).write() + "\n";
    FILE* file = fsbridge::fopen(temporary, "wb");
    if (!file) {
        err = "failed to open temporary operator profile";
        return false;
    }
    const bool committed = fwrite(bytes.data(), 1, bytes.size(), file) == bytes.size() && FileCommit(file);
    const int closed = fclose(file);
    if (!committed || closed != 0 || !RenameOver(temporary, path)) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        err = "failed to commit operator profile";
        return false;
    }
    DirectoryCommit(path.parent_path());
    return true;
}

bool AutoHostShouldAdvertise(bool modelnet, bool helper_ready, uint64_t effective_storage,
                             bool has_verified_seeded_range, bool may_advertise_reachability)
{
    return modelnet && helper_ready && effective_storage > 0 && has_verified_seeded_range &&
           may_advertise_reachability;
}

void SetNodeModelHostAdvertised(bool on)
{
    const bool prev = g_host_advertised.exchange(on);
    if (prev == on) return;
    std::function<void(bool)> hook;
    {
        std::lock_guard<std::mutex> lock(g_host_bit_mu);
        hook = g_host_bit_hook;
    }
    if (hook) hook(on);
}

bool NodeModelHostAdvertisedWanted()
{
    return g_host_advertised.load();
}

void SetModelHostServiceBitHook(std::function<void(bool)> hook)
{
    std::function<void(bool)> installed;
    {
        std::lock_guard<std::mutex> lock(g_host_bit_mu);
        g_host_bit_hook = std::move(hook);
        installed = g_host_bit_hook;
    }
    if (installed) installed(g_host_advertised.load());
}

void ApplyModelHostServiceBit(bool on)
{
    SetNodeModelHostAdvertised(on);
}

} // namespace modelnet
