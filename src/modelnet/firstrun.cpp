// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/firstrun.h>

#include <univalue.h>
#include <util/fs_helpers.h>
#include <util/readwritefile.h>

#include <cstdlib>
#include <stdexcept>

namespace modelnet {

fs::path FirstRunConsentPath(const fs::path& datadir)
{
    return datadir / "modelnet" / "firstrun.json";
}

bool ParseStorageBudget(const std::string& in, uint64_t& out, std::string& err)
{
    return ParseModelBytes(in, out, err);
}

bool AllowPayloadStorage(const FirstRunConsent& in)
{
    if (in.storage_mode == StorageMode::AUTO) return true;
    return in.storage_bytes > 0;
}

bool AllowPayloadStorageFile(const fs::path& path)
{
    FirstRunConsent c;
    std::string err;
    if (!LoadFirstRunConsent(path, c, err)) return false;
    return AllowPayloadStorage(c);
}

std::string ResolveHeadlessStorageArg(const std::string& requested, bool explicit_operator_choice, const fs::path& consent_path)
{
    if (requested == "0") return requested;
    if (explicit_operator_choice) return requested;
    FirstRunConsent saved;
    std::string saved_err;
    if (fs::exists(consent_path)) {
        // An existing refusal or malformed policy must never fall back to a positive default.
        if (!LoadFirstRunConsent(consent_path, saved, saved_err) || !AllowPayloadStorage(saved)) return "0";
        return saved.storage_mode == StorageMode::AUTO ? requested : std::to_string(saved.storage_bytes);
    }
    uint64_t env_bytes{0};
    std::string env_err;
    if (std::getenv("BTX_MODEL_STORAGE") != nullptr) {
        return EnvHasPositiveStorageBudget(env_bytes, env_err) ? std::to_string(env_bytes) : "0";
    }
    // A bounded starter cache allows free verified model acquisition on a fresh node.
    // The much larger adaptive budget still requires an explicit choice. This grants
    // neither execution nor private data access, and -modelstorage=0 remains final.
    return requested == "auto" ? "1GiB" : "0";
}

bool LoadFirstRunConsent(const fs::path& path, FirstRunConsent& out, std::string& err)
{
    out = FirstRunConsent{};
    const auto [ok, raw] = ReadBinaryFile(path, /*maxsize=*/65536);
    if (!ok || raw.empty()) {
        err = "no first-run storage consent";
        return false;
    }
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject()) {
        err = "invalid first-run consent";
        return false;
    }
    try {
        if (obj.exists("storage_bytes")) {
            const UniValue& v = obj["storage_bytes"];
            if (v.isStr()) {
                if (!ParseModelBytes(v.get_str(), out.storage_bytes, err)) return false;
            } else {
                out.storage_bytes = v.getInt<uint64_t>();
            }
        }
        if (obj.exists("storage_mode") && obj["storage_mode"].isStr()) {
            StorageMode mode;
            if (StorageModeFromName(obj["storage_mode"].get_str(), mode)) {
                out.storage_mode = mode;
            }
        } else if (out.storage_bytes > 0) {
            out.storage_mode = StorageMode::FIXED;
        } else {
            out.storage_mode = StorageMode::DISABLED;
        }
        if (obj.exists("seed") && obj["seed"].isStr()) {
            if (!SeedModeFromName(obj["seed"].get_str(), out.seed)) {
                err = "seed must be auto, manual, or off";
                return false;
            }
        }
        if (obj.exists("preserve_rare")) out.preserve_rare = obj["preserve_rare"].get_bool();
        if (obj.exists("resource_governor_auto")) {
            out.resource_governor_auto = obj["resource_governor_auto"].get_bool();
        }
        if (obj.exists("mining_idle")) out.mining_idle = obj["mining_idle"].get_bool();
        if (obj.exists("consented_unix")) out.consented_unix = obj["consented_unix"].getInt<int64_t>();
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return true;
}

bool SaveFirstRunConsent(const fs::path& path, const FirstRunConsent& in, std::string& err)
{
    try {
        if (!TryCreateDirectories(path.parent_path()) && !fs::exists(path.parent_path())) {
            err = "cannot create modelnet consent directory";
            return false;
        }
    } catch (const fs::filesystem_error& e) {
        err = e.what();
        return false;
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("storage_bytes", in.storage_bytes);
    o.pushKV("storage_mode", StorageModeName(in.storage_mode));
    o.pushKV("seed", SeedModeName(in.seed));
    o.pushKV("preserve_rare", in.preserve_rare);
    o.pushKV("resource_governor_auto", in.resource_governor_auto);
    o.pushKV("mining_idle", in.mining_idle);
    o.pushKV("consented_unix", in.consented_unix);
    if (!WriteBinaryFile(path, o.write() + "\n")) {
        err = "failed to write first-run consent";
        return false;
    }
    return true;
}

bool EnvHasPositiveStorageBudget(uint64_t& bytes, std::string& err)
{
    bytes = 0;
    const char* env = std::getenv("BTX_MODEL_STORAGE");
    if (!env || !*env) {
        err = "BTX_MODEL_STORAGE unset";
        return false;
    }
    if (!ParseModelBytes(env, bytes, err)) {
        bytes = 0;
        return false;
    }
    if (bytes == 0) {
        err = "BTX_MODEL_STORAGE is 0";
        return false;
    }
    return true;
}

} // namespace modelnet
