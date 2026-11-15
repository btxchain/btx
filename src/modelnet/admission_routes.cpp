// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>

#include <modelnet/lab_disk.h>
#include <univalue.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

std::mutex& StrictMu()
{
    static std::mutex mu;
    return mu;
}

std::unordered_map<std::string, StrictAdmissionRecord>& StrictModels()
{
    static std::unordered_map<std::string, StrictAdmissionRecord> models;
    return models;
}

struct AdmissionRow {
    std::string digest;
    std::string decision;
};

std::map<std::string, std::string>& DurableStrict()
{
    static std::map<std::string, std::string> ids;
    return ids;
}

std::map<std::string, AdmissionRow>& DurableAdmissions()
{
    static std::map<std::string, AdmissionRow> rows;
    return rows;
}

std::map<std::string, bool>& DurableLegacy()
{
    static std::map<std::string, bool> ids;
    return ids;
}

std::map<std::string, bool>& DurableRevoked()
{
    static std::map<std::string, bool> ids;
    return ids;
}

bool& RegistryCorrupt()
{
    static bool corrupt = false;
    return corrupt;
}

fs::path RegistryPath()
{
    const fs::path dir = LabDiskDirectory();
    if (dir.empty()) return {};
    return dir / "admission-registry.json";
}

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

UniValue StringList(const std::vector<std::string>& values)
{
    UniValue arr(UniValue::VARR);
    for (const std::string& value : values) arr.push_back(value);
    return arr;
}

bool ReadStringList(const UniValue& arr, std::vector<std::string>& out)
{
    out.clear();
    if (!arr.isArray()) return false;
    for (size_t i = 0; i < arr.size(); ++i) {
        if (!arr[i].isStr() || arr[i].get_str().empty()) return false;
        out.push_back(arr[i].get_str());
    }
    return true;
}

std::string EncodeRegistry()
{
    UniValue strict(UniValue::VARR);
    for (const auto& item : DurableStrict()) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("model_id", item.first);
        row.pushKV("digest", item.second);
        strict.push_back(std::move(row));
    }
    UniValue admissions(UniValue::VARR);
    for (const auto& item : DurableAdmissions()) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("model_id", item.first);
        row.pushKV("digest", item.second.digest);
        row.pushKV("decision", item.second.decision);
        admissions.push_back(std::move(row));
    }
    std::vector<std::string> legacy;
    for (const auto& item : DurableLegacy()) legacy.push_back(item.first);
    std::vector<std::string> revoked;
    for (const auto& item : DurableRevoked()) revoked.push_back(item.first);
    std::sort(legacy.begin(), legacy.end());
    std::sort(revoked.begin(), revoked.end());
    UniValue root(UniValue::VOBJ);
    root.pushKV("automatic_spend_atoms", "0");
    root.pushKV("strict", strict);
    root.pushKV("legacy", StringList(legacy));
    root.pushKV("admissions", admissions);
    root.pushKV("quarantine", StringList(QuarantineIds()));
    root.pushKV("revoked", StringList(revoked));
    return root.write();
}

bool ApplyRegistry(const std::string& bytes)
{
    UniValue root;
    if (!root.read(bytes) || !root.isObject()) return false;
    if (!root.exists("automatic_spend_atoms") || !root["automatic_spend_atoms"].isStr() ||
        root["automatic_spend_atoms"].get_str() != "0") {
        return false;
    }
    std::map<std::string, std::string> strict;
    if (root.exists("strict")) {
        if (!root["strict"].isArray()) return false;
        for (size_t i = 0; i < root["strict"].size(); ++i) {
            const UniValue& row = root["strict"][i];
            if (!row.isObject() || !row.exists("model_id") || !row["model_id"].isStr() || row["model_id"].get_str().empty() ||
                !row.exists("digest") || !row["digest"].isStr()) {
                return false;
            }
            strict.emplace(row["model_id"].get_str(), row["digest"].get_str());
        }
    }
    std::map<std::string, AdmissionRow> admissions;
    if (root.exists("admissions")) {
        if (!root["admissions"].isArray()) return false;
        for (size_t i = 0; i < root["admissions"].size(); ++i) {
            const UniValue& row = root["admissions"][i];
            if (!row.isObject() || !row.exists("model_id") || !row["model_id"].isStr() || row["model_id"].get_str().empty() ||
                !row.exists("digest") || !row["digest"].isStr() || !row.exists("decision") || !row["decision"].isStr() ||
                row["decision"].get_str().empty()) {
                return false;
            }
            AdmissionRow saved;
            saved.digest = row["digest"].get_str();
            saved.decision = row["decision"].get_str();
            admissions.emplace(row["model_id"].get_str(), std::move(saved));
        }
    }
    std::vector<std::string> legacy;
    std::vector<std::string> quarantine;
    std::vector<std::string> revoked;
    if (root.exists("legacy") && !ReadStringList(root["legacy"], legacy)) return false;
    if (root.exists("quarantine") && !ReadStringList(root["quarantine"], quarantine)) return false;
    if (root.exists("revoked") && !ReadStringList(root["revoked"], revoked)) return false;
    DurableStrict() = std::move(strict);
    DurableAdmissions() = std::move(admissions);
    DurableLegacy().clear();
    for (const std::string& id : legacy) DurableLegacy().emplace(id, true);
    DurableRevoked().clear();
    for (const std::string& id : revoked) DurableRevoked().emplace(id, true);
    ReplaceQuarantine(quarantine);
    return true;
}

bool ReadRegistryFile(std::string& bytes)
{
    const fs::path path = RegistryPath();
    if (path.empty()) return false;
    FILE* file = fsbridge::fopen(path, "rb");
    if (!file) return false;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return false;
    }
    const long size = ftell(file);
    if (size < 0 || size > 8 * 1024 * 1024) {
        fclose(file);
        return false;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return false;
    }
    bytes.resize(static_cast<size_t>(size));
    const size_t n = size == 0 ? 0 : fread(bytes.data(), 1, bytes.size(), file);
    const int closed = fclose(file);
    return closed == 0 && n == bytes.size();
}

bool WriteRegistryFile()
{
    const fs::path dir = LabDiskDirectory();
    if (dir.empty()) return true;
    if (!fs::exists(dir)) {
        if (!fs::create_directories(dir)) return false;
    }
    const std::string bytes = EncodeRegistry();
    const fs::path dest = dir / "admission-registry.json";
    const fs::path tmp = dir / "admission-registry.json.tmp";
    FILE* file = fsbridge::fopen(tmp, "wb");
    if (!file) return false;
    const size_t n = bytes.empty() ? 0 : fwrite(bytes.data(), 1, bytes.size(), file);
    const bool committed = n == bytes.size() && FileCommit(file);
    const int closed = fclose(file);
    if (!committed || closed != 0 || !RenameOver(tmp, dest)) {
        fs::remove(tmp);
        return false;
    }
    DirectoryCommit(dir);
    return true;
}

void ReloadRegistryLocked()
{
    const fs::path path = RegistryPath();
    if (path.empty()) {
        RegistryCorrupt() = false;
        return;
    }
    bool present = false;
    try {
        present = fs::exists(path);
    } catch (const std::filesystem::filesystem_error&) {
        RegistryCorrupt() = true;
        return;
    }
    if (!present) {
        RegistryCorrupt() = false;
        return;
    }
    std::string bytes;
    if (!ReadRegistryFile(bytes) || !ApplyRegistry(bytes)) {
        RegistryCorrupt() = true;
        return;
    }
    RegistryCorrupt() = false;
}

/**
 * Load the durable file before a change, so the write that follows keeps the
 * rows an earlier run wrote. False when the file cannot be read: the caller
 * then leaves it in place for recovery instead of overwriting it from memory.
 */
bool ReloadBeforeWriteLocked()
{
    ReloadRegistryLocked();
    return !RegistryCorrupt();
}

std::string StrictDigestLocked(const std::string& model_id)
{
    const auto memory = StrictModels().find(model_id);
    if (memory != StrictModels().end() && !memory->second.digest.empty()) return memory->second.digest;
    const auto durable = DurableStrict().find(model_id);
    if (durable == DurableStrict().end()) return {};
    return durable->second;
}

bool StrictModelLocked(const std::string& model_id)
{
    return StrictModels().count(model_id) != 0 || DurableStrict().count(model_id) != 0;
}

bool AdmittedExactLocked(const std::string& model_id, const std::string& digest)
{
    const auto it = DurableAdmissions().find(model_id);
    if (it == DurableAdmissions().end()) return false;
    return it->second.decision == "ADMITTED" && it->second.digest == digest;
}

bool RouteDecision(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    // Quarantine wins over a hash match and over a record that would serve.
    if (Serve(model_id, true).code == "BTX035_QUARANTINE") {
        admission = "BTX035_QUARANTINE";
        return false;
    }

    StrictAdmissionRecord record;
    {
        std::lock_guard<std::mutex> lock(StrictMu());
        const auto it = StrictModels().find(model_id);
        if (it == StrictModels().end()) {
            admission.clear();
            return true;
        }
        record = it->second;
    }

    const AdmissionResult result = Admit(record.assurance, byte_hash_matches, record.intervals, record.total,
                                         record.start_state, record.final_state, record.independent_roots,
                                         record.owner_authorized);
    if (!result.ServeAllowed()) {
        admission = result.code;
        return false;
    }
    admission.clear();
    return true;
}

} // namespace

void RegisterStrictModel(const std::string& model_id, StrictAdmissionRecord record)
{
    if (model_id.empty()) return;
    std::lock_guard<std::mutex> lock(StrictMu());
    const bool writable = ReloadBeforeWriteLocked();
    DurableStrict()[model_id] = record.digest;
    DurableLegacy().erase(model_id);
    StrictModels()[model_id] = std::move(record);
    if (writable) WriteRegistryFile();
}

void RegisterLegacyModel(const std::string& model_id)
{
    if (model_id.empty()) return;
    std::lock_guard<std::mutex> lock(StrictMu());
    const bool writable = ReloadBeforeWriteLocked();
    DurableLegacy()[model_id] = true;
    DurableStrict().erase(model_id);
    StrictModels().erase(model_id);
    if (writable) WriteRegistryFile();
}

bool RecordModelAdmission(const std::string& model_id, const std::string& digest, const std::string& decision, std::string& err)
{
    if (model_id.empty() || decision.empty()) return Fail(err, "BTX035_SCHEMA");
    std::lock_guard<std::mutex> lock(StrictMu());
    if (!ReloadBeforeWriteLocked()) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    if (DurableStrict().count(model_id) == 0) DurableStrict()[model_id] = digest;
    else if (DurableStrict()[model_id].empty()) DurableStrict()[model_id] = digest;
    AdmissionRow row;
    row.digest = digest;
    row.decision = decision;
    DurableAdmissions()[model_id] = std::move(row);
    if (decision == "REVOKED") DurableRevoked()[model_id] = true;
    if (!WriteRegistryFile()) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    err.clear();
    return true;
}

void RevokeModel(const std::string& model_id)
{
    if (model_id.empty()) return;
    std::lock_guard<std::mutex> lock(StrictMu());
    const bool writable = ReloadBeforeWriteLocked();
    DurableRevoked()[model_id] = true;
    const auto it = DurableAdmissions().find(model_id);
    if (it != DurableAdmissions().end()) it->second.decision = "REVOKED";
    if (writable) WriteRegistryFile();
}

void ClearAdmissionMemory()
{
    std::lock_guard<std::mutex> lock(StrictMu());
    StrictModels().clear();
    DurableStrict().clear();
    DurableAdmissions().clear();
    DurableLegacy().clear();
    DurableRevoked().clear();
    RegistryCorrupt() = false;
    ClearQuarantineMemory();
}

void RememberQuarantine(const std::string& model_id)
{
    if (model_id.empty()) return;
    std::lock_guard<std::mutex> lock(StrictMu());
    const bool writable = ReloadBeforeWriteLocked();
    // The reload replaced the in-memory set with the file's list. Keep this id.
    AddQuarantine(model_id);
    if (writable) WriteRegistryFile();
}

bool RouteMayServe(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    return RouteDecision(model_id, byte_hash_matches, admission);
}

bool RouteMayGenerate(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    return RouteDecision(model_id, byte_hash_matches, admission);
}

bool LivePathAllowed(const std::string& model_id, bool generate, std::string& code)
{
    std::lock_guard<std::mutex> lock(StrictMu());
    ReloadRegistryLocked();
    if (RegistryCorrupt()) {
        code = "BTX035_RECOVERY_REQUIRED";
        return false;
    }
    if (Serve(model_id, true).code == "BTX035_QUARANTINE" || DurableRevoked().count(model_id) != 0) {
        code = "BTX035_QUARANTINE";
        return false;
    }
    if (DurableLegacy().count(model_id) != 0) {
        code.clear();
        return true;
    }
    if (StrictModelLocked(model_id)) {
        const std::string digest = StrictDigestLocked(model_id);
        if (!AdmittedExactLocked(model_id, digest)) {
            code = "BTX035_ADMISSION";
            return false;
        }
        code.clear();
        return true;
    }
    // No strict record and no quarantine. Existing call sites stay allowed.
    (void)generate;
    code.clear();
    return true;
}

} // namespace modelnet
