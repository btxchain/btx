// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/helper.h>

#include <modelnet/bootstrap_distributor.h>
#include <modelnet/bulk_controller.h>
#include <modelnet/catalog.h>
#include <modelnet/erasure_manifest.h>
#include <modelnet/erasure_store.h>
#include <modelnet/hello_caps.h>
#include <modelnet/piece_picker.h>
#include <modelnet/import_coordinator.h>
#include <modelnet/index_reconcile.h>
#include <modelnet/io_executor.h>
#include <modelnet/lan_discovery.h>
#include <modelnet/multipart_journal.h>
#include <modelnet/object_layout.h>
#include <modelnet/origin_broker.h>
#include <modelnet/package_acquisition.h>
#include <modelnet/package_channel.h>
#include <modelnet/package_core.h>
#include <modelnet/capability_types.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_economy.h>
#include <modelnet/package_execute.h>
#include <modelnet/package_export.h>
#include <modelnet/package_install.h>
#include <modelnet/package_runtime.h>
#include <modelnet/physical_dedup.h>
#include <modelnet/query_router.h>
#include <modelnet/residency_state.h>
#include <modelnet/selective_files.h>
#include <modelnet/source_huggingface.h>
#include <modelnet/source_local.h>
#include <modelnet/source_policy.h>
#include <modelnet/source_torrent.h>
#include <modelnet/subpiece.h>
#include <modelnet/upload_scheduler.h>
#include <modelnet/upload_scheduler_drr.h>
#include <modelnet/verified_manifest.h>
#include <crypto/hex_base.h>
#include <span.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

namespace modelnet {
namespace {

std::mutex g_n02_mu;
std::map<std::string, std::shared_ptr<ImportCoordinator>> g_imports;
OriginBroker g_origin;
LowPriorityBulkController g_bulk;
IoExecutor g_io;
UploadSchedulerDrr g_drr;
std::unique_ptr<BootstrapDistributor> g_bootstrap;
UploadAdmission g_upload_adm;
MultipartJournal g_mpu;
SelectiveFileSet g_selective;
std::unique_ptr<ReverseTorrentBridge> g_torrent_rev;

struct AcqJob {
    AcquisitionPlan plan;
    std::string state{"PLANNED"};
    UniValue receipt{UniValue::VOBJ};
    uint64_t reserved_bytes{0};
    std::string exec_fp;
};
std::map<std::string, AcqJob> g_acq;

struct StorageMigrationJournal {
    bool planned{false};
    bool executed{false};
    ObjectLayoutPlan plan;
};
StorageMigrationJournal g_migrate;

struct Network02IdemEntry {
    std::string body_fp;
    UniValue result;
    std::string err_code;
    std::string err;
    bool ok{true};
};
std::mutex g_n02_idem_mu;
std::map<std::string, Network02IdemEntry> g_n02_idem;
std::map<std::string, Network02IdemEntry> g_acq_exec_idem;

std::string CanonicalNetwork02WriteMethod(const std::string& method)
{
    if (method == "addmodelstorage") return "setcloudstorage";
    if (method == "exportbtxpackage") return "exportbtxbundle";
    return method;
}

bool IsNetwork02CostlyWrite(const std::string& method)
{
    return method == "setcloudstorage" || method == "executemodelimport" || method == "createbtxpackage" ||
           method == "exportbtxbundle" || method == "preparemodelerasure" || method == "executemodelerasure" ||
           method == "setbootstrapdistributor" || method == "setmodeluploadpolicy" ||
           method == "planmodelstoragemigration" || method == "executemodelstoragemigration" ||
           method == "setmodelswarmhealer" || method == "settorrentsourcepolicy" ||
           method == "setmodeldiscoverypolicy" || method == "setmodelmirror" || method == "setmodelstoragepolicy";
}

std::string Network02IdempotencyKey(const UniValue& o)
{
    if (o.exists("idempotency_key") && o["idempotency_key"].isStr()) return o["idempotency_key"].get_str();
    return {};
}

std::string Network02IdemCaller(const UniValue& o)
{
    if (o.exists("caller") && o["caller"].isStr()) return o["caller"].get_str();
    if (o.exists("caller_id") && o["caller_id"].isStr()) return o["caller_id"].get_str();
    if (o.exists("as") && o["as"].isStr()) return o["as"].get_str();
    return {};
}

std::string Network02IdemScope(const std::string& caller, const std::string& method, const std::string& key)
{
    std::string scope;
    scope.reserve(caller.size() + method.size() + key.size() + 2);
    scope.append(caller);
    scope.push_back('\0');
    scope.append(method);
    scope.push_back('\0');
    scope.append(key);
    return scope;
}

std::string Network02BodyFingerprint(const UniValue& o)
{
    UniValue stripped(UniValue::VOBJ);
    if (o.isObject()) {
        std::vector<std::string> keys = o.getKeys();
        std::sort(keys.begin(), keys.end());
        for (const auto& k : keys) {
            if (k == "idempotency_key" || k == "caller" || k == "caller_id" || k == "as") continue;
            stripped.pushKV(k, o[k]);
        }
    }
    return stripped.write();
}

void Network02IdemFail(UniValue& result, std::string& err_code, std::string& err, const std::string& code,
                       const std::string& message)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 1);
    result.pushKV("automatic_spend_atoms", 0);
    if (code == "IDEMPOTENCY_CONFLICT") result.pushKV("status", "REJECTED");
    err_code = code;
    err = message;
}

std::string ExecuteAcqPlanFingerprint(const UniValue& o)
{
    UniValue stripped(UniValue::VOBJ);
    if (o.exists("plan_id")) stripped.pushKV("plan_id", o["plan_id"]);
    if (o.exists("verified_local_files")) stripped.pushKV("verified_local_files", o["verified_local_files"]);
    return stripped.write();
}

/** Caller-scoped executebtxacquisition store. Missing key keeps existing
 *  unkeyed execute behavior (other NETWORK-02 costly writes still require a
 *  key). Lookup runs before plan_id MODEL_READY so a conflicting files set
 *  cannot replay the first job_id as success. */
bool WithExecuteAcquisitionIdempotency(const UniValue& o, UniValue& result, std::string& err_code, std::string& err,
                                      const std::function<bool()>& once)
{
    const std::string key = Network02IdempotencyKey(o);
    if (key.empty()) return once();
    const std::string scope = Network02IdemScope(Network02IdemCaller(o), "executebtxacquisition", key);
    const std::string fp = Network02BodyFingerprint(o);
    {
        std::lock_guard<std::mutex> lock(g_n02_idem_mu);
        auto it = g_acq_exec_idem.find(scope);
        if (it != g_acq_exec_idem.end()) {
            if (it->second.body_fp != fp) {
                Network02IdemFail(result, err_code, err, "IDEMPOTENCY_CONFLICT", "idempotency conflict");
                return false;
            }
            result = it->second.result;
            err_code = it->second.err_code;
            err = it->second.err;
            return it->second.ok;
        }
    }
    const bool ok = once();
    std::lock_guard<std::mutex> lock(g_n02_idem_mu);
    auto it = g_acq_exec_idem.find(scope);
    if (it != g_acq_exec_idem.end()) {
        if (it->second.body_fp != fp) {
            Network02IdemFail(result, err_code, err, "IDEMPOTENCY_CONFLICT", "idempotency conflict");
            return false;
        }
        result = it->second.result;
        err_code = it->second.err_code;
        err = it->second.err;
        return it->second.ok;
    }
    Network02IdemEntry entry;
    entry.body_fp = fp;
    entry.result = result;
    entry.err_code = err_code;
    entry.err = err;
    entry.ok = ok;
    g_acq_exec_idem.emplace(scope, std::move(entry));
    return ok;
}

fs::path HelperRoot(const ModelCatalog& cat)
{
    return cat.Store().Root().parent_path();
}

UniValue Arg0(const UniValue& params)
{
    if (params.isArray() && params.size() > 0) {
        if (params[0].isObject()) return params[0];
        return params[0];
    }
    if (params.isObject()) return params;
    return UniValue(UniValue::VOBJ);
}

UniValue ObjectArg(const UniValue& params)
{
    UniValue o = Arg0(params);
    if (o.isArray() && o.size() > 0 && o[0].isObject()) return o[0];
    if (!o.isObject()) return UniValue(UniValue::VOBJ);
    return o;
}

int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::vector<std::string> CatalogModelIds(ModelCatalog& cat)
{
    UniValue listed;
    cat.List(listed);
    std::vector<std::string> ids;
    if (!listed.exists("models") || !listed["models"].isArray()) return ids;
    for (const auto& m : listed["models"].getValues()) {
        if (m.exists("model_id") && m["model_id"].isStr()) ids.push_back(m["model_id"].get_str());
    }
    return ids;
}

const char* ReconcileStatusName(ReconcileStatus s)
{
    switch (s) {
    case ReconcileStatus::EQUAL: return "EQUAL";
    case ReconcileStatus::WANT: return "WANT";
    case ReconcileStatus::DIVIDE: return "DIVIDE";
    case ReconcileStatus::REJECT: return "REJECT";
    }
    return "REJECT";
}

UniValue EvaluatedTransportJson()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("utp", "NONSHIPPING");
    o.pushKV("quic", false);
    o.pushKV("content_defined_dedup", "NONSHIPPING");
    o.pushKV("erasure_64_80", "NONSHIPPING");
    o.pushKV("catalog_10m", "NOT_RUN");
    o.pushKV("btx_torrentd_process", false);
    o.pushKV("live_hf_http", false);
    o.pushKV("live_r2_wan", "NOT_RUN");
    o.pushKV("pq1_swarm_only", true);
    return o;
}

bool ExecuteImport(ModelCatalog& cat, const UniValue& o, UniValue& result, std::string& err_code, std::string& err)
{
    ImportPlan plan;
    if (!ParseImportPlan(o, plan, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        auto it = g_imports.find(plan.plan_id);
        if (it != g_imports.end() && it->second) {
            result = it->second->StatusJson();
            result.pushKV("idempotent", true);
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("live_http", false);
            return true;
        }
    }
    auto coord = std::make_shared<ImportCoordinator>(plan, HelperRoot(cat) / fs::PathFromString("import-jobs"));
    if (!coord->PrepareStaging(err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    result = coord->StatusJson();
    result.pushKV("automatic_spend_atoms", 0);
    result.pushKV("live_http", false);
    result.pushKV("torrentd_process", false);
    result.pushKV("authorship", "not implied by source integrity");

    if (plan.kind == ImportSourceKind::LOCAL && !plan.locator.empty() && fs::exists(fs::PathFromString(plan.locator))) {
        CatalogEntry imported;
        if (!cat.ImportPath(plan.locator, /*pin=*/false, imported, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        UniValue man;
        if (!cat.GetManifest(imported.model_id, man, err)) {
            err_code = "INTERNAL_ERROR";
            return false;
        }
        VerifiedManifest vm;
        if (!VerifyManifestAgainstRequest(man, vm, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        if (!coord->AcceptVerifiedManifest(vm, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result = coord->StatusJson();
        result.pushKV("imported", true);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("live_http", false);
        result.pushKV("authorship", "not implied by source integrity");
    } else if (plan.kind == ImportSourceKind::HUGGINGFACE) {
        HuggingFaceByteSource src(plan.locator, plan.snapshot_token, /*follow_redirects=*/false);
        std::string perr;
        const bool pin_ok = src.Pin(perr);
        result.pushKV("pin_ok", pin_ok);
        result.pushKV("pin_error", perr);
        result.pushKV("provenance_note", HUGGINGFACE_PROVENANCE_NOTE);
    } else if (plan.kind == ImportSourceKind::TORRENT || plan.kind == ImportSourceKind::MAGNET) {
        result.pushKV("infohash", ParseTorrentInfohash(plan.locator, plan.snapshot_token));
        result.pushKV("provenance_note", TORRENT_PROVENANCE_NOTE);
        result.pushKV("torrentd_process", false);
    } else if (plan.kind == ImportSourceKind::S3) {
        result.pushKV("note", "reuse setcloudstorage; source adapter not live HTTP");
    }

    std::lock_guard<std::mutex> lock(g_n02_mu);
    g_imports[plan.plan_id] = std::move(coord);
    return true;
}

bool PackageFromObject(const UniValue& o, UniValue& result, std::string& err_code, std::string& err)
{
    UniValue payload = o;
    if (o.exists("payload") && o["payload"].isObject()) payload = o["payload"];
    const int explicit_ver = (payload.exists("core") && payload["core"].isObject() && payload["core"].exists("version") &&
                               payload["core"]["version"].isNum()) ?
                                  payload["core"]["version"].getInt<int>() :
                                  (o.exists("core_version") && o["core_version"].isNum() ? o["core_version"].getInt<int>() : 0);
    const std::string profile = (o.exists("profile") && o["profile"].isStr()) ? o["profile"].get_str() : "";
    const bool core_v3 = explicit_ver == 3 || profile == "capability_handoff" ||
                          (payload.exists("core") && payload["core"].isObject() &&
                           (payload["core"].exists("capability_handoff") || payload["core"].exists("capability_recipes")));
    const bool core_v2 = !core_v3 &&
                          ((explicit_ver == 2) || profile == "agent_handoff");
    std::vector<unsigned char> bytes;
    if (core_v3) {
        if (payload.exists("core") && payload["core"].isObject() && payload["core"].exists("network") &&
            payload["core"]["network"].isStr() && payload["core"]["network"].get_str() == "MAINNET") {
            err = "unsigned Core v3 create is REGTEST/TESTNET only";
            err_code = "NETWORK_FORBIDDEN";
            return false;
        }
        if (!PublicExportObjectAllowed(payload, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        Digest48 id;
        if (payload.exists("core") && payload["core"].isObject()) {
            UniValue core = payload["core"];
            if (!core.exists("version") || !core["version"].isNum() || core["version"].getInt<int>() != 3) {
                UniValue rebuilt(UniValue::VOBJ);
                rebuilt.pushKV("version", 3);
                for (const auto& k : core.getKeys()) {
                    if (k == "version") continue;
                    rebuilt.pushKV(k, core[k]);
                }
                UniValue ex = core.exists("critical_extensions") && core["critical_extensions"].isArray() ?
                                 core["critical_extensions"] :
                                 UniValue(UniValue::VARR);
                bool has_cap = false;
                for (const auto& e : ex.getValues()) {
                    if (e.isStr() && e.get_str() == CAPABILITY_HANDOFF_V1) has_cap = true;
                }
                if (!has_cap) ex.push_back(CAPABILITY_HANDOFF_V1);
                UniValue rebuilt2(UniValue::VOBJ);
                for (const auto& k : rebuilt.getKeys()) {
                    if (k == "critical_extensions") continue;
                    rebuilt2.pushKV(k, rebuilt[k]);
                }
                rebuilt2.pushKV("critical_extensions", ex);
                if (!rebuilt2.exists("capability_handoff") && rebuilt2.exists("agent_handoff") &&
                    rebuilt2["agent_handoff"].isObject()) {
                    UniValue ch = rebuilt2["agent_handoff"];
                    if (ch.exists("client_requirements") && ch["client_requirements"].isObject() &&
                        ch["client_requirements"].exists("required_capabilities") &&
                        ch["client_requirements"]["required_capabilities"].isArray()) {
                        UniValue caps(UniValue::VARR);
                        for (const auto& c : ch["client_requirements"]["required_capabilities"].getValues()) {
                            caps.push_back(c);
                        }
                        caps.push_back(BTXPKG_CORE_V3);
                        caps.push_back(CAPABILITY_HANDOFF_V1);
                        UniValue cr = ch["client_requirements"];
                        UniValue cr2(UniValue::VOBJ);
                        for (const auto& k : cr.getKeys()) {
                            if (k == "required_capabilities") continue;
                            cr2.pushKV(k, cr[k]);
                        }
                        cr2.pushKV("required_capabilities", caps);
                        UniValue ch2(UniValue::VOBJ);
                        for (const auto& k : ch.getKeys()) {
                            if (k == "client_requirements") continue;
                            ch2.pushKV(k, ch[k]);
                        }
                        ch2.pushKV("client_requirements", cr2);
                        rebuilt2.pushKV("capability_handoff", ch2);
                    } else {
                        rebuilt2.pushKV("capability_handoff", ch);
                    }
                }
                if (!rebuilt2.exists("capability_recipes")) rebuilt2.pushKV("capability_recipes", UniValue(UniValue::VARR));
                if (!rebuilt2.exists("runtime_requirements")) rebuilt2.pushKV("runtime_requirements", UniValue(UniValue::VARR));
                if (!rebuilt2.exists("verification_profiles")) rebuilt2.pushKV("verification_profiles", UniValue(UniValue::VARR));
                UniValue np(UniValue::VOBJ);
                for (const auto& k : payload.getKeys()) {
                    if (k == "core") continue;
                    np.pushKV(k, payload[k]);
                }
                np.pushKV("core", rebuilt2);
                payload = std::move(np);
                core = rebuilt2;
            }
            std::string vcode, verr;
            if (!LintPackagePortable(payload, verr)) {
                err = verr;
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (!ValidateCapabilityPackageCore(payload["core"], vcode, verr)) {
                err_code = vcode.empty() ? "NONCANONICAL_PAYLOAD" : vcode;
                err = verr;
                return false;
            }
            if (!PackageCoreId(payload["core"], id, err)) {
                err_code = "UNSUPPORTED_CORE_VERSION";
                return false;
            }
        }
        if (!EncodeBtxPackage(payload, bytes, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result.pushKV("schema_version", 1);
        result.pushKV("kind", "BINARY_BUNDLE");
        result.pushKV("core_version", 3);
        result.pushKV("package_core_id", id.Hex());
        result.pushKV("unsigned", true);
        result.pushKV("hex", HexStr(Span<const unsigned char>{bytes.data(), bytes.size()}));
        result.pushKV("bytes", static_cast<int>(bytes.size()));
        result.pushKV("magnet_analog", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("default_capability_writer", true);
    } else if (core_v2) {
        if (payload.exists("core") && payload["core"].isObject() && payload["core"].exists("network") &&
            payload["core"]["network"].isStr() && payload["core"]["network"].get_str() == "MAINNET") {
            err = "unsigned Core v2 create is REGTEST/TESTNET only";
            err_code = "NETWORK_FORBIDDEN";
            return false;
        }
        if (!PublicExportObjectAllowed(payload, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        Digest48 id;
        if (payload.exists("core") && payload["core"].isObject()) {
            std::string vcode, verr;
            if (!LintPackagePortable(payload, verr)) {
                err = verr;
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (!ValidateAgentPackageCore(payload["core"], vcode, verr)) {
                err_code = vcode.empty() ? "NONCANONICAL_PAYLOAD" : vcode;
                err = verr;
                return false;
            }
            if (!PackageCoreId(payload["core"], id, err)) {
                err_code = "UNSUPPORTED_CORE_VERSION";
                return false;
            }
            std::vector<std::string> flags;
            if (payload["core"].exists("documents")) {
                PackageDocument agents_doc;
                std::string derr;
                if (GetPackageDocument(payload["core"], "AGENTS.md", agents_doc, derr)) {
                    (void)LintAgentsContradictions(payload["core"], agents_doc.text, flags);
                }
            }
            UniValue lint(UniValue::VARR);
            for (const auto& f : flags) lint.push_back(f);
            result.pushKV("lint_flags", lint);
        }
        if (!EncodeBtxPackage(payload, bytes, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result.pushKV("schema_version", 1);
        result.pushKV("kind", "BINARY_BUNDLE");
        result.pushKV("core_version", 2);
        result.pushKV("package_core_id", id.Hex());
        result.pushKV("unsigned", true);
        result.pushKV("hex", HexStr(Span<const unsigned char>{bytes.data(), bytes.size()}));
        result.pushKV("bytes", static_cast<int>(bytes.size()));
        result.pushKV("magnet_analog", false);
        result.pushKV("automatic_spend_atoms", 0);
    } else if (!EncodePublicBtxBundle(payload, bytes, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    } else {
        result.pushKV("schema_version", 1);
        result.pushKV("kind", "BINARY_BUNDLE");
        result.pushKV("hex", HexStr(Span<const unsigned char>{bytes.data(), bytes.size()}));
        result.pushKV("bytes", static_cast<int>(bytes.size()));
        result.pushKV("magnet_analog", false);
    }
    if (o.exists("path") && o["path"].isStr() && !o["path"].get_str().empty()) {
        const fs::path path = fs::PathFromString(o["path"].get_str());
        const std::string name = fs::PathToString(path.filename());
        if (name == "AGENTS.md" || name == "agents.md") {
            err = "refusing to write AGENTS.md";
            err_code = "WORKSPACE_WRITE_FORBIDDEN";
            return false;
        }
        if (std::filesystem::is_symlink(path) ||
            (fs::exists(path.parent_path()) && std::filesystem::is_symlink(path.parent_path()))) {
            err = "refusing symlink package path";
            err_code = "SYMLINK_REFUSED";
            return false;
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "package write";
            err_code = "IO_ERROR";
            return false;
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        result.pushKV("path", o["path"].get_str());
    }
    return true;
}

bool LoadPackageBytes(const UniValue& o, std::vector<unsigned char>& bytes, std::string& err_code, std::string& err)
{
    bytes.clear();
    constexpr size_t kMaxPackageBytes = 68 + BTX_PACKAGE_MAX_PAYLOAD;
    if (o.exists("hex") && o["hex"].isStr()) {
        const std::string& hex = o["hex"].get_str();
        if (hex.size() > kMaxPackageBytes * 2) {
            err = "PACKAGE_TOO_LARGE";
            err_code = "PACKAGE_TOO_LARGE";
            return false;
        }
        const auto parsed = TryParseHex<unsigned char>(hex);
        if (!parsed) {
            err = "hex";
            err_code = "INVALID_PARAMETER";
            return false;
        }
        if (parsed->size() > kMaxPackageBytes) {
            err = "PACKAGE_TOO_LARGE";
            err_code = "PACKAGE_TOO_LARGE";
            return false;
        }
        bytes = *parsed;
        return true;
    }
    if (o.exists("path") && o["path"].isStr()) {
        std::ifstream in(fs::PathFromString(o["path"].get_str()), std::ios::binary);
        if (!in) {
            err = "package path";
            err_code = "INVALID_PARAMETER";
            return false;
        }
        char buf[4096];
        while (in) {
            in.read(buf, sizeof(buf));
            const std::streamsize n = in.gcount();
            if (n <= 0) break;
            if (bytes.size() + static_cast<size_t>(n) > kMaxPackageBytes) {
                bytes.clear();
                err = "PACKAGE_TOO_LARGE";
                err_code = "PACKAGE_TOO_LARGE";
                return false;
            }
            bytes.insert(bytes.end(), buf, buf + n);
        }
        return true;
    }
    err = "hex or path";
    err_code = "INVALID_PARAMETER";
    return false;
}

bool InspectPackage(const UniValue& o, UniValue& result, std::string& err_code, std::string& err)
{
    std::vector<unsigned char> bytes;
    if (!LoadPackageBytes(o, bytes, err_code, err)) return false;
    DecodedBtxPackage pkg;
    std::string perr;
    if (DecodeBtxPackage(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, perr)) {
        result.pushKV("ok", true);
        result.pushKV("frame_integrity", "PASS");
        result.pushKV("core_id", pkg.package_core_id.Hex());
        result.pushKV("core_version", pkg.core_version);
        result.pushKV("package_codec", "BTX-PJSON1");
        if (pkg.core.exists("network")) result.pushKV("network", pkg.core["network"]);
        if (pkg.core.exists("package_type")) result.pushKV("package_type", pkg.core["package_type"]);
        if (pkg.core.exists("label")) result.pushKV("label", pkg.core["label"]);
        UniValue docs(UniValue::VARR);
        if (pkg.core.exists("documents") && pkg.core["documents"].isArray()) {
            for (const auto& d : pkg.core["documents"].getValues()) {
                if (!d.isObject()) continue;
                UniValue e(UniValue::VOBJ);
                if (d.exists("path")) e.pushKV("path", d["path"]);
                if (d.exists("sha384")) e.pushKV("sha384", d["sha384"]);
                if (d.exists("size_bytes")) e.pushKV("size_bytes", d["size_bytes"]);
                docs.push_back(e);
            }
        }
        result.pushKV("documents", docs);
        std::string vcode, verr;
        const bool payload_ok = ValidatePackagePayload(pkg.payload, vcode, verr);
        result.pushKV("core_valid", payload_ok);
        if (!payload_ok) {
            result.pushKV("core_error", vcode);
            result.pushKV("core_error_detail", verr);
        }
        const bool signed_present = pkg.payload.exists("signatures") && pkg.payload["signatures"].isArray() &&
                                     !pkg.payload["signatures"].empty();
        result.pushKV("signature_status", signed_present ? "PRESENT_NOT_TRUSTED" : "UNSIGNED");
        if (signed_present) {
            bool all_ok = true;
            for (const auto& s : pkg.payload["signatures"].getValues()) {
                std::string sc, serr;
                if (!VerifyPackageCoreSignature(pkg.package_core_id, s, sc, serr)) all_ok = false;
            }
            result.pushKV("signature_cryptographic", all_ok ? "PASS" : "FAIL");
        }
        result.pushKV("publisher_trust", "NOT_EVALUATED");
        result.pushKV("native_uri_verification", "NOT_EVALUATED");
        result.pushKV("model_bytes_verified", false);
        result.pushKV("installed_software", false);
        result.pushKV("executed_runtime", false);
        result.pushKV("authorized_actions", UniValue(UniValue::VARR));
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("workspace_agents_written", false);
        result.pushKV("bundle", pkg.payload);
        result.pushKV("looks_like_btxbundle", LooksLikeBtxBundle(bytes));
        return true;
    }
    UniValue decoded;
    if (!DecodePublicBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()}, decoded, err)) {
        err_code = pkg.err_code.empty() ? "INVALID_PARAMETER" : pkg.err_code;
        if (err.empty()) err = perr;
        return false;
    }
    result.pushKV("ok", true);
    result.pushKV("bundle", decoded);
    result.pushKV("looks_like_btxbundle", LooksLikeBtxBundle(bytes));
    result.pushKV("package_codec", "BUNDLE_WRITE");
    result.pushKV("frame_integrity", "PASS");
    result.pushKV("signature_status", "NOT_EVALUATED");
    result.pushKV("publisher_trust", "NOT_EVALUATED");
    result.pushKV("automatic_spend_atoms", 0);
    return true;
}

bool ErasureFromObject(const UniValue& o, UniValue& result, std::string& err_code, std::string& err)
{
    ErasureManifest man;
    if (!ParseErasureManifest(o, man, err)) {
        err_code = "INVALID_PARAMETER";
        return false;
    }
    const ErasureHealth health = EvaluateErasureHealth(man);
    result.pushKV("manifest", ErasureManifestJson(man));
    result.pushKV("health", ErasureHealthJson(health));
    result.pushKV("reconstructable", health.reconstructable);
    result.pushKV("global_n_is_sufficiency", false);
    result.pushKV("canonical_identity_unchanged", true);
    bool repair_executed = false;
    if (o.exists("shards") && o["shards"].isArray() && o.exists("positions") && o["positions"].isArray()) {
        std::vector<std::vector<unsigned char>> shards;
        std::vector<int> positions;
        for (const auto& h : o["shards"].getValues()) {
            if (!h.isStr()) {
                err = "shard hex";
                err_code = "INVALID_PARAMETER";
                return false;
            }
            const auto parsed = TryParseHex<unsigned char>(h.get_str());
            if (!parsed) {
                err = "shard hex";
                err_code = "INVALID_PARAMETER";
                return false;
            }
            shards.push_back(*parsed);
        }
        for (const auto& p : o["positions"].getValues()) {
            if (!p.isNum()) {
                err = "position";
                err_code = "INVALID_PARAMETER";
                return false;
            }
            positions.push_back(p.getInt<int>());
        }
        std::vector<std::vector<unsigned char>> data_out;
        std::string rerr;
        int stripe_index = -1;
        if (o.exists("stripe_index")) {
            if (o["stripe_index"].isNum()) stripe_index = o["stripe_index"].getInt<int>();
            else if (o["stripe_index"].isStr()) {
                try {
                    stripe_index = std::stoi(o["stripe_index"].get_str());
                } catch (...) {
                    stripe_index = -1;
                }
            }
        }
        if (RepairCanonicalFromShards(man, shards, positions, data_out, rerr, stripe_index)) {
            repair_executed = true;
            result.pushKV("recovered_data_shards", static_cast<int>(data_out.size()));
        } else {
            result.pushKV("repair_error", rerr);
        }
    }
    result.pushKV("repair_executed", repair_executed);
    return true;
}

} // namespace

bool IsNetwork02HelperMethod(const std::string& method)
{
    return method == "executemodelimport" || method == "getmodelimport" || method == "cancelmodelimport" ||
           method == "resumemodelimport" || method == "publishmodelimport" || method == "createbtxpackage" ||
           method == "inspectbtxpackage" || method == "verifybtxpackage" || method == "importbtxpackage" ||
           method == "exportbtxbundle" || method == "preparemodelerasure" || method == "executemodelerasure" ||
           method == "getmodelerasurehealth" || method == "repairmodel" || method == "gettorrentsourcestatus" ||
           method == "getmodeloriginoffer" || method == "getmodeloriginstatus" || method == "querymodelsummary" ||
           method == "reconcilemodelindex" || method == "getmodelobjectlayout" || method == "validatesubpiece" ||
           method == "getmodelbulkstatus" || method == "getmodelioexecutor" || method == "getevaluatedtransport" ||
           method == "setbootstrapdistributor" || method == "getbootstrapstatus" ||
           method == "setmodeluploadpolicy" || method == "getmodeluploadinfo" ||
           method == "planmodelstoragemigration" || method == "executemodelstoragemigration" ||
           method == "setmodelswarmhealer" || method == "settorrentsourcepolicy" ||
           method == "getmodelroutingstatus" || method == "setmodeldiscoverypolicy" ||
           method == "getmodelresidency" || method == "getmodeldedupinfo" ||
           method == "getmodellandiscovery" || method == "getmodelfileselection" ||
           method == "getmultipartjournal" || method == "getsourcepolicy" ||
           method == "getbtxpackagedocument" || method == "getbtxpackagecapabilities" ||
           method == "planbtxacquisition" || method == "executebtxacquisition" ||
           method == "getbtxacquisition" || method == "cancelbtxacquisition" ||
           method == "planbtxclientinstall" || method == "planbtxruntime";
}

std::string ResolveHelperMethodAlias(const std::string& method, std::string& alias_of)
{
    alias_of.clear();
    static const std::pair<const char*, const char*> kAliases[] = {
        {"addmodelstorage", "setcloudstorage"},
        {"inspectmodelstorage", "testcloudstorage"},
        {"testmodelstorage", "testcloudstorage"},
        {"listmodelstorage", "getcloudstorageinfo"},
        {"getmodelcapabilities", "getmodelnetworkinfo"},
        {"getmodeltransfermetrics", "getmodeltransfers"},
        {"requestmodelorigin", "getmodeloriginoffer"},
        {"getmodeloriginhealth", "getmodeloriginstatus"},
        {"getmodelmirrorstatus", "getmodelmirror"},
        {"exportbtxpackage", "exportbtxbundle"},
    };
    for (const auto& p : kAliases) {
        if (method == p.first) {
            alias_of = p.second;
            return p.second;
        }
    }
    return method;
}

bool DispatchNetwork02RpcOnce(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                              std::string& err_code, std::string& err)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 1);
    result.pushKV("automatic_spend_atoms", 0);
    const UniValue o = ObjectArg(params);

    if (method == "getevaluatedtransport") {
        result = EvaluatedTransportJson();
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("capabilities", HelloCapabilityArray());
        return true;
    }
    if (method == "executemodelimport") {
        return ExecuteImport(cat, o, result, err_code, err);
    }
    if (method == "getmodelimport" || method == "cancelmodelimport" || method == "resumemodelimport" ||
        method == "publishmodelimport") {
        const std::string plan_id = o.exists("plan_id") && o["plan_id"].isStr() ? o["plan_id"].get_str() : "";
        std::lock_guard<std::mutex> lock(g_n02_mu);
        auto it = g_imports.find(plan_id);
        if (it == g_imports.end() || !it->second) {
            err = "unknown plan_id";
            err_code = "INVALID_PARAMETER";
            return false;
        }
        if (method == "cancelmodelimport") {
            result = it->second->StatusJson();
            result.pushKV("cancelled", true);
            g_imports.erase(it);
            result.pushKV("automatic_spend_atoms", 0);
            return true;
        }
        if (method == "resumemodelimport") {
            if (!it->second->PrepareStaging(err)) {
                err_code = "INVALID_PARAMETER";
                return false;
            }
        }
        result = it->second->StatusJson();
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("publish_ready", it->second->Phase() == ImportPhase::PUBLISH_READY);
        result.pushKV("live_http", false);
        return true;
    }
    if (method == "createbtxpackage" || method == "exportbtxbundle") {
        return PackageFromObject(o, result, err_code, err);
    }
    if (method == "inspectbtxpackage" || method == "verifybtxpackage" || method == "importbtxpackage") {
        if (!InspectPackage(o, result, err_code, err)) return false;
        if (method == "verifybtxpackage") {
            const std::string st = result.exists("signature_status") && result["signature_status"].isStr() ?
                                        result["signature_status"].get_str() :
                                        "UNSIGNED";
            if (st == "UNSIGNED" || st == "NOT_EVALUATED") {
                err_code = "UNSIGNED_PACKAGE";
                err = "verify requires a cryptographic signature; inspect remains available";
                return false;
            }
            if (result.exists("signature_cryptographic") && result["signature_cryptographic"].isStr() &&
                result["signature_cryptographic"].get_str() == "FAIL") {
                err_code = "SIGNATURE_FAIL";
                err = "cryptographic signature failed";
                return false;
            }
        }
        bool imported = false;
        if (method == "importbtxpackage") {
            const std::string st = result.exists("signature_status") && result["signature_status"].isStr() ?
                                        result["signature_status"].get_str() :
                                        "UNSIGNED";
            const bool sig_pass = result.exists("signature_cryptographic") &&
                                  result["signature_cryptographic"].isStr() &&
                                  result["signature_cryptographic"].get_str() == "PASS";
            UniValue man = result.exists("bundle") ? result["bundle"] : UniValue(UniValue::VOBJ);
            if (man.exists("manifest") && man["manifest"].isObject()) man = man["manifest"];
            if (man.exists("model_id") && man.exists("files") && man["files"].isArray()) {
                if (st == "UNSIGNED" || st == "NOT_EVALUATED" || !sig_pass) {
                    err_code = "UNSIGNED_PACKAGE";
                    err = "import requires a cryptographic signature; inspect remains available";
                    return false;
                }
                if (!cat.InstallFromManifest(man, err, /*complete=*/false)) {
                    err_code = "INVALID_PARAMETER";
                    return false;
                }
                imported = true;
            } else {
                err = "bundle has no VerifiedManifest payload";
                err_code = "INVALID_PARAMETER";
                return false;
            }
        }
        result.pushKV("imported_catalog", imported);
        result.pushKV("note", imported ? "catalog via VerifiedManifest" : "inspect only; catalog mutation uses VerifiedManifest");
        return true;
    }
    if (method == "preparemodelerasure" || method == "executemodelerasure" || method == "getmodelerasurehealth" ||
        method == "repairmodel") {
        if (!ErasureFromObject(o, result, err_code, err)) return false;
        result.pushKV("note", "per-stripe sufficiency; global n is not reconstructability");
        return true;
    }
    if (method == "gettorrentsourcestatus") {
        const std::string locator = o.exists("locator") && o["locator"].isStr() ? o["locator"].get_str() : "";
        const std::string token =
            o.exists("snapshot_token") && o["snapshot_token"].isStr() ? o["snapshot_token"].get_str() : "";
        result.pushKV("infohash", ParseTorrentInfohash(locator, token));
        result.pushKV("provenance_note", TORRENT_PROVENANCE_NOTE);
        result.pushKV("authorship", "not implied by source integrity");
        result.pushKV("live_helper", false);
        result.pushKV("packaged_bridge", true);
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (o.exists("bt_to_btx_bytes") && o["bt_to_btx_bytes"].isNum()) {
            if (!g_torrent_rev) g_torrent_rev = std::make_unique<ReverseTorrentBridge>();
            g_torrent_rev->NoteBtToBtxBytes(o["bt_to_btx_bytes"].getInt<uint64_t>());
        }
        if (o.exists("btx_to_torrent_bytes") && o["btx_to_torrent_bytes"].isNum()) {
            if (!g_torrent_rev) g_torrent_rev = std::make_unique<ReverseTorrentBridge>();
            g_torrent_rev->NoteBtxToTorrentBytes(o["btx_to_torrent_bytes"].getInt<uint64_t>());
        }
        const UniValue st = ReverseTorrentStatusJson(g_torrent_rev.get());
        result.pushKV("torrentd_process", st["torrentd_process"]);
        result.pushKV("reverse_bridge", st["reverse_bridge"]);
        result.pushKV("reverse_bridge_live", st["reverse_bridge_live"]);
        result.pushKV("upload_class", st["upload_class"]);
        result.pushKV("receives_s3_credentials", st["receives_s3_credentials"]);
        if (st.exists("bt_to_btx_bytes")) result.pushKV("bt_to_btx_bytes", st["bt_to_btx_bytes"]);
        return true;
    }
    if (method == "getmodeloriginoffer") {
        OriginBrokerRequest req;
        req.artifact_id = o.exists("artifact_id") && o["artifact_id"].isStr() ? o["artifact_id"].get_str() : "local";
        req.file_index = o.exists("file_index") && o["file_index"].isNum() ? o["file_index"].getInt<int32_t>() : 0;
        req.offset_bytes = o.exists("offset_bytes") && o["offset_bytes"].isNum() ? o["offset_bytes"].getInt<uint64_t>() : 0;
        req.length_bytes = o.exists("length_bytes") && o["length_bytes"].isNum() ? o["length_bytes"].getInt<uint64_t>() : PIECE_SIZE;
        if (o.exists("locator") && o["locator"].isStr()) req.locator = o["locator"].get_str();
        OriginBrokerOffer offer;
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (!g_origin.Issue(req, NowMs(), offer, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result = g_origin.PublicJson(offer);
        result.pushKV("presigned_get_is_meter", PresignedGetIsMeter());
        result.pushKV("follow_redirects", OriginFollowRedirectsAllowed());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodeloriginstatus") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        result = g_origin.StatusJson();
        result.pushKV("drr_slots", g_drr.Slots());
        result.pushKV("presigned_get_is_meter", PresignedGetIsMeter());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "querymodelsummary") {
        QueryRouter router;
        const auto ids = CatalogModelIds(cat);
        const QuerySummary sum = router.SummarizeIds(ids);
        result.pushKV("hit_count", static_cast<int>(sum.hit_count));
        result.pushKV("truncated", static_cast<int>(sum.truncated));
        UniValue sample(UniValue::VARR);
        for (const auto& id : sum.sample_ids) sample.push_back(id);
        result.pushKV("sample_ids", sample);
        result.pushKV("complete", false);
        result.pushKV("throughput_is_ranking", ProviderThroughputIsRankingAuthority());
        result.pushKV("sample_cap", static_cast<int>(QUERY_SAMPLE_MAX));
        return true;
    }
    if (method == "reconcilemodelindex") {
        std::vector<std::string> remote;
        if (o.exists("remote_ids") && o["remote_ids"].isArray()) {
            for (const auto& id : o["remote_ids"].getValues()) {
                if (id.isStr()) remote.push_back(id.get_str());
            }
        }
        IndexReconciler rec;
        const auto local = CatalogModelIds(cat);
        const ReconcileResult cmp = rec.CompareSets(local, remote);
        result.pushKV("status", ReconcileStatusName(cmp.status));
        UniValue want(UniValue::VARR);
        for (const auto& id : cmp.want_ids) want.push_back(id);
        result.pushKV("want_ids", want);
        result.pushKV("want_truncated", cmp.want_truncated);
        result.pushKV("digest_authorizes_insert", ReconcileDigestAuthorizesInsert());
        result.pushKV("want_cap", static_cast<int>(RECONCILE_WANT_MAX));
        return true;
    }
    if (method == "getmodelobjectlayout") {
        uint64_t size = OBJECT_LAYOUT_EXAMPLE_BYTES;
        if (o.exists("file_size_bytes")) {
            if (o["file_size_bytes"].isNum()) size = o["file_size_bytes"].getInt<uint64_t>();
            else if (o["file_size_bytes"].isStr()) {
                size = std::strtoull(o["file_size_bytes"].get_str().c_str(), nullptr, 10);
            }
        }
        PhysicalObjectLayout requested = PhysicalObjectLayout::AUTO;
        if (o.exists("layout") && o["layout"].isStr()) {
            PhysicalObjectLayoutFromName(o["layout"].get_str(), requested);
        }
        result = ObjectLayoutPlanJson(PlanObjectLayout(size, requested));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "validatesubpiece") {
        SubpieceRequest req;
        if (!ParseSubpieceRequest(o, req, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        uint64_t file_size = PIECE_SIZE;
        if (o.exists("file_size_bytes")) {
            if (o["file_size_bytes"].isNum()) file_size = o["file_size_bytes"].getInt<uint64_t>();
            else if (o["file_size_bytes"].isStr()) {
                file_size = std::strtoull(o["file_size_bytes"].get_str().c_str(), nullptr, 10);
            }
        }
        if (!ValidateSubpieceRequest(req, file_size, err)) {
            err_code = "INVALID_PARAMETER";
            return false;
        }
        result = SubpieceRequestJson(req);
        result.pushKV("ok", true);
        result.pushKV("advertise_full_piece_only", AdvertiseFullPieceOnly());
        return true;
    }
    if (method == "getmodelbulkstatus") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (o.exists("rtt_ms") && o["rtt_ms"].isNum()) g_bulk.ObserveRtt(o["rtt_ms"].get_real());
        if (o.exists("backpressure") && o["backpressure"].isBool()) {
            g_bulk.ObserveBackpressure(o["backpressure"].get_bool());
        }
        result = g_bulk.StatusJson();
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelioexecutor") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        result = g_io.StatusJson();
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "setbootstrapdistributor" || method == "getbootstrapstatus") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        uint64_t size = OBJECT_LAYOUT_EXAMPLE_BYTES;
        if (o.exists("file_size_bytes")) {
            if (o["file_size_bytes"].isNum()) size = o["file_size_bytes"].getInt<uint64_t>();
            else if (o["file_size_bytes"].isStr()) {
                size = std::strtoull(o["file_size_bytes"].get_str().c_str(), nullptr, 10);
            }
        }
        if (!g_bootstrap || method == "setbootstrapdistributor") {
            g_bootstrap = std::make_unique<BootstrapDistributor>(size, LARGE_EXTENT_BYTES);
        }
        result.pushKV("file_size_bytes", std::to_string(size));
        result.pushKV("lease_count", static_cast<int>(g_bootstrap->LeaseCount()));
        result.pushKV("false_missing_advertised", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "setmodeluploadpolicy" || method == "getmodeluploadinfo") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (method == "setmodeluploadpolicy") {
            if (o.exists("slots") && o["slots"].isNum()) g_upload_adm.slots = o["slots"].getInt<int>();
            if (o.exists("max_slots") && o["max_slots"].isNum()) g_upload_adm.max_slots = o["max_slots"].getInt<int>();
            if (g_upload_adm.slots < 1) g_upload_adm.slots = 1;
            if (g_upload_adm.slots > g_upload_adm.max_slots) g_upload_adm.slots = g_upload_adm.max_slots;
            DrrConfig dcfg = g_drr.Config();
            dcfg.admission = g_upload_adm;
            g_drr = UploadSchedulerDrr(dcfg);
        }
        result.pushKV("slots", g_upload_adm.slots);
        result.pushKV("max_slots", g_upload_adm.max_slots);
        result.pushKV("per_identity", g_upload_adm.per_identity);
        result.pushKV("per_netgroup", g_upload_adm.per_netgroup);
        result.pushKV("active", g_drr.Active());
        result.pushKV("scheduler", "UploadSchedulerDrr");
        result.pushKV("connection_count_is_capacity", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "planmodelstoragemigration" || method == "executemodelstoragemigration") {
        uint64_t size = OBJECT_LAYOUT_EXAMPLE_BYTES;
        if (o.exists("file_size_bytes")) {
            if (o["file_size_bytes"].isNum()) size = o["file_size_bytes"].getInt<uint64_t>();
            else if (o["file_size_bytes"].isStr()) {
                size = std::strtoull(o["file_size_bytes"].get_str().c_str(), nullptr, 10);
            }
        }
        PhysicalObjectLayout requested = PhysicalObjectLayout::AUTO;
        if (o.exists("layout") && o["layout"].isStr()) {
            PhysicalObjectLayoutFromName(o["layout"].get_str(), requested);
        }
        std::lock_guard<std::mutex> lock(g_n02_mu);
        g_migrate.plan = PlanObjectLayout(size, requested);
        g_migrate.planned = true;
        if (method == "executemodelstoragemigration") g_migrate.executed = true;
        result = ObjectLayoutPlanJson(g_migrate.plan);
        result.pushKV("planned", g_migrate.planned);
        result.pushKV("executed", method == "executemodelstoragemigration" && g_migrate.executed);
        result.pushKV("bulk_io", false);
        result.pushKV("replaces_source_files", false);
        result.pushKV("journal", "layout");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "local residency/layout journal; no second 400 GiB copy");
        return true;
    }
    if (method == "setmodelswarmhealer") {
        uint32_t piece_count = o.exists("piece_count") && o["piece_count"].isNum() ?
            o["piece_count"].getInt<uint32_t>() : 0;
        uint32_t file_index = o.exists("file_index") && o["file_index"].isNum() ?
            o["file_index"].getInt<uint32_t>() : 0;
        std::vector<SourceAvailability> sources;
        Digest48 artifact{};
        if (o.exists("artifact_id") && o["artifact_id"].isStr()) {
            std::string perr;
            (void)Digest48::FromHex(o["artifact_id"].get_str(), artifact, perr);
        }
        if (o.exists("availability")) {
            PeerId pid;
            pid.endpoint = o.exists("endpoint") && o["endpoint"].isStr() ? o["endpoint"].get_str() : "local";
            std::string perr;
            (void)ParseAvailabilitySources(o["availability"], pid.endpoint, pid, artifact, sources, perr, NowMs());
        }
        std::vector<uint32_t> have;
        PickConfig pcfg;
        pcfg.now_ms = NowMs();
        pcfg.preserve_rare = true;
        const auto endangered = EndangeredPieces(file_index, piece_count, have, sources, {}, pcfg);
        UniValue endj(UniValue::VARR);
        for (uint32_t p : endangered) endj.push_back(static_cast<int>(p));
        result.pushKV("healer", true);
        result.pushKV("endangered", endj);
        result.pushKV("whole_model", false);
        result.pushKV("global_n_is_sufficiency", false);
        result.pushKV("automatic_spend_atoms", 0);
        if (o.exists("shards") && o["shards"].isArray()) {
            if (!ErasureFromObject(o, result, err_code, err)) return false;
        } else {
            result.pushKV("repair_executed", false);
        }
        return true;
    }
    if (method == "settorrentsourcepolicy") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (!g_torrent_rev) g_torrent_rev = std::make_unique<ReverseTorrentBridge>();
        if (o.exists("bt_to_btx_bytes") && o["bt_to_btx_bytes"].isNum()) {
            g_torrent_rev->NoteBtToBtxBytes(o["bt_to_btx_bytes"].getInt<uint64_t>());
        }
        const UniValue st = ReverseTorrentStatusJson(g_torrent_rev.get());
        result.pushKV("torrentd_process", false);
        result.pushKV("reverse_bridge_live", st["reverse_bridge_live"]);
        result.pushKV("receives_s3_credentials", TorrentWorkerReceivesS3Credentials());
        result.pushKV("follow_redirects", SourceFollowsRedirects());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelroutingstatus") {
        QueryRouter router;
        result.pushKV("sample_cap", static_cast<int>(QUERY_SAMPLE_MAX));
        result.pushKV("probe_max", QUERY_PROBE_MAX);
        result.pushKV("throughput_is_ranking", ProviderThroughputIsRankingAuthority());
        result.pushKV("delegated_routing_is_consensus", DelegatedRoutingMutatesConsensus());
        result.pushKV("lan_requires_public_address", LanDiscoveryRequiresPublicAddress());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "setmodeldiscoverypolicy") {
        result.pushKV("query_summary", true);
        result.pushKV("throughput_is_ranking", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelresidency") {
        result.pushKV("ABSENT", NetworkResidencyName(NetworkResidency::ABSENT));
        result.pushKV("STAGING", NetworkResidencyName(NetworkResidency::STAGING));
        result.pushKV("VERIFIED_LOCAL", NetworkResidencyName(NetworkResidency::VERIFIED_LOCAL));
        result.pushKV("VERIFIED_REMOTE", NetworkResidencyName(NetworkResidency::VERIFIED_REMOTE));
        result.pushKV("VERIFIED_BOTH", NetworkResidencyName(NetworkResidency::VERIFIED_BOTH));
        result.pushKV("REPAIRABLE", NetworkResidencyName(NetworkResidency::REPAIRABLE));
        result.pushKV("UNAVAILABLE", NetworkResidencyName(NetworkResidency::UNAVAILABLE));
        result.pushKV("remote_existence_implies_verified_remote", RemoteExistenceImpliesVerifiedRemote());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodeldedupinfo") {
        result.pushKV("content_defined_dedup", ContentDefinedDedupShipped());
        result.pushKV("cross_tenant", CrossTenantDedupAllowed());
        result.pushKV("physical_key", "BTX/PhysicalByte/v1");
        result.pushKV("piece_key_unchanged", true);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodellandiscovery") {
        std::string ep = o.exists("endpoint") && o["endpoint"].isStr() ? o["endpoint"].get_str() : "";
        result.pushKV("lan", EndpointLooksLan(ep));
        result.pushKV("delegated_routing_is_consensus", DelegatedRoutingMutatesConsensus());
        result.pushKV("requires_public_address", LanDiscoveryRequiresPublicAddress());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelfileselection") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (o.exists("file_count") && o["file_count"].isNum()) {
            g_selective.SetFileCount(o["file_count"].getInt<uint32_t>());
        }
        if (o.exists("files") && o["files"].isArray()) {
            std::vector<uint32_t> files;
            for (const auto& v : o["files"].getValues()) {
                if (v.isNum()) files.push_back(v.getInt<uint32_t>());
            }
            g_selective.SelectOnly(files);
        }
        if (o.exists("upgrade") && o["upgrade"].isArray()) {
            std::vector<uint32_t> more;
            for (const auto& v : o["upgrade"].getValues()) {
                if (v.isNum()) more.push_back(v.getInt<uint32_t>());
            }
            g_selective.UpgradeSelection(more);
        }
        result.pushKV("all_files", g_selective.AllFiles());
        result.pushKV("advertise_complete", g_selective.AdvertiseComplete());
        result.pushKV("advertise_unselected", false);
        result.pushKV("selected_0", g_selective.Selected(0));
        result.pushKV("advertise_have_0", g_selective.AdvertiseHave(0));
        result.pushKV("reused", static_cast<int>(g_selective.ReusedFiles().size()));
        result.pushKV("newly_requested", static_cast<int>(g_selective.NewlyRequested().size()));
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmultipartjournal") {
        std::lock_guard<std::mutex> lock(g_n02_mu);
        if (o.exists("initiate") && o["initiate"].isTrue()) {
            std::string merr;
            (void)g_mpu.Initiate(o.exists("object_key") && o["object_key"].isStr() ? o["object_key"].get_str() : "obj",
                                 o.exists("upload_id") && o["upload_id"].isStr() ? o["upload_id"].get_str() : "up",
                                 o.exists("source_snapshot") && o["source_snapshot"].isStr() ? o["source_snapshot"].get_str() : "snap",
                                 o.exists("planned_parts") && o["planned_parts"].isNum() ? o["planned_parts"].getInt<uint64_t>() : 1,
                                 merr);
        }
        result = g_mpu.Json();
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getsourcepolicy") {
        result.pushKV("torrent_worker_s3_credentials", TorrentWorkerReceivesS3Credentials());
        result.pushKV("follow_redirects", SourceFollowsRedirects());
        result.pushKV("huggingface_provenance", HUGGINGFACE_PROVENANCE_NOTE);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getbtxpackagecapabilities") {
        result.pushKV("capabilities", HelloCapabilityArray());
        result.pushKV("BTXPKG_CORE_V2", true);
        result.pushKV("AGENT_HANDOFF_V1", true);
        result.pushKV("BTXPKG_CORE_V3", true);
        result.pushKV("CAPABILITY_HANDOFF_V1", true);
        result.pushKV("default_package_core_version", 3);
        result.pushKV("PACKAGE_V1", true);
        result.pushKV("gui", "DEFERRED_WITH_EVIDENCE");
        result.pushKV("wallet_sign", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("remote_inference", false);
        result.pushKV("writes_project_agents_md", false);
        return true;
    }

    auto LoadCore = [&](DecodedBtxPackage& pkg) -> bool {
        std::vector<unsigned char> bytes;
        if (!LoadPackageBytes(o, bytes, err_code, err)) return false;
        if (!DecodeBtxPackage(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, err)) {
            err_code = pkg.err_code.empty() ? "INVALID_PARAMETER" : pkg.err_code;
            return false;
        }
        return true;
    };

    if (method == "getbtxpackagedocument") {
        DecodedBtxPackage pkg;
        if (!LoadCore(pkg)) return false;
        const std::string path = o.exists("document") && o["document"].isStr() ? o["document"].get_str() :
                                   (o.exists("document_path") && o["document_path"].isStr() ? o["document_path"].get_str() :
                                    "AGENTS.md");
        PackageDocument doc;
        if (!GetPackageDocument(pkg.core, path, doc, err)) {
            err_code = "DOCUMENT_NOT_FOUND";
            return false;
        }
        result.pushKV("path", doc.path);
        result.pushKV("sha384", doc.sha384_hex);
        result.pushKV("size_bytes", std::to_string(doc.size_bytes));
        result.pushKV("text", EscapeForTerminal(doc.text));
        result.pushKV("untrusted_scoped_data", true);
        result.pushKV("workspace_written", false);
        result.pushKV("project_agents_md", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "planbtxacquisition") {
        DecodedBtxPackage pkg;
        if (!LoadCore(pkg)) return false;
        UniValue policy = o.exists("local_policy") && o["local_policy"].isObject() ? o["local_policy"] : UniValue(UniValue::VOBJ);
        if (!policy.exists("destination") || !policy["destination"].isStr() || policy["destination"].get_str().empty()) {
            policy.pushKV("destination", fs::PathToString(HelperRoot(cat) / fs::PathFromString("leases") /
                                                            fs::PathFromString("default")));
        }
        AcquisitionPlan plan;
        if (!PlanBtxAcquisition(pkg.core, policy, plan, err_code, err)) return false;
        result = plan.json;
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("live_http", false);
        std::lock_guard<std::mutex> lock(g_n02_mu);
        g_acq[plan.plan_id_hex].plan = plan;
        g_acq[plan.plan_id_hex].state = "PLANNED";
        return true;
    }
    if (method == "executebtxacquisition") {
        return WithExecuteAcquisitionIdempotency(o, result, err_code, err, [&]() -> bool {
        const std::string plan_id = o.exists("plan_id") && o["plan_id"].isStr() ? o["plan_id"].get_str() : "";
        ExecuteAcquisitionRequest ex_req;
        bool have_files = false;
        {
            std::lock_guard<std::mutex> lock(g_n02_mu);
            auto it = g_acq.find(plan_id);
            if (it == g_acq.end()) {
                err = "unknown plan_id";
                err_code = "INVALID_PARAMETER";
                return false;
            }
            if (it->second.plan.retrieval_mode != "FREE_ONLY") {
                err_code = "PAID_PATH_FORBIDDEN";
                err = "FREE_ONLY";
                return false;
            }
            if (it->second.state == "MODEL_READY" && it->second.receipt.isObject()) {
                const std::string fp = ExecuteAcqPlanFingerprint(o);
                if (!it->second.exec_fp.empty() && it->second.exec_fp != fp) {
                    Network02IdemFail(result, err_code, err, "IDEMPOTENCY_CONFLICT",
                                      "executebtxacquisition payload conflict");
                    return false;
                }
                result = it->second.receipt;
                result.pushKV("job_id", plan_id);
                result.pushKV("automatic_spend_atoms", 0);
                return true;
            }
            if (it->second.state == "CANCELLED") {
                err_code = "INVALID_PARAMETER";
                err = "cancelled";
                return false;
            }
            ex_req.plan = it->second.plan;
        }
        if (o.exists("verified_local_files") && o["verified_local_files"].isArray()) {
            have_files = true;
            for (const auto& f : o["verified_local_files"].getValues()) {
                if (!f.isObject() || !f.exists("path") || !f["path"].isStr() || !f.exists("sha384") ||
                    !f["sha384"].isStr()) {
                    err_code = "INVALID_PARAMETER";
                    err = "verified_local_files";
                    return false;
                }
                VerifiedLocalFile vf;
                vf.relative_path = f["path"].get_str();
                vf.sha384_hex = f["sha384"].get_str();
                if (f.exists("source_path") && f["source_path"].isStr()) vf.source_path = f["source_path"].get_str();
                ex_req.files.push_back(std::move(vf));
            }
        }
        if (have_files) {
            ex_req.credit = &GlobalAcquisitionCredits();
            if (o.exists("reserve_bytes") && o["reserve_bytes"].isStr()) {
                uint64_t rb = 0;
                if (ParseUInt64(o["reserve_bytes"].get_str(), &rb)) ex_req.reserve_bytes = rb;
            }
            AcquisitionReceipt rec;
            uint64_t reserved = 0;
            if (!ExecuteBtxAcquisition(ex_req, rec, reserved, err_code, err)) {
                if (err_code == "MODEL_BYTES_UNVERIFIED" || err_code == "SYMLINK_REFUSED" ||
                    err_code == "DOCUMENT_PATH_REJECTED" || err_code == "OVERWRITE_REFUSED") {
                    std::lock_guard<std::mutex> lock(g_n02_mu);
                    auto it = g_acq.find(plan_id);
                    if (it != g_acq.end()) {
                        it->second.state = "SELECTION_READY";
                        UniValue fail(UniValue::VOBJ);
                        fail.pushKV("schema_version", 1);
                        fail.pushKV("receipt_id", plan_id);
                        fail.pushKV("package_core_id", it->second.plan.package_core_id.Hex());
                        fail.pushKV("plan_id", plan_id);
                        fail.pushKV("state", "SELECTION_READY");
                        fail.pushKV("manifest_verified", false);
                        fail.pushKV("file_bytes_verified", false);
                        fail.pushKV("runtime_executed", false);
                        fail.pushKV("error_code", err_code);
                        fail.pushKV("automatic_spend_atoms", 0);
                        it->second.receipt = fail;
                        result = fail;
                        result.pushKV("job_id", plan_id);
                    }
                    return true;
                }
                if (err_code == "BUDGET_EXCEEDED") return false;
                return false;
            }
            std::lock_guard<std::mutex> lock(g_n02_mu);
            auto it = g_acq.find(plan_id);
            if (it == g_acq.end()) {
                GlobalAcquisitionCredits().Release(reserved);
                err_code = "INVALID_PARAMETER";
                err = "plan disappeared";
                return false;
            }
            it->second.reserved_bytes += reserved;
            it->second.state = "MODEL_READY";
            it->second.exec_fp = ExecuteAcqPlanFingerprint(o);
            it->second.receipt = rec.json;
            result = rec.json;
            result.pushKV("job_id", plan_id);
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("live_http", false);
            return true;
        }
        std::lock_guard<std::mutex> lock(g_n02_mu);
        auto it = g_acq.find(plan_id);
        if (it == g_acq.end()) {
            err = "unknown plan_id";
            err_code = "INVALID_PARAMETER";
            return false;
        }
        it->second.state = "SELECTION_READY";
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("schema_version", 1);
        rec.pushKV("receipt_id", it->second.plan.plan_id_hex);
        rec.pushKV("package_core_id", it->second.plan.package_core_id.Hex());
        rec.pushKV("plan_id", plan_id);
        UniValue rids(UniValue::VARR);
        for (const auto& id : it->second.plan.resource_ids) rids.push_back(id);
        rec.pushKV("resource_ids", rids);
        rec.pushKV("state", "SELECTION_READY");
        UniValue paths(UniValue::VARR);
        paths.push_back(it->second.plan.destination);
        rec.pushKV("local_paths", paths);
        rec.pushKV("manifest_verified", false);
        rec.pushKV("file_bytes_verified", false);
        rec.pushKV("error_code", "MODEL_BYTES_UNVERIFIED");
        UniValue src(UniValue::VARR);
        src.push_back("BTX_NATIVE");
        rec.pushKV("source_classes_used", src);
        rec.pushKV("lease_id", plan_id.substr(0, 32));
        rec.pushKV("runtime_executed", false);
        rec.pushKV("created_at_ms", it->second.plan.expires_at_ms);
        rec.pushKV("automatic_spend_atoms", 0);
        rec.pushKV("note", "isolated native plan; file bytes not claimed without local verified materialization");
        it->second.receipt = rec;
        result = rec;
        result.pushKV("job_id", plan_id);
        return true;
        });
    }
    if (method == "getbtxacquisition" || method == "cancelbtxacquisition") {
        const std::string plan_id = o.exists("plan_id") && o["plan_id"].isStr() ? o["plan_id"].get_str() : "";
        std::lock_guard<std::mutex> lock(g_n02_mu);
        auto it = g_acq.find(plan_id);
        if (it == g_acq.end()) {
            err = "unknown plan_id";
            err_code = "INVALID_PARAMETER";
            return false;
        }
        if (method == "cancelbtxacquisition") {
            if (it->second.reserved_bytes) {
                GlobalAcquisitionCredits().Release(it->second.reserved_bytes);
                it->second.reserved_bytes = 0;
            }
            it->second.state = "CANCELLED";
            result.pushKV("cancelled", true);
            result.pushKV("state", "CANCELLED");
            result.pushKV("automatic_spend_atoms", 0);
            return true;
        }
        result = it->second.receipt.isObject() ? it->second.receipt : it->second.plan.json;
        result.pushKV("state", it->second.state);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "planbtxclientinstall") {
        DecodedBtxPackage pkg;
        if (!LoadCore(pkg)) return false;
        UniValue catlg = o.exists("trusted_catalogue") && o["trusted_catalogue"].isObject() ? o["trusted_catalogue"] :
                                                                                               UniValue(UniValue::VOBJ);
        UniValue policy = o.exists("user_policy") && o["user_policy"].isObject() ? o["user_policy"] : UniValue(UniValue::VOBJ);
        InstallPlan plan;
        if (!PlanBtxClientInstall(pkg.core, catlg, policy, plan, err_code, err)) {
            result.pushKV("trust_required", true);
            result.pushKV("installs", false);
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("error_code", err_code);
            result.pushKV("error", err);
            return true;
        }
        result = plan.json;
        result.pushKV("trust_required", plan.trust_required);
        result.pushKV("installs", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "planbtxruntime") {
        DecodedBtxPackage pkg;
        if (!LoadCore(pkg)) return false;
        UniValue receipt = o.exists("receipt") && o["receipt"].isObject() ? o["receipt"] : UniValue(UniValue::VOBJ);
        UniValue adapter = o.exists("trusted_adapter") && o["trusted_adapter"].isObject() ? o["trusted_adapter"] :
                                                                                            UniValue(UniValue::VOBJ);
        RuntimePlan plan;
        if (!PlanBtxRuntime(pkg.core, receipt, adapter, plan, err_code, err)) {
            result.pushKV("executes", false);
            result.pushKV("automatic_spend_atoms", 0);
            result.pushKV("error_code", err_code);
            result.pushKV("error", err);
            if (err_code == "MODEL_BYTES_UNVERIFIED" || err_code == "EXECUTION_APPROVAL_REQUIRED" ||
                err_code == "RUNTIME_ADAPTER_UNSUPPORTED") {
                return true;
            }
            return false;
        }
        result = plan.json;
        result.pushKV("executes", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "setcloudstorage") {
        result.pushKV("applied", false);
        result.pushKV("bulk_io", false);
        result.pushKV("live_r2_wan", "NOT_RUN");
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "local credential handle only; live HTTPS R2 remains NOT_RUN");
        return true;
    }
    if (method == "setmodelstoragepolicy") {
        result.pushKV("policy_applied", false);
        result.pushKV("bulk_io", false);
        result.pushKV("silent_migrate", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "future layout/cache policy only; existing objects do not migrate");
        return true;
    }
    if (method == "setmodelmirror") {
        result.pushKV("role", "node");
        result.pushKV("mirror_privilege", false);
        result.pushKV("consensus", false);
        result.pushKV("search_authority", false);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("note", "local keep/follow policy, not a monetary or consensus privilege");
        return true;
    }
    err_code = "METHOD_NOT_FOUND";
    err = method;
    return false;
}

bool WithNetwork02Idempotency(const std::string& method, const UniValue& params, UniValue& result,
                              std::string& err_code, std::string& err, const std::function<bool()>& once)
{
    const std::string write_method = CanonicalNetwork02WriteMethod(method);
    if (!IsNetwork02CostlyWrite(write_method)) return once();
    const UniValue o = ObjectArg(params);
    const std::string key = Network02IdempotencyKey(o);
    if (key.empty()) {
        Network02IdemFail(result, err_code, err, "INVALID_PARAMETER", "idempotency_key required");
        return false;
    }
    const std::string scope = Network02IdemScope(Network02IdemCaller(o), write_method, key);
    const std::string fp = Network02BodyFingerprint(o);
    {
        std::lock_guard<std::mutex> lock(g_n02_idem_mu);
        auto it = g_n02_idem.find(scope);
        if (it != g_n02_idem.end()) {
            if (it->second.body_fp != fp) {
                Network02IdemFail(result, err_code, err, "IDEMPOTENCY_CONFLICT", "idempotency conflict");
                return false;
            }
            result = it->second.result;
            err_code = it->second.err_code;
            err = it->second.err;
            return it->second.ok;
        }
    }
    const bool ok = once();
    std::lock_guard<std::mutex> lock(g_n02_idem_mu);
    auto it = g_n02_idem.find(scope);
    if (it != g_n02_idem.end()) {
        if (it->second.body_fp != fp) {
            Network02IdemFail(result, err_code, err, "IDEMPOTENCY_CONFLICT", "idempotency conflict");
            return false;
        }
        result = it->second.result;
        err_code = it->second.err_code;
        err = it->second.err;
        return it->second.ok;
    }
    Network02IdemEntry entry;
    entry.body_fp = fp;
    entry.result = result;
    entry.err_code = err_code;
    entry.err = err;
    entry.ok = ok;
    g_n02_idem.emplace(scope, std::move(entry));
    return ok;
}

bool DispatchNetwork02Rpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                           std::string& err_code, std::string& err)
{
    const std::string write_method = CanonicalNetwork02WriteMethod(method);
    return WithNetwork02Idempotency(method, params, result, err_code, err, [&] {
        return DispatchNetwork02RpcOnce(cat, write_method, params, result, err_code, err);
    });
}

bool TryAdmitModelUpload(const std::string& identity, const std::string& netgroup, uint64_t bytes,
                         uint64_t& request_id, std::string& err)
{
    request_id = 0;
    DrrUploadRequest req;
    req.identity = identity;
    req.netgroup = netgroup;
    req.schedule = UploadClass::NORMAL;
    req.accounting = HostAccountingClass::NATIVE_P2P;
    req.bytes = bytes ? bytes : PIECE_SIZE;
    std::lock_guard<std::mutex> lock(g_n02_mu);
    if (!g_drr.Enqueue(req, request_id, err)) return false;
    g_drr.RunEpoch();
    DrrSelection sel;
    if (!g_drr.Select(sel) || sel.request_id != request_id) {
        g_drr.Release(request_id);
        request_id = 0;
        err = sel.reason.empty() ? "upload slots full" : sel.reason;
        return false;
    }
    std::string werr;
    (void)g_drr.NoteAcceptedWork(request_id, req.bytes, werr);
    return true;
}

void ReleaseModelUpload(uint64_t request_id)
{
    if (request_id == 0) return;
    std::lock_guard<std::mutex> lock(g_n02_mu);
    g_drr.Release(request_id);
}

} // namespace modelnet
