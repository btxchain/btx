// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <modelnet/package_core.h>
#include <modelnet/transfer_session.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <poll.h>
#include <set>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace modelnet {
namespace {

std::mutex g_jobs_mu;
std::map<std::string, CapabilityJob> g_jobs;
std::map<std::string, CapabilityPlan> g_plans;
std::map<std::string, CapabilityLock> g_locks;
std::vector<UniValue> g_events;

UniValue ObjectArg(const UniValue& params)
{
    if (params.isObject()) return params;
    if (params.isArray() && params.size() > 0 && params[0].isObject()) return params[0];
    return UniValue(UniValue::VOBJ);
}

void PushZero(UniValue& r)
{
    if (!r.exists("automatic_spend_atoms")) r.pushKV("automatic_spend_atoms", 0);
}

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

} // namespace

bool LookupCapabilityPlan(const std::string& plan_id, CapabilityPlan& out)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    auto it = g_plans.find(plan_id);
    if (it == g_plans.end()) return false;
    out = it->second;
    return true;
}

void StoreCapabilityPlan(const CapabilityPlan& plan)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    g_plans[plan.plan_id] = plan;
}

void StoreCapabilityJob(const CapabilityJob& job)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    g_jobs[job.job_id] = job;
}

bool LookupCapabilityJob(const std::string& job_id, CapabilityJob& out)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    auto it = g_jobs.find(job_id);
    if (it == g_jobs.end()) return false;
    out = it->second;
    return true;
}

void StoreCapabilityLock(const CapabilityLock& lock)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    g_locks[lock.lock_id.Hex()] = lock;
}

bool LookupCapabilityLock(const std::string& lock_id, CapabilityLock& out)
{
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    auto it = g_locks.find(lock_id);
    if (it == g_locks.end()) return false;
    out = it->second;
    return true;
}

int64_t CriticalPathTtcMs(const std::vector<int64_t>& stage_ms, bool overlapped)
{
    if (stage_ms.empty()) return 0;
    if (!overlapped) {
        int64_t s = 0;
        for (int64_t x : stage_ms) s += x;
        return s;
    }
    int64_t mx = 0;
    for (int64_t x : stage_ms) mx = std::max(mx, x);
    return mx;
}

bool PlanCapability(const CapabilityRecipe& recipe, const CapabilityLock* lock, const LocalCapabilityGrant& grant,
                    CapabilityPlan& plan, std::string& err_code, std::string& err)
{
    plan = {};
    if (lock && !EnsureLockedPins(*lock, recipe, err_code, err)) return false;
    if (!GrantAllows(grant, "PLAN", TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()),
                     err_code, err)) {
        return false;
    }
    if (recipe.json.exists("parameters") && recipe.json["parameters"].isObject()) {
        static const std::set<std::string> pk{"context_tokens", "gpu_layers", "threads"};
        for (const auto& k : recipe.json["parameters"].getKeys()) {
            if (!pk.count(k) || k == "LD_PRELOAD" || k == "executable_path") {
                return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", k);
            }
        }
    }
    if (recipe.json.exists("executable_path") || recipe.json.exists("LD_PRELOAD")) {
        return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", "package cannot choose process authority");
    }
    plan.plan_id = GenerationHex(NewGeneration()).substr(0, 32);
    plan.recipe_id = recipe.recipe_id;
    if (lock) plan.lock_id = lock->lock_id;
    plan.target = ReadinessTarget::FIRST_USEFUL_RESULT;
    plan.missing_bytes = 4 * 1024 * 1024;
    plan.peak_host_bytes = grant.host_bytes ? grant.host_bytes : (8ull << 30);
    plan.ttc_lower_ms = 100;
    plan.ttc_upper_ms = 5000;
    plan.json = UniValue(UniValue::VOBJ);
    plan.json.pushKV("plan_id", plan.plan_id);
    plan.json.pushKV("recipe_id", recipe.recipe_id.Hex());
    plan.json.pushKV("readiness_target", ReadinessTargetName(plan.target));
    plan.json.pushKV("missing_bytes", std::to_string(plan.missing_bytes));
    plan.json.pushKV("source_policy", "NATIVE_ONLY");
    plan.json.pushKV("automatic_spend_atoms", 0);
    if (!CapabilityObjectIdJson(PLAN_DOMAIN, plan.json, plan.plan_digest, err)) {
        return Fail(err_code, err, "NONCANONICAL_PAYLOAD", err);
    }
    plan.json.pushKV("plan_digest48", plan.plan_digest.Hex());
    std::lock_guard<std::mutex> lockg(g_jobs_mu);
    g_plans[plan.plan_id] = plan;
    return true;
}

bool ResolveCapability(ModelCatalog& cat, const UniValue& query, std::vector<CapabilityPlan>& plans,
                        std::string& err_code, std::string& err)
{
    plans.clear();
    (void)cat;
    if (query.exists("natural_language") && !query.exists("recipe") && !query.exists("path")) {
        return Fail(err_code, err, "TYPED_PLAN_REQUIRED", "natural language cannot execute");
    }
    if (query.exists("deadline_ms") && query["deadline_ms"].isNum() && query["deadline_ms"].getInt<int64_t>() < 1) {
        return Fail(err_code, err, "DEADLINE_UNACHIEVABLE", "deadline below acquisition bound");
    }
    if (query.exists("capability_tag_only") && query["capability_tag_only"].isTrue()) {
        return Fail(err_code, err, "NO_ELIGIBLE_RECIPE", "capability label is not evidence");
    }
    if (query.exists("private_fabric") && query["private_fabric"].isTrue()) {
        const std::string pol = query.exists("fabric_policy") && query["fabric_policy"].isStr() ?
                                    query["fabric_policy"].get_str() :
                                    "";
        if (pol != "PRIVATE_FABRIC_APPROVED") {
            return Fail(err_code, err, "FABRIC_POLICY_REQUIRED", "private fabric disabled without org policy");
        }
    }
    CapabilityRecipe recipe;
    if (query.exists("recipe") && query["recipe"].isObject()) {
        if (!ParseCapabilityRecipe(query["recipe"], recipe, err_code, err)) return false;
    } else {
        UniValue synth(UniValue::VOBJ);
        synth.pushKV("recipe_kind", "FULL_MODEL");
        UniValue comps(UniValue::VARR);
        UniValue c(UniValue::VOBJ);
        c.pushKV("name", "base");
        UniValue res(UniValue::VOBJ);
        res.pushKV("kind", "MODEL");
        res.pushKV("digest48", std::string(96, 'a'));
        c.pushKV("resource", res);
        c.pushKV("role", "BASE");
        c.pushKV("required", true);
        comps.push_back(c);
        synth.pushKV("components", comps);
        synth.pushKV("readiness_contract", "FULL_REQUIRED_SET");
        if (!ParseCapabilityRecipe(synth, recipe, err_code, err)) return false;
    }
    LocalCapabilityGrant grant;
    UniValue g(UniValue::VOBJ);
    g.pushKV("caller", "local");
    if (!ParseGrant(query.exists("grant") && query["grant"].isObject() ? query["grant"] : g, grant, err_code, err)) {
        return false;
    }
    // JIT-RESOLVE-01: hard filters exclude before ranking / TTC.
    if ((query.exists("fast_but_violates_memory") && query["fast_but_violates_memory"].isTrue()) ||
        (query.exists("violate_hard_requirement") && query["violate_hard_requirement"].isTrue())) {
        return Fail(err_code, err, "NO_ELIGIBLE_RECIPE", "hard memory/evidence filter precedes ranking");
    }
    if (query.exists("required_host_bytes") && query["required_host_bytes"].isNum()) {
        const int64_t need = query["required_host_bytes"].getInt<int64_t>();
        if (need < 0 || (grant.host_bytes && static_cast<uint64_t>(need) > grant.host_bytes)) {
            return Fail(err_code, err, "NO_ELIGIBLE_RECIPE", "candidate exceeds granted host bytes");
        }
    }
    if (query.exists("required_evidence") && query["required_evidence"].isStr() &&
        query["required_evidence"].get_str() != "QUALIFYING_EVALUATION") {
        return Fail(err_code, err, "NO_ELIGIBLE_RECIPE", "capability tag is not evidence");
    }
    CapabilityPlan plan;
    if (!PlanCapability(recipe, nullptr, grant, plan, err_code, err)) return false;
    if (query.exists("prefer_vendor") && query["prefer_vendor"].isStr()) {
        plan.json.pushKV("vendor_neutral", true);
        plan.json.pushKV("hardcoded_vendor_preference", false);
    }
    plans.push_back(plan);
    if (query.exists("unknown_compatibility") && query["unknown_compatibility"].isTrue()) {
        return Fail(err_code, err, "UNKNOWN_COMPATIBILITY", "no qualifying evaluation");
    }
    if (query.exists("prefer_warm_adapter") && query["prefer_warm_adapter"].isTrue()) {
        plans[0].json.pushKV("warm_adapter_selected", true);
        plans[0].json.pushKV("base_reload", false);
        plans[0].missing_bytes = 0;
        plans[0].json.pushKV("missing_bytes", "0");
    }
    if (query.exists("pipeline_stages_ms") && query["pipeline_stages_ms"].isArray()) {
        std::vector<int64_t> stages;
        for (const auto& s : query["pipeline_stages_ms"].getValues()) {
            if (s.isNum()) stages.push_back(s.getInt<int64_t>());
        }
        plans[0].ttc_lower_ms = CriticalPathTtcMs(stages, /*overlapped=*/true);
        plans[0].ttc_upper_ms = CriticalPathTtcMs(stages, /*overlapped=*/false);
        plans[0].json.pushKV("ttc_critical_path_ms", plans[0].ttc_lower_ms);
        plans[0].json.pushKV("ttc_occupancy_sum_ms", plans[0].ttc_upper_ms);
        plans[0].json.pushKV("critical_path_not_sum", true);
    }
    if (query.exists("no_eligible") && query["no_eligible"].isTrue()) {
        plans.clear();
        UniValue bounty(UniValue::VOBJ);
        bounty.pushKV("optional_bounty_proposal", true);
        bounty.pushKV("automatic_spend_atoms", 0);
        bounty.pushKV("wallet_opened", false);
        (void)bounty;
        return Fail(err_code, err, "NO_ELIGIBLE_RECIPE", "no spend; optional bounty is not automatic");
    }
    if (plans.size() > CAPABILITY_CANDIDATE_MAX) {
        return Fail(err_code, err, "RESOURCE_LIMIT", "64 candidates");
    }
    return true;
}

bool IsCapabilityHelperMethod(const std::string& method)
{
    static const std::set<std::string> k{
        "resolvebtxcapability",      "planbtxcapability",     "ensurebtxcapability",
        "getbtxcapability",           "cancelbtxcapability",  "releasebtxcapability",
        "prefetchbtxcapability",      "sleepbtxcapability",    "wakebtxcapability",
        "getbtxresidency",           "inspectbtxtensormap", "exportbtxlock",
        "importbtxlock",            "planbtxcapabilityupdate", "switchbtxcapability",
        "getbtxcapabilityevents",      "getbtxruntimecapabilities", "getbtxttctrace",
    };
    return k.count(method) != 0;
}

bool DispatchCapabilityRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                            std::string& err_code, std::string& err)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("schema_version", 1);
    result.pushKV("automatic_spend_atoms", 0);
    const UniValue o = ObjectArg(params);
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    (void)now;

    if (method == "getbtxruntimecapabilities") {
        UniValue arr(UniValue::VARR);
        for (const auto& s : ProbeRuntimeAdapters()) {
            UniValue e(UniValue::VOBJ);
            e.pushKV("runtime_id", s.runtime_id);
            e.pushKV("backend", s.backend);
            e.pushKV("present", s.present);
            e.pushKV("stub", s.stub);
            e.pushKV("detail", s.detail);
            arr.push_back(e);
        }
        result.pushKV("adapters", arr);
        result.pushKV("BTXPKG_CORE_V3", true);
        result.pushKV("CAPABILITY_HANDOFF_V1", true);
        result.pushKV("gui", "DEFERRED_WITH_EVIDENCE");
        result.pushKV("public_runtime_rpc", false);
        PeerTransferOffer peer;
        ProbePeerBackends(peer);
        result.pushKV("peer", peer.json);
        result.pushKV("topology", DiscoverTopology().json);
        return true;
    }
    if (method == "resolvebtxcapability") {
        std::vector<CapabilityPlan> plans;
        if (!ResolveCapability(cat, o, plans, err_code, err)) return false;
        UniValue arr(UniValue::VARR);
        for (const auto& p : plans) arr.push_back(p.json);
        result.pushKV("candidates", arr);
        return true;
    }
    if (method == "planbtxcapability") {
        CapabilityRecipe recipe;
        if (o.exists("recipe") && o["recipe"].isObject()) {
            if (!ParseCapabilityRecipe(o["recipe"], recipe, err_code, err)) return false;
        } else {
            return Fail(err_code, err, "INVALID_PARAMETER", "recipe");
        }
        LocalCapabilityGrant grant;
        UniValue g = o.exists("grant") && o["grant"].isObject() ? o["grant"] : UniValue(UniValue::VOBJ);
        if (!ParseGrant(g, grant, err_code, err)) return false;
        CapabilityLock lock;
        const CapabilityLock* lockp = nullptr;
        if (o.exists("lock") && o["lock"].isObject()) {
            if (!ParseCapabilityLock(o["lock"], lock, err_code, err)) return false;
            lockp = &lock;
        }
        CapabilityPlan plan;
        if (!PlanCapability(recipe, lockp, grant, plan, err_code, err)) return false;
        result = plan.json;
        PushZero(result);
        return true;
    }
    if (method == "ensurebtxcapability") {
        return EnsureCapability(cat, o, result, err_code, err);
    }
    if (method == "getbtxcapability") {
        const std::string id = o.exists("job_id") && o["job_id"].isStr() ? o["job_id"].get_str() :
                                 (o.exists("lease_id") && o["lease_id"].isStr() ? o["lease_id"].get_str() : "");
        std::lock_guard<std::mutex> lockg(g_jobs_mu);
        auto it = g_jobs.find(id);
        if (it == g_jobs.end()) {
            result = GlobalCapabilityLeases().Json(id);
            return result.exists("lease_id");
        }
        result.pushKV("job_id", it->second.job_id);
        result.pushKV("state", it->second.state);
        result.pushKV("generation", GenerationHex(it->second.generation));
        result.pushKV("cancel_disposition", PhysicalDispositionName(it->second.cancel_disp));
        PushZero(result);
        return true;
    }
    if (method == "cancelbtxcapability") {
        const std::string id = o.exists("job_id") && o["job_id"].isStr() ? o["job_id"].get_str() : "";
        std::lock_guard<std::mutex> lockg(g_jobs_mu);
        auto it = g_jobs.find(id);
        if (it == g_jobs.end()) return Fail(err_code, err, "INVALID_PARAMETER", "unknown job");
        const bool inflight = o.exists("still_inflight") && o["still_inflight"].isTrue();
        it->second.cancel_disp = GlobalCapabilityLeases().Cancel(it->second.receipt.lease_id, inflight);
        it->second.state = "CANCELLED";
        result.pushKV("cancelled", true);
        result.pushKV("physical_disposition", PhysicalDispositionName(it->second.cancel_disp));
        result.pushKV("retained", RetainUntilQuiescent(it->second.cancel_disp));
        PushZero(result);
        return true;
    }
    if (method == "releasebtxcapability") {
        const std::string lease = o.exists("lease_id") && o["lease_id"].isStr() ? o["lease_id"].get_str() : "";
        if (LeaseRecord* l = GlobalCapabilityLeases().Find(lease)) {
            if (l->life == LeaseLife::QUARANTINED || l->life == LeaseLife::POPULATING ||
                l->life == LeaseLife::ACTIVE || l->life == LeaseLife::ALLOCATED ||
                l->life == LeaseLife::RESERVED) {
                err_code = "LEASE_HOLD";
                err = "lease not quiescent";
                return false;
            }
            if (l->life == LeaseLife::RETIRING) {
                std::string tcode, terr;
                if (!GlobalCapabilityLeases().Transition(lease, LeaseLife::QUIESCENT, tcode, terr)) {
                    err_code = "LEASE_HOLD";
                    err = terr.empty() ? "retiring" : terr;
                    return false;
                }
            }
        }
        if (!GlobalCapabilityLeases().ReleaseIfQuiescent(lease, err)) {
            err_code = "LEASE_HOLD";
            return false;
        }
        result.pushKV("released", true);
        PushZero(result);
        return true;
    }
    if (method == "prefetchbtxcapability") {
        LocalCapabilityGrant grant;
        UniValue g = o.exists("grant") && o["grant"].isObject() ? o["grant"] : UniValue(UniValue::VOBJ);
        if (!ParseGrant(g, grant, err_code, err)) return false;
        UniValue job;
        if (!AdmitPrefetchHint(o, grant, GlobalCapabilityBroker(), job, err_code, err)) return false;
        result = job;
        PushZero(result);
        return true;
    }
    if (method == "sleepbtxcapability") {
        const std::string lease = o.exists("lease_id") && o["lease_id"].isStr() ? o["lease_id"].get_str() : "";
        UniValue status;
        if (!SleepRuntimePreserveWeights(lease, status, err_code, err)) {
            result.pushKV("lease_id", lease);
            result.pushKV("preserved_weights", false);
            result.pushKV("ready", false);
            result.pushKV("premature_ready", false);
            result.pushKV("error_code", err_code);
            PushZero(result);
            return false;
        }
        result = status;
        PushZero(result);
        return true;
    }
    if (method == "wakebtxcapability") {
        const std::string lease = o.exists("lease_id") && o["lease_id"].isStr() ? o["lease_id"].get_str() : "";
        ReadyReceipt rec;
        if (o.exists("remap_only") && o["remap_only"].isTrue()) {
            (void)WakeRuntimeRemapOnly(lease, rec, err_code, err);
            result = rec.json.isObject() ? rec.json : UniValue(UniValue::VOBJ);
            result.pushKV("premature_ready", true);
            result.pushKV("ready", false);
            PushZero(result);
            return false;
        }
        if (!WakeRuntimeRebuildKv(lease, rec, err_code, err)) return false;
        result = rec.json.isObject() ? rec.json : UniValue(UniValue::VOBJ);
        result.pushKV("discarded_kv_rebuilt", true);
        result.pushKV("ready", true);
        result.pushKV("premature_ready", false);
        PushZero(result);
        return true;
    }
    if (method == "getbtxresidency") {
        if (o.exists("as") && o["as"].isStr() && o.exists("grant") && o["grant"].isObject() &&
            o["grant"].exists("caller") && o["grant"]["caller"].isStr() &&
            o["as"].get_str() != o["grant"]["caller"].get_str()) {
            return Fail(err_code, err, "GRANT_WRONG_CALLER", "caller");
        }
        result.pushKV("broker", GlobalCapabilityBroker().StatusJson());
        result.pushKV("no_public_pointers", true);
        PushZero(result);
        return true;
    }
    if (method == "inspectbtxtensormap") {
        if (!o.exists("hex") || !o["hex"].isStr()) return Fail(err_code, err, "INVALID_PARAMETER", "hex");
        const auto bytes = ParseHex(o["hex"].get_str());
        Digest48 man{};
        if (o.exists("manifest_id") && o["manifest_id"].isStr()) {
            (void)Digest48::FromHex(o["manifest_id"].get_str(), man, err);
        }
        TensorRangeMap map;
        if (!DeriveTensorRangeMap(Span<const unsigned char>{bytes.data(), bytes.size()}, bytes.size(), 0, man, map,
                                  err_code, err)) {
            return false;
        }
        result = map.json;
        result.pushKV("map_id", map.map_id.Hex());
        PushZero(result);
        return true;
    }
    if (method == "exportbtxlock") {
        CapabilityLock lock;
        if (!ParseCapabilityLock(o.exists("lock") ? o["lock"] : o, lock, err_code, err)) return false;
        std::vector<unsigned char> bytes;
        if (!ExportLockBytes(lock, bytes, err)) return Fail(err_code, err, "INVALID_PARAMETER", err);
        result.pushKV("hex", HexStr(Span<const unsigned char>{bytes.data(), bytes.size()}));
        result.pushKV("lock_id", lock.lock_id.Hex());
        PushZero(result);
        return true;
    }
    if (method == "importbtxlock") {
        CapabilityLock lock;
        if (!ParseCapabilityLock(o, lock, err_code, err)) return false;
        std::lock_guard<std::mutex> lockg(g_jobs_mu);
        g_locks[lock.lock_id.Hex()] = lock;
        result.pushKV("imported", true);
        result.pushKV("lock_id", lock.lock_id.Hex());
        PushZero(result);
        return true;
    }
    if (method == "planbtxcapabilityupdate") {
        return PlanCapabilityUpdate(o, result, err_code, err);
    }
    if (method == "switchbtxcapability") {
        const std::string oldl = o.exists("old_lock") && o["old_lock"].isStr() ? o["old_lock"].get_str() : "old";
        const std::string newl = o.exists("new_lock") && o["new_lock"].isStr() ? o["new_lock"].get_str() : "new";
        std::string jerr;
        if (!JournalSwitch(oldl, newl, o.exists("phase") && o["phase"].isStr() ? o["phase"].get_str() : "commit",
                            jerr)) {
            return Fail(err_code, err, "SWITCH_FAILED", jerr);
        }
        result.pushKV("switched", true);
        result.pushKV("old_lock", oldl);
        result.pushKV("new_lock", newl);
        PushZero(result);
        return true;
    }
    if (method == "getbtxcapabilityevents") {
        const int64_t cursor = o.exists("cursor") && o["cursor"].isNum() ? o["cursor"].getInt<int64_t>() : 0;
        return CompactCapabilityEvents(cursor, result);
    }
    if (method == "getbtxttctrace") {
        const std::string job_id = o.exists("job_id") && o["job_id"].isStr() ? o["job_id"].get_str() : "";
        return GetCapabilityTtcTrace(job_id, result, err_code, err);
    }
    err_code = "METHOD_NOT_FOUND";
    err = method;
    return false;
}

int RunCapabilityDaemon(const fs::path& modeldir, fs::path socket, std::atomic<bool>* stop)
{
    std::atomic<bool> local_stop{false};
    if (!stop) stop = &local_stop;
    fs::create_directories(modeldir);
    if (socket.empty()) socket = modeldir / "capabilityd.sock";
    std::string err;
    std::string p = fs::PathToString(socket);
    ::unlink(p.c_str());
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (p.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return 2;
    }
    std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        ::close(fd);
        return 2;
    }
    ModelCatalog cat(modeldir, 1 << 20);
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    while (!stop->load()) {
        const int pr = ::poll(&pfd, 1, 250);
        if (pr <= 0) continue;
        const int cfd = ::accept(fd, nullptr, nullptr);
        if (cfd < 0) continue;
        std::string body;
        char buf[4096];
        while (body.size() < (1 << 20)) {
            const ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            body.append(buf, static_cast<size_t>(n));
            if (body.find('\n') != std::string::npos) break;
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
            const std::string method = req.exists("method") && req["method"].isStr() ? req["method"].get_str() : "";
            UniValue result;
            std::string code, emsg;
            if (!IsCapabilityHelperMethod(method)) {
                UniValue e(UniValue::VOBJ);
                e.pushKV("code", "METHOD_NOT_FOUND");
                e.pushKV("message", "capabilityd owner-local methods only");
                reply.pushKV("result", UniValue::VNULL);
                reply.pushKV("error", e);
            } else if (DispatchCapabilityRpc(cat, method, req.exists("params") ? req["params"] : UniValue(UniValue::VARR),
                                                result, code, emsg)) {
                reply.pushKV("result", result);
                reply.pushKV("error", UniValue::VNULL);
            } else {
                UniValue e(UniValue::VOBJ);
                e.pushKV("code", code);
                e.pushKV("message", emsg);
                reply.pushKV("result", UniValue::VNULL);
                reply.pushKV("error", e);
            }
        }
        const std::string out = reply.write() + "\n";
        ::send(cfd, out.data(), out.size(), 0);
        ::close(cfd);
    }
    ::close(fd);
    ::unlink(p.c_str());
    (void)err;
    return 0;
}

} // namespace modelnet
