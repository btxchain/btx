// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Worker K (MoE + topology) for BTX-SPEC-0348-CAPABILITY-01.
// Owns MoEDispatch, MoEAllResidentParity, MoEExpertMapComplete,
// MoEWorkingSetShift, MoEEvictionRaceSafe, MoERuntimeHook,
// DiscoverTopology, PlaceInTier, NumaPlaceRepresentation,
// PhysicalPoolUnique, RecoverTierLoss, PlacementCompare.
//
// Coordinator owns CMake/capability.h. This TU is the sole definition of
// the MoE/topology symbols (exec placeholders must not return).
// Do not implement peer/GDS symbols here.
//
// Portable CPU expert-paging is the PASS path. GPU MoE and real CXL
// hardware are NOT_RUN unless OS/env evidence is actually present.
// automatic_spend_atoms stays 0. Never privileged sysfs write.

#include <modelnet/capability.h>

#include <util/fs.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

namespace modelnet {
namespace {

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

bool SysfsExists(const char* p)
{
    return fs::exists(p);
}

bool DispatchableLife(LeaseLife life)
{
    return life == LeaseLife::ACTIVE || life == LeaseLife::VERIFIED;
}

bool ExpertKeyMatch(const ExpertUnit& a, uint32_t layer, uint32_t expert)
{
    return a.layer == layer && a.expert == expert;
}

bool RequiredPresent(const ExpertUnit& need, const ExpertUnit& have)
{
    if (!ExpertKeyMatch(have, need.layer, need.expert)) return false;
    if (!need.expert_id.empty() && have.expert_id != need.expert_id) return false;
    switch (have.life) {
    case LeaseLife::RELEASED:
    case LeaseLife::QUARANTINED:
        return false;
    default:
        return true;
    }
}

bool ColdEvictable(LeaseLife life)
{
    // Evict cold reservations / retiring generations. Never an executing ACTIVE expert.
    return life == LeaseLife::RESERVED || life == LeaseLife::RETIRING;
}

bool FitsBudget(size_t count, uint64_t expert_bytes, uint64_t budget)
{
    if (expert_bytes == 0) return true;
    if (count > budget / expert_bytes) return false;
    return count * expert_bytes <= budget;
}

bool SameWorkingExpert(const ExpertUnit& a, const ExpertUnit& b)
{
    if (!ExpertKeyMatch(a, b.layer, b.expert)) return false;
    if (a.expert_id.empty() || b.expert_id.empty()) return true;
    return a.expert_id == b.expert_id;
}

const char* OperatorEnvName(const std::string& runtime_id)
{
    if (runtime_id == "llama.cpp") return "BTX_LLAMA_CLI";
    if (runtime_id == "vLLM") return "BTX_VLLM";
    if (runtime_id == "MLX") return "BTX_MLX";
    return nullptr;
}

bool OperatorEnvPathExists(const char* env_name)
{
    if (!env_name) return false;
    const char* v = std::getenv(env_name);
    if (!v || v[0] == '\0') return false;
    return fs::exists(fs::PathFromString(v));
}

bool IsNumaNodeDir(const std::string& name)
{
    if (name.size() < 5 || name.compare(0, 4, "node") != 0) return false;
    for (size_t i = 4; i < name.size(); ++i) {
        if (name[i] < '0' || name[i] > '9') return false;
    }
    return true;
}

int ParseNodeIndex(const std::string& name)
{
    int n = 0;
    for (size_t i = 4; i < name.size(); ++i) {
        n = n * 10 + (name[i] - '0');
    }
    return n;
}

std::string ReadSysfsTrim(const std::string& path)
{
    std::ifstream in(path);
    if (!in) return {};
    std::string s;
    std::getline(in, s);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    return s;
}

bool FallbackAfterLoss(PlacementTier fallback)
{
    switch (fallback) {
    case PlacementTier::LOCAL_FILE:
    case PlacementTier::PAGE_CACHE:
    case PlacementTier::HOST_PAGEABLE:
    case PlacementTier::HOST_PINNED:
        return true;
    default:
        return false;
    }
}

} // namespace

bool MoEDispatch(const std::vector<ExpertUnit>& resident, uint32_t layer, uint32_t expert, bool allow_wan,
                 std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    // Spec 18.2 / JIT-MOE-06: public WAN is not an inner-token expert path.
    if (allow_wan) {
        return Fail(err_code, err, "WAN_INNER_TOKEN_FORBIDDEN",
                    "public WAN lookup is not an inner-token expert path; pause/prepare instead");
    }
    for (const auto& e : resident) {
        if (ExpertKeyMatch(e, layer, expert) && DispatchableLife(e.life)) {
            return true;
        }
    }
    // JIT-MOE-03: wait/fail. Never skip, zero-fill, or change routing.
    return Fail(err_code, err, "EXPERT_MISS",
                "required expert unavailable; wait/fail, never skip or zero-fill");
}

bool MoEAllResidentParity(Span<const unsigned char> paged, Span<const unsigned char> all_resident)
{
    // JIT-MOE-02 / J08: demand-paged bytes must match the all-resident reference exactly.
    if (paged.size() != all_resident.size()) return false;
    return std::equal(paged.begin(), paged.end(), all_resident.begin());
}

bool MoEExpertMapComplete(const std::vector<ExpertUnit>& required, const std::vector<ExpertUnit>& resident,
                           std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    for (const auto& need : required) {
        bool found = false;
        for (const auto& have : resident) {
            if (RequiredPresent(need, have)) {
                found = true;
                break;
            }
        }
        if (!found) {
            const std::string who = need.expert_id.empty() ?
                                         ("L" + std::to_string(need.layer) + "E" + std::to_string(need.expert)) :
                                         need.expert_id;
            return Fail(err_code, err, "EXPERT_UNAVAILABLE",
                        "expert map incomplete (missing scale/companion or expert " + who +
                            "); refusing mathematically incomplete admission");
        }
    }
    return true;
}

bool MoEWorkingSetShift(std::vector<ExpertUnit>& working, const ExpertUnit& incoming, uint64_t device_budget_bytes,
                         uint64_t expert_bytes, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    for (const auto& e : working) {
        if (SameWorkingExpert(e, incoming)) return true;
    }
    if (!FitsBudget(1, expert_bytes, device_budget_bytes)) {
        return Fail(err_code, err, "MEMORY_RESERVATION_FAILED",
                    "single expert exceeds device budget; stall reported, not hidden");
    }
    // Bounded demand: only the requested incoming expert, never extra prefetch fill.
    while (!working.empty() && !FitsBudget(working.size() + 1, expert_bytes, device_budget_bytes)) {
        auto it = std::find_if(working.begin(), working.end(),
                                 [](const ExpertUnit& e) { return ColdEvictable(e.life); });
        if (it == working.end()) {
            return Fail(err_code, err, "EXPERT_MISS",
                        "working-set shift cannot evict ACTIVE executing experts; miss/stall reported, not hidden");
        }
        working.erase(it);
    }
    if (!FitsBudget(working.size() + 1, expert_bytes, device_budget_bytes)) {
        return Fail(err_code, err, "EXPERT_MISS",
                    "demand expert does not fit after cold eviction; stall reported, not hidden");
    }
    working.push_back(incoming);
    return true;
}

bool MoEEvictionRaceSafe(LeaseLife executing, bool evict_same, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    // JIT-MOE-05 / spec 18.1: do not replace an expert whose generation is in-flight.
    const bool in_flight = executing == LeaseLife::ACTIVE || executing == LeaseLife::POPULATING;
    if (evict_same && in_flight) {
        return Fail(err_code, err, "TRANSFER_STILL_IN_FLIGHT",
                    "cannot evict expert currently executing; generation remains leased until quiescence");
    }
    return true;
}

bool MoERuntimeHook(const std::string& runtime_id, bool& hook_present, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    hook_present = false;
    // Portable CPU expert-paging simulation: the PASS path for MOE-01..06 and MOE-07 CPU.
    if (runtime_id == "synthetic-cpu-fixture") {
        hook_present = true;
        return true;
    }
    const char* env_name = OperatorEnvName(runtime_id);
    if (!env_name) {
        return Fail(err_code, err, "UNSUPPORTED_RUNTIME_PROFILE",
                    "unknown MoE runtime id; GPU MoE PASS is never faked");
    }
    hook_present = OperatorEnvPathExists(env_name);
    if (!hook_present) {
        return Fail(err_code, err, "LIVE_RUNTIME_NOT_RUN",
                    std::string(env_name) +
                        " unset or path not present; llama.cpp/vLLM/MLX expert hook NOT_RUN; "
                        "never fake GPU MoE PASS");
    }
    // Hook is wired (operator env path exists) but this TU does not spawn GPU dispatch.
    return Fail(err_code, err, "HARDWARE_NOT_RUN",
                runtime_id + " operator env resolved; live expert-dispatch was not executed; mock is not PASS; NOT_RUN");
}

TopologyReport DiscoverTopology()
{
    TopologyReport r;
    r.json = UniValue(UniValue::VOBJ);
    r.json.pushKV("automatic_spend_atoms", 0);
    r.json.pushKV("privileged_sysfs_write", false);
    r.json.pushKV("assumed_link_rate", UniValue::VNULL);
    r.json.pushKV("assumed_pool_capacity", UniValue::VNULL);
    r.json.pushKV("cxl_emulation", false);

#ifdef __APPLE__
    r.macos_unified = true;
    r.numa = false;
    r.cxl = false;
    r.json.pushKV("unified_memory", true);
    r.json.pushKV("numa", false);
    r.json.pushKV("cxl", false);
    r.json.pushKV("cxl_evidence", "NOT_RUN");
    r.json.pushKV("numa_evidence", "NOT_RUN");
    r.json.pushKV("numa_node_count", 0);
    r.json.pushKV("cxl_bus", false);
    r.json.pushKV("cxl_firmware", false);
    r.json.pushKV("topology_source", "macos-unified");
#elif defined(__linux__)
    UniValue nodes(UniValue::VARR);
    const bool node_root = SysfsExists("/sys/devices/system/node");
    if (node_root) {
        std::error_code ec;
        const auto root = std::filesystem::path("/sys/devices/system/node");
        for (auto it = std::filesystem::directory_iterator(root, ec), end = std::filesystem::directory_iterator();
             it != end && !ec; it.increment(ec)) {
            std::error_code dec;
            if (!it->is_directory(dec) || dec) continue;
            const std::string name = it->path().filename().string();
            if (!IsNumaNodeDir(name)) continue;
            nodes.push_back(ParseNodeIndex(name));
        }
    }
    r.numa = nodes.size() > 0;
    r.json.pushKV("numa", r.numa);
    r.json.pushKV("numa_evidence", r.numa ? "DISCOVERED" : "NOT_RUN");
    r.json.pushKV("numa_node_count", static_cast<int64_t>(nodes.size()));
    r.json.pushKV("numa_nodes", nodes);
    const std::string dist = ReadSysfsTrim("/sys/devices/system/node/node0/distance");
    if (!dist.empty()) {
        r.json.pushKV("numa_distance_sysfs", dist);
    }
    const std::string online = ReadSysfsTrim("/sys/devices/system/node/online");
    if (!online.empty()) {
        r.json.pushKV("numa_online", online);
    }

    const bool cxl_bus = SysfsExists("/sys/bus/cxl");
    const bool cxl_fw = SysfsExists("/sys/firmware/cxl");
    r.cxl = cxl_bus || cxl_fw;
    r.json.pushKV("cxl", r.cxl);
    r.json.pushKV("cxl_bus", cxl_bus);
    r.json.pushKV("cxl_firmware", cxl_fw);
    // Never claim CXL hardware from emulation or from a missing bus.
    r.json.pushKV("cxl_evidence", r.cxl ? "DISCOVERED" : "NOT_RUN");
    r.json.pushKV("unified_memory", false);
    r.json.pushKV("topology_source", "linux-sysfs");
#else
    r.json.pushKV("topology", "UNKNOWN");
    r.json.pushKV("numa", false);
    r.json.pushKV("cxl", false);
    r.json.pushKV("cxl_evidence", "NOT_RUN");
    r.json.pushKV("numa_evidence", "NOT_RUN");
    r.json.pushKV("unified_memory", false);
#endif
    return r;
}

bool PlaceInTier(PlacementTier want, PlacementTier have, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    if (want == PlacementTier::CXL_NUMA && have != PlacementTier::CXL_NUMA) {
        return Fail(err_code, err, "TIER_UNAVAILABLE",
                    "requested CXL/NUMA tier not present; emulation is not hardware evidence");
    }
    if (want == PlacementTier::DEVICE && have == PlacementTier::UNKNOWN_TIER) {
        return Fail(err_code, err, "UNKNOWN_COMPATIBILITY", "device capability unknown");
    }
    return true;
}

bool NumaPlaceRepresentation(int node, int want_node, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    if (node != want_node) {
        return Fail(err_code, err, "NUMA_MISPLACE",
                    "representation landed on NUMA node " + std::to_string(node) + " want " +
                        std::to_string(want_node));
    }
    return true;
}

bool PhysicalPoolUnique(const std::vector<std::string>& pool_ids, std::string& err_code, std::string& err)
{
    err_code.clear();
    err.clear();
    std::set<std::string> seen;
    for (const auto& id : pool_ids) {
        if (!seen.insert(id).second) {
            return Fail(err_code, err, "POOL_ALIAS_FORBIDDEN",
                        "duplicate physical pool id '" + id + "'; UMA/CXL aliases must not double-count capacity");
        }
    }
    return true;
}

bool RecoverTierLoss(PlacementTier lost, PlacementTier fallback, PlacementTier& used, std::string& err_code,
                     std::string& err)
{
    err_code.clear();
    err.clear();
    used = PlacementTier::UNKNOWN_TIER;
    // JIT-CXL-06: topology discovery does not confer host administration. Never write sysfs.
    if (lost == fallback) {
        return Fail(err_code, err, "TIER_UNAVAILABLE",
                    "cannot recover onto the lost tier; no privileged fabric/hotplug configuration");
    }
    if (fallback == PlacementTier::CXL_NUMA || fallback == PlacementTier::UNKNOWN_TIER) {
        return Fail(err_code, err, "TIER_UNAVAILABLE",
                    "lost-tier recovery cannot claim CXL/unknown without hardware evidence");
    }
    if (lost == PlacementTier::CXL_NUMA && fallback == PlacementTier::HOST_PAGEABLE) {
        used = PlacementTier::HOST_PAGEABLE;
        return true;
    }
    if (!FallbackAfterLoss(fallback)) {
        return Fail(err_code, err, "TIER_UNAVAILABLE",
                    "fallback tier not eligible after loss; drain/fail rather than stale dereference");
    }
    used = fallback;
    return true;
}

bool PlacementCompare(int64_t local_nvme_ms, int64_t remote_tier_ms, PlacementTier& chosen)
{
    // JIT-CXL-07: pick the faster eligible measured path. Not a fixed CXL>NVMe ladder.
    chosen = PlacementTier::UNKNOWN_TIER;
    const bool local_ok = local_nvme_ms >= 0;
    const bool remote_ok = remote_tier_ms >= 0;
    if (!local_ok && !remote_ok) return false;
    if (local_ok && (!remote_ok || local_nvme_ms <= remote_tier_ms)) {
        chosen = PlacementTier::LOCAL_FILE;
        return true;
    }
    chosen = PlacementTier::CXL_NUMA;
    return true;
}

} // namespace modelnet
