// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/resource_governor.h>

#include <logging.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

namespace node {

namespace {

std::mutex g_gov_mu;
ResourceGovernor* g_gov = nullptr;

int ClampInt(int v, int lo, int hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int64_t ClampI64(int64_t v, int64_t lo, int64_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

int ModeUploadDivisor(GovernorMode m)
{
    switch (m) {
    case GovernorMode::PERFORMANCE: return 1;
    case GovernorMode::AUTO: return 2;
    case GovernorMode::BALANCED: return 4;
    case GovernorMode::ECO: return 8;
    case GovernorMode::MANUAL: return 2;
    case GovernorMode::OFF: return 32;
    }
    return 2;
}

int ModeMiningCap(GovernorMode m, int configured)
{
    if (m == GovernorMode::OFF) return 0;
    if (m == GovernorMode::ECO) return std::min(configured, 25);
    if (m == GovernorMode::BALANCED) return std::min(configured, 50);
    return configured;
}

} // namespace

const char* GovernorModeName(GovernorMode m)
{
    switch (m) {
    case GovernorMode::AUTO: return "AUTO";
    case GovernorMode::PERFORMANCE: return "PERFORMANCE";
    case GovernorMode::BALANCED: return "BALANCED";
    case GovernorMode::ECO: return "ECO";
    case GovernorMode::MANUAL: return "MANUAL";
    case GovernorMode::OFF: return "OFF";
    }
    return "AUTO";
}

bool ParseGovernorMode(const std::string& s, GovernorMode& out)
{
    std::string u = s;
    for (char& c : u) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    if (u == "AUTO") { out = GovernorMode::AUTO; return true; }
    if (u == "PERFORMANCE") { out = GovernorMode::PERFORMANCE; return true; }
    if (u == "BALANCED") { out = GovernorMode::BALANCED; return true; }
    if (u == "ECO") { out = GovernorMode::ECO; return true; }
    if (u == "MANUAL") { out = GovernorMode::MANUAL; return true; }
    if (u == "OFF") { out = GovernorMode::OFF; return true; }
    return false;
}

const char* PauseReasonName(PauseReason r)
{
    switch (r) {
    case PauseReason::NONE: return "NONE";
    case PauseReason::FOREGROUND_GPU_LOAD: return "FOREGROUND_GPU_LOAD";
    case PauseReason::VALIDATION_PRIORITY: return "VALIDATION_PRIORITY";
    case PauseReason::THERMAL_PRESSURE: return "THERMAL_PRESSURE";
    case PauseReason::BATTERY_POLICY: return "BATTERY_POLICY";
    case PauseReason::USER_DISABLED: return "USER_DISABLED";
    case PauseReason::GOVERNOR_COOLDOWN: return "GOVERNOR_COOLDOWN";
    case PauseReason::GPU_MEMORY_PRESSURE: return "GPU_MEMORY_PRESSURE";
    case PauseReason::NETWORK_BUSY: return "NETWORK_BUSY";
    case PauseReason::LATENCY_PRESSURE: return "LATENCY_PRESSURE";
    case PauseReason::DISK_PRESSURE: return "DISK_PRESSURE";
    case PauseReason::STORAGE_FULL: return "STORAGE_FULL";
    case PauseReason::USER_TRANSFER_PRIORITY: return "USER_TRANSFER_PRIORITY";
    case PauseReason::POWER_POLICY: return "POWER_POLICY";
    case PauseReason::METERED_NETWORK: return "METERED_NETWORK";
    case PauseReason::GOVERNOR_UNAVAILABLE: return "GOVERNOR_UNAVAILABLE";
    }
    return "NONE";
}

const char* ThermalStateName(ThermalState t)
{
    switch (t) {
    case ThermalState::UNKNOWN: return "UNKNOWN";
    case ThermalState::NORMAL: return "NORMAL";
    case ThermalState::WARM: return "WARM";
    case ThermalState::HOT: return "HOT";
    case ThermalState::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char* PressureStateName(PressureState p)
{
    switch (p) {
    case PressureState::UNKNOWN: return "UNKNOWN";
    case PressureState::OK: return "OK";
    case PressureState::ELEVATED: return "ELEVATED";
    case PressureState::HIGH: return "HIGH";
    case PressureState::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

bool GovernorTouchesConsensus() { return false; }
bool GovernorAuthorizesSpend() { return false; }

ResourceGovernor& GlobalResourceGovernor()
{
    std::lock_guard<std::mutex> lock(g_gov_mu);
    if (!g_gov) g_gov = new ResourceGovernor();
    return *g_gov;
}

void ResetGlobalResourceGovernorForTest()
{
    std::lock_guard<std::mutex> lock(g_gov_mu);
    delete g_gov;
    g_gov = new ResourceGovernor();
}

void ResourceGovernor::SetMode(GovernorMode m)
{
    if (m_mode == m) return;
    m_mode = m;
    ++m_generation;
    ++m_status_seq;
    ++m_metrics.transitions;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::SetPolicy(const GovernorPolicy& p)
{
    GovernorPolicy n = p;
    n.idle_gpu_threshold = ClampInt(n.idle_gpu_threshold, 0, 90);
    n.pause_gpu_threshold = ClampInt(n.pause_gpu_threshold, n.idle_gpu_threshold + 1, 100);
    n.idle_resume_seconds = ClampInt(n.idle_resume_seconds, 1, 600);
    n.pause_seconds = ClampInt(n.pause_seconds, 1, 120);
    n.cooldown_seconds = ClampInt(n.cooldown_seconds, 0, 600);
    n.mining_max_intensity = ClampInt(n.mining_max_intensity, 0, 100);
    n.upload_max_bps = ClampI64(n.upload_max_bps, 0, 10LL * 1024 * 1024 * 1024);
    n.background_upload_floor_bps = ClampI64(n.background_upload_floor_bps, 0, 1024 * 1024 * 1024);
    n.background_upload_auto_bps = ClampI64(n.background_upload_auto_bps, n.background_upload_floor_bps, 1024LL * 1024 * 1024);
    m_policy = n;
    ++m_generation;
    ++m_status_seq;
}

void ResourceGovernor::ResetPolicy()
{
    SetPolicy(GovernorPolicy{});
}

void ResourceGovernor::SetMiningConsent(bool on)
{
    if (m_mining_consent == on) return;
    m_mining_consent = on;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::SetUnavailable(bool on)
{
    if (m_unavailable == on) return;
    m_unavailable = on;
    ++m_generation;
    ++m_status_seq;
    ++m_metrics.transitions;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::BeginForegroundAiWork()
{
    if (m_foreground_ai) return;
    m_foreground_ai = true;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::EndForegroundAiWork()
{
    if (!m_foreground_ai) return;
    m_foreground_ai = false;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::BeginValidationWork()
{
    if (m_validation) return;
    m_validation = true;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::EndValidationWork()
{
    if (!m_validation) return;
    m_validation = false;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::SetUserRetrievalActive(bool on)
{
    if (m_user_retrieval == on) return;
    m_user_retrieval = on;
    ++m_generation;
    ++m_status_seq;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::PauseBackground(int64_t now_ms, int64_t duration_ms)
{
    m_user_pause = true;
    m_user_pause_until_ms = duration_ms > 0 ? now_ms + duration_ms : 0;
    ++m_generation;
    ++m_status_seq;
    ++m_metrics.transitions;
    MaybeTransition(now_ms);
}

void ResourceGovernor::ResumeBackground()
{
    m_user_pause = false;
    m_user_pause_until_ms = 0;
    ++m_generation;
    ++m_status_seq;
    ++m_metrics.transitions;
    MaybeTransition(m_last_tick_ms);
}

void ResourceGovernor::MaybeTransition(int64_t now_ms)
{
    const GovernorPolicy& p = m_policy;
    const SystemSignals& s = m_sig;
    const PauseReason prev_mine = m_mining_reason;
    const int prev_intensity = m_intensity;
    const bool prev_active = m_mining_active;

    if (m_unavailable) {
        m_mining_active = false;
        m_intensity = 0;
        m_mining_reason = PauseReason::GOVERNOR_UNAVAILABLE;
        m_effective_upload_bps = p.background_upload_floor_bps;
        m_seed_reason = PauseReason::GOVERNOR_UNAVAILABLE;
        m_preserve_reason = PauseReason::GOVERNOR_UNAVAILABLE;
        m_last_tick_ms = now_ms;
        return;
    }

    if (m_user_pause && m_user_pause_until_ms > 0 && now_ms >= m_user_pause_until_ms) {
        m_user_pause = false;
        m_user_pause_until_ms = 0;
    }

    const bool validation = m_validation || s.validation_active;
    const bool fg_ai = m_foreground_ai || s.foreground_ai;
    const bool user_dl = m_user_retrieval || s.user_retrieval_active;
    const bool thermal_hot = s.gpu.thermal == ThermalState::HOT || s.gpu.thermal == ThermalState::CRITICAL;
    const bool thermal_crit = s.gpu.thermal == ThermalState::CRITICAL;
    const bool battery_block = !s.on_ac && !p.battery_background_allowed;
    const bool mem_pressure = s.memory_pressure == PressureState::HIGH ||
                              s.memory_pressure == PressureState::CRITICAL || s.swap_pressure;
    const bool gpu_unknown = s.gpu.utilization_pct < 0;
    const int util = s.gpu.utilization_pct;

    PauseReason hard = PauseReason::NONE;
    if (m_mode == GovernorMode::OFF) hard = PauseReason::USER_DISABLED;
    else if (m_user_pause) hard = PauseReason::USER_DISABLED;
    else if (!m_mining_consent) hard = PauseReason::USER_DISABLED;
    else if (validation) hard = PauseReason::VALIDATION_PRIORITY;
    else if (fg_ai) hard = PauseReason::FOREGROUND_GPU_LOAD;
    else if (thermal_crit || thermal_hot) hard = PauseReason::THERMAL_PRESSURE;
    else if (battery_block) hard = PauseReason::BATTERY_POLICY;
    else if (mem_pressure) hard = PauseReason::GPU_MEMORY_PRESSURE;
    else if (s.gpu.reserved_for_validation || s.gpu.excluded) hard = PauseReason::VALIDATION_PRIORITY;

    int idle_need_s = p.idle_resume_seconds;
    if (m_mode == GovernorMode::PERFORMANCE) idle_need_s = std::min(idle_need_s, 5);

    if (util >= 0 && util < p.idle_gpu_threshold) {
        if (m_low_util_since_ms < 0) m_low_util_since_ms = now_ms;
        m_high_util_since_ms = -1;
        m_gpu_idle = (now_ms - m_low_util_since_ms >= int64_t(idle_need_s) * 1000)
                         ? DimIdle::IDLE
                         : DimIdle::BECOMING_IDLE;
    } else if (util > p.pause_gpu_threshold) {
        if (m_high_util_since_ms < 0) m_high_util_since_ms = now_ms;
        m_low_util_since_ms = -1;
        m_gpu_idle = (now_ms - m_high_util_since_ms >= int64_t(p.pause_seconds) * 1000)
                         ? DimIdle::ACTIVE
                         : DimIdle::BECOMING_ACTIVE;
    } else if (util >= 0) {
        // Between thresholds: hold current hysteresis timers (no flap).
        m_gpu_idle = m_mining_active ? DimIdle::IDLE : DimIdle::ACTIVE;
    } else {
        m_gpu_idle = DimIdle::IDLE; // unknown telemetry: do not pretend the GPU is busy
    }

    const bool sustained_idle = util >= 0 && util < p.idle_gpu_threshold &&
                                m_low_util_since_ms >= 0 &&
                                now_ms - m_low_util_since_ms >= int64_t(idle_need_s) * 1000;
    const bool sustained_busy = util > p.pause_gpu_threshold &&
                                 m_high_util_since_ms >= 0 &&
                                 now_ms - m_high_util_since_ms >= int64_t(p.pause_seconds) * 1000;
    const bool in_cooldown = m_last_pause_ms >= 0 &&
                             now_ms - m_last_pause_ms < int64_t(p.cooldown_seconds) * 1000;

    PauseReason mine_r = hard;
    if (hard == PauseReason::NONE) {
        if (!m_auto_schedule) {
            mine_r = PauseReason::NONE;
        } else if (gpu_unknown) {
            // Conservative: after a real Observe, allow low intensity. Do not
            // start from SetMiningConsent with empty signals.
            mine_r = m_have_sample ? PauseReason::NONE : PauseReason::GOVERNOR_COOLDOWN;
        } else if (sustained_busy) {
            mine_r = PauseReason::FOREGROUND_GPU_LOAD;
        } else if (in_cooldown && !m_mining_active) {
            mine_r = PauseReason::GOVERNOR_COOLDOWN;
        } else if (!m_mining_active && !sustained_idle) {
            mine_r = PauseReason::GOVERNOR_COOLDOWN;
        }
    }

    const bool want_mine = (mine_r == PauseReason::NONE);
    if (want_mine != m_mining_active) {
        m_mining_active = want_mine;
        ++m_metrics.transitions;
        ++m_status_seq;
        ++m_generation;
        if (want_mine) {
            m_last_resume_ms = now_ms;
            m_intensity = 25;
        } else {
            m_last_pause_ms = now_ms;
            m_intensity = 0;
        }
    } else if (m_mining_active) {
        const int cap = ModeMiningCap(m_mode, p.mining_max_intensity);
        int64_t idle_for = m_last_resume_ms >= 0 ? now_ms - m_last_resume_ms : 0;
        int target = 25;
        if (!gpu_unknown) {
            if (idle_for >= 30000) target = 50;
            if (idle_for >= 60000) target = 75;
            if (idle_for >= 90000) target = cap;
        }
        if (!m_auto_schedule) target = cap;
        if (s.gpu.thermal == ThermalState::WARM) target = std::min(target, 50);
        if (m_mode == GovernorMode::ECO) target = std::min(target, 25);
        m_intensity = std::min(cap, std::max(0, target));
    } else {
        m_intensity = 0;
    }
    m_mining_reason = m_mining_active ? PauseReason::NONE : (mine_r == PauseReason::NONE ? PauseReason::GOVERNOR_COOLDOWN : mine_r);

    // Network: spare capacity, not binary idle. Hard caps always win.
    int64_t auto_ceil = p.background_upload_auto_bps / ModeUploadDivisor(m_mode);
    if (m_mode == GovernorMode::PERFORMANCE) auto_ceil = p.background_upload_auto_bps;
    if (m_mode == GovernorMode::OFF || m_user_pause) auto_ceil = 0;
    if (s.metered && !p.background_on_metered) auto_ceil = 0;
    if (!s.on_ac && !p.battery_background_allowed) auto_ceil = std::min(auto_ceil, p.background_upload_floor_bps);

    if (p.latency_backoff_enabled && s.latency_baseline_ms > 0 && s.latency_current_ms > 0 &&
        s.latency_current_ms > s.latency_baseline_ms * 2 + 20) {
        auto_ceil /= 4;
        m_seed_reason = PauseReason::LATENCY_PRESSURE;
    } else if (s.egress_bps > 0 && s.egress_bps > auto_ceil * 65 / 100 && auto_ceil > 0) {
        auto_ceil = std::max(p.background_upload_floor_bps, auto_ceil / 2);
        m_seed_reason = PauseReason::NETWORK_BUSY;
    } else if (user_dl) {
        auto_ceil = std::max(p.background_upload_floor_bps, auto_ceil / 4);
        m_seed_reason = PauseReason::USER_TRANSFER_PRIORITY;
    } else if (m_mode == GovernorMode::OFF || m_user_pause) {
        m_seed_reason = PauseReason::USER_DISABLED;
    } else if (s.metered && !p.background_on_metered) {
        m_seed_reason = PauseReason::METERED_NETWORK;
    } else {
        m_seed_reason = PauseReason::NONE;
        if (s.egress_bps < auto_ceil * 25 / 100) {
            // quiet: keep / gradually raise (already at auto_ceil)
        }
    }
    // Operator/profile upload_max_bps may replace the auto ceiling, but must
    // not restore a hard environmental stop (metered / OFF / battery floor).
    if (!p.upload_auto && p.upload_max_bps > 0 && auto_ceil > 0) auto_ceil = p.upload_max_bps;
    if (p.upload_max_bps > 0 && auto_ceil > 0) auto_ceil = std::min(auto_ceil, p.upload_max_bps);
    if (m_mode == GovernorMode::OFF || m_user_pause) auto_ceil = 0;
    if (s.metered && !p.background_on_metered) auto_ceil = 0;
    if (!s.on_ac && !p.battery_background_allowed) {
        auto_ceil = std::min(auto_ceil, p.background_upload_floor_bps);
    }
    m_effective_upload_bps = auto_ceil;

    if (thermal_crit) m_preserve_reason = PauseReason::THERMAL_PRESSURE;
    else if (battery_block && !p.preserve_on_battery) m_preserve_reason = PauseReason::BATTERY_POLICY;
    else if (s.metered && !p.background_on_metered) m_preserve_reason = PauseReason::METERED_NETWORK;
    else if (s.storage_free_pct < 5) m_preserve_reason = PauseReason::STORAGE_FULL;
    else if (s.disk_pressure == PressureState::HIGH || s.disk_pressure == PressureState::CRITICAL)
        m_preserve_reason = PauseReason::DISK_PRESSURE;
    else if (user_dl) m_preserve_reason = PauseReason::USER_TRANSFER_PRIORITY;
    else if (m_mode == GovernorMode::OFF || m_user_pause) m_preserve_reason = PauseReason::USER_DISABLED;
    else m_preserve_reason = PauseReason::NONE;

    if (m_last_tick_ms > 0 && now_ms > m_last_tick_ms) {
        const int64_t dt = (now_ms - m_last_tick_ms) / 1000;
        if (m_mining_active) m_metrics.mining_active_seconds += dt;
        if (want_mine) m_metrics.mining_allowed_seconds += dt;
        if (m_mining_reason == PauseReason::FOREGROUND_GPU_LOAD) m_metrics.mining_paused_foreground_seconds += dt;
        if (m_mining_reason == PauseReason::VALIDATION_PRIORITY) m_metrics.mining_paused_validation_seconds += dt;
        if (m_mining_reason == PauseReason::THERMAL_PRESSURE) m_metrics.mining_paused_thermal_seconds += dt;
        if (m_seed_reason != PauseReason::NONE) m_metrics.model_seed_throttled_seconds += dt;
        if (m_preserve_reason != PauseReason::NONE) m_metrics.preservation_paused_seconds += dt;
    }
    m_last_tick_ms = now_ms;
    if (prev_active != m_mining_active || prev_mine != m_mining_reason || prev_intensity != m_intensity) {
        if (m_mining_active) {
            LogInfo("resource-governor: mining RESUME idle=%ds intensity=%d%%\n",
                    m_last_resume_ms >= 0 && now_ms >= m_last_resume_ms ? int((now_ms - m_last_resume_ms) / 1000) : 0,
                    m_intensity);
        } else if (prev_active && !m_mining_active) {
            LogInfo("resource-governor: mining PAUSE reason=%s util=%d%%\n",
                    PauseReasonName(m_mining_reason), util);
        }
    }
}

void ResourceGovernor::Observe(const SystemSignals& s, int64_t now_ms)
{
    m_sig = s;
    m_have_sample = true;
    MaybeTransition(now_ms);
}

BackgroundPermit ResourceGovernor::Permit(GovernorJob job) const
{
    BackgroundPermit out;
    out.generation = m_generation;
    if (m_mode == GovernorMode::OFF) {
        out.reason = PauseReason::USER_DISABLED;
        if (job == GovernorJob::MODEL_SEED) {
            // explicit retrieval still uses helper; ordinary seeding off
        }
        return out;
    }
    switch (job) {
    case GovernorJob::MINING:
        out.allowed = MiningAllowed();
        out.max_intensity = m_intensity;
        out.reason = m_mining_reason;
        return out;
    case GovernorJob::MODEL_SEED:
        out.allowed = m_effective_upload_bps > 0 && m_seed_reason != PauseReason::USER_DISABLED;
        out.max_bandwidth_bps = m_effective_upload_bps;
        out.max_concurrency = m_sig.memory_pressure == PressureState::HIGH ? 1 : 8;
        out.reason = m_seed_reason;
        return out;
    case GovernorJob::PRESERVATION: {
        const bool ok = m_preserve_reason == PauseReason::NONE;
        out.allowed = ok;
        out.max_bandwidth_bps = ok ? std::min(m_effective_upload_bps, int64_t(5) * 1024 * 1024) : 0;
        out.max_concurrency = ok ? 2 : 0;
        out.reason = m_preserve_reason;
        return out;
    }
    case GovernorJob::QUALIFICATION:
        out.allowed = MiningAllowed() && m_mode != GovernorMode::ECO;
        out.max_intensity = std::min(m_intensity, 50);
        out.reason = out.allowed ? PauseReason::NONE : m_mining_reason;
        return out;
    case GovernorJob::CACHE_GC: {
        const bool emergency = m_sig.storage_free_pct < 5 || m_sig.disk_pressure == PressureState::CRITICAL;
        const bool quiet = m_preserve_reason == PauseReason::NONE || emergency;
        out.allowed = emergency || (quiet && m_mode != GovernorMode::OFF);
        out.max_concurrency = emergency ? 4 : 1;
        out.reason = out.allowed ? PauseReason::NONE : PauseReason::DISK_PRESSURE;
        return out;
    }
    case GovernorJob::SEARCH_MAINTENANCE:
        out.allowed = m_mode != GovernorMode::OFF && !m_user_pause &&
                      m_sig.cpu_pressure != PressureState::CRITICAL;
        out.max_concurrency = 1;
        out.reason = out.allowed ? PauseReason::NONE : PauseReason::POWER_POLICY;
        return out;
    }
    return out;
}

bool ResourceGovernor::MiningAllowed() const
{
    // OFF denies mining (and all other governed work). It is not an ungoverned
    // mining mode and must stay false here.
    if (m_unavailable || m_mode == GovernorMode::OFF || !m_mining_consent) return false;
    if (m_user_pause || m_validation || m_foreground_ai) return false;
    // Unarmed AUTO/hysteresis must not fail-open. MaybeTransition already
    // starts mining when auto-schedule is off (existing -gen miner). Returning
    // true here let SolveMatMulV4RC's consent latch skip idle gating.
    return m_mining_active && m_intensity > 0;
}

UniValue ResourceGovernor::InfoJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("mode", GovernorModeName(m_mode));
    o.pushKV("enabled", m_mode != GovernorMode::OFF);
    o.pushKV("system_idle_state", m_gpu_idle == DimIdle::IDLE ? "IDLE" : "ACTIVE");
    if (m_sig.user_idle_ms >= 0) o.pushKV("user_idle_seconds", m_sig.user_idle_ms / 1000);
    UniValue cpu(UniValue::VOBJ);
    cpu.pushKV("load", m_sig.cpu_load_pct);
    cpu.pushKV("pressure_state", PressureStateName(m_sig.cpu_pressure));
    o.pushKV("cpu", cpu);
    UniValue mem(UniValue::VOBJ);
    mem.pushKV("available_bytes", m_sig.memory_available_bytes);
    mem.pushKV("pressure_state", PressureStateName(m_sig.memory_pressure));
    o.pushKV("memory", mem);
    UniValue gpus(UniValue::VARR);
    UniValue g(UniValue::VOBJ);
    g.pushKV("id", m_sig.gpu.id);
    g.pushKV("type", m_sig.gpu.type);
    g.pushKV("utilization", m_sig.gpu.utilization_pct);
    g.pushKV("memory_used", m_sig.gpu.memory_used);
    g.pushKV("memory_total", m_sig.gpu.memory_total);
    g.pushKV("temperature", m_sig.gpu.temperature_c);
    g.pushKV("thermal_state", ThermalStateName(m_sig.gpu.thermal));
    g.pushKV("mining_allowed", MiningAllowed() && !m_sig.gpu.reserved_for_validation);
    g.pushKV("mining_active", m_mining_active);
    g.pushKV("mining_intensity", m_intensity);
    g.pushKV("pause_reason", PauseReasonName(m_mining_reason));
    gpus.push_back(g);
    o.pushKV("gpu", gpus);
    UniValue net(UniValue::VOBJ);
    net.pushKV("ingress_bps", m_sig.ingress_bps);
    net.pushKV("egress_bps", m_sig.egress_bps);
    net.pushKV("background_upload_limit_bps", m_effective_upload_bps);
    net.pushKV("current_model_upload_bps", m_sig.egress_bps);
    net.pushKV("latency_baseline_ms", m_sig.latency_baseline_ms);
    net.pushKV("latency_current_ms", m_sig.latency_current_ms);
    net.pushKV("pressure_state", PauseReasonName(m_seed_reason));
    o.pushKV("network", net);
    UniValue st(UniValue::VOBJ);
    st.pushKV("current_model_io_bps", m_sig.model_io_bps);
    st.pushKV("pressure_state", PressureStateName(m_sig.disk_pressure));
    o.pushKV("storage", st);
    UniValue power(UniValue::VOBJ);
    power.pushKV("on_ac", m_sig.on_ac);
    if (m_sig.battery_percent >= 0) power.pushKV("battery_percent", m_sig.battery_percent);
    power.pushKV("thermal_state", ThermalStateName(m_sig.gpu.thermal));
    o.pushKV("power", power);
    o.pushKV("jobs", JobsJson());
    o.pushKV("last_policy_change", int64_t(m_generation));
    o.pushKV("last_transition", int64_t(m_status_seq));
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("touches_consensus", false);
    return o;
}

UniValue ResourceGovernor::PolicyJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("idle_gpu_threshold", m_policy.idle_gpu_threshold);
    o.pushKV("pause_gpu_threshold", m_policy.pause_gpu_threshold);
    o.pushKV("idle_resume_seconds", m_policy.idle_resume_seconds);
    o.pushKV("pause_seconds", m_policy.pause_seconds);
    o.pushKV("cooldown_seconds", m_policy.cooldown_seconds);
    o.pushKV("mining_max_intensity", m_policy.mining_max_intensity);
    o.pushKV("upload_auto", m_policy.upload_auto);
    o.pushKV("upload_max_bps", m_policy.upload_max_bps);
    o.pushKV("latency_backoff_enabled", m_policy.latency_backoff_enabled);
    o.pushKV("battery_background_allowed", m_policy.battery_background_allowed);
    o.pushKV("preserve_on_battery", m_policy.preserve_on_battery);
    o.pushKV("background_on_metered", m_policy.background_on_metered);
    o.pushKV("background_upload_auto_bps", m_policy.background_upload_auto_bps);
    o.pushKV("precedence", "cli > conf > gui > mode defaults > platform");
    return o;
}

UniValue ResourceGovernor::JobsJson() const
{
    UniValue arr(UniValue::VARR);
    const GovernorJob jobs[] = {
        GovernorJob::MINING, GovernorJob::MODEL_SEED, GovernorJob::PRESERVATION,
        GovernorJob::QUALIFICATION, GovernorJob::CACHE_GC, GovernorJob::SEARCH_MAINTENANCE};
    const char* names[] = {"MINING", "MODEL_SEED", "PRESERVATION", "QUALIFICATION", "CACHE_GC", "SEARCH_MAINTENANCE"};
    for (int i = 0; i < 6; ++i) {
        auto p = Permit(jobs[i]);
        UniValue j(UniValue::VOBJ);
        j.pushKV("type", names[i]);
        j.pushKV("state", p.allowed ? "running" : "paused");
        j.pushKV("priority", 8 - i);
        j.pushKV("pause_reason", PauseReasonName(p.reason));
        j.pushKV("max_intensity", p.max_intensity);
        j.pushKV("max_bandwidth_bps", p.max_bandwidth_bps);
        arr.push_back(j);
    }
    return arr;
}

UniValue ResourceGovernor::MiningInfoJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("enabled", m_mining_consent);
    o.pushKV("automatic", m_mode == GovernorMode::AUTO);
    o.pushKV("active", m_mining_active);
    o.pushKV("intensity", m_intensity);
    o.pushKV("device", m_sig.gpu.id);
    o.pushKV("current_utilization", m_sig.gpu.utilization_pct);
    o.pushKV("pause_reason", PauseReasonName(m_mining_reason));
    o.pushKV("last_started", m_last_resume_ms);
    o.pushKV("last_stopped", m_last_pause_ms);
    o.pushKV("mined_idle_seconds", m_metrics.mining_active_seconds);
    o.pushKV("reserved_validator", m_sig.gpu.reserved_for_validation);
    return o;
}

UniValue ResourceGovernor::BandwidthJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("current_upload", m_sig.egress_bps);
    o.pushKV("current_download", m_sig.ingress_bps);
    o.pushKV("foreground_download", m_user_retrieval);
    o.pushKV("background_download", Permit(GovernorJob::PRESERVATION).max_bandwidth_bps);
    o.pushKV("seed_upload", m_effective_upload_bps);
    o.pushKV("configured_maximum", m_policy.upload_max_bps);
    o.pushKV("effective_governor_ceiling", m_effective_upload_bps);
    o.pushKV("latency_pressure", m_seed_reason == PauseReason::LATENCY_PRESSURE);
    return o;
}

bool ResourceGovernor::ApplyPolicyJson(const UniValue& o, std::string& err)
{
    if (!o.isObject()) {
        err = "policy must be an object";
        return false;
    }
    GovernorPolicy p = m_policy;
    auto take_int = [&](const char* k, int& dst, int lo, int hi) {
        if (!o.exists(k)) return true;
        if (!o[k].isNum()) {
            err = std::string(k) + " must be a number";
            return false;
        }
        int v = o[k].getInt<int>();
        if (v < lo || v > hi) {
            err = std::string(k) + " out of range";
            return false;
        }
        dst = v;
        return true;
    };
    auto take_i64 = [&](const char* k, int64_t& dst, int64_t lo, int64_t hi) {
        if (!o.exists(k)) return true;
        if (!o[k].isNum()) {
            err = std::string(k) + " must be a number";
            return false;
        }
        int64_t v = o[k].getInt<int64_t>();
        if (v < lo || v > hi) {
            err = std::string(k) + " out of range";
            return false;
        }
        dst = v;
        return true;
    };
    auto take_bool = [&](const char* k, bool& dst) {
        if (!o.exists(k)) return true;
        if (!o[k].isBool()) {
            err = std::string(k) + " must be a boolean";
            return false;
        }
        dst = o[k].get_bool();
        return true;
    };
    if (!take_int("idle_gpu_threshold", p.idle_gpu_threshold, 0, 90)) return false;
    if (!take_int("pause_gpu_threshold", p.pause_gpu_threshold, 1, 100)) return false;
    if (!take_int("idle_resume_seconds", p.idle_resume_seconds, 1, 600)) return false;
    if (!take_int("pause_seconds", p.pause_seconds, 1, 120)) return false;
    if (!take_int("cooldown_seconds", p.cooldown_seconds, 0, 600)) return false;
    if (!take_int("mining_max_intensity", p.mining_max_intensity, 0, 100)) return false;
    if (!take_i64("upload_max_bps", p.upload_max_bps, 0, 10LL * 1024 * 1024 * 1024)) return false;
    if (!take_bool("upload_auto", p.upload_auto)) return false;
    if (!take_bool("latency_backoff_enabled", p.latency_backoff_enabled)) return false;
    if (!take_bool("battery_background_allowed", p.battery_background_allowed)) return false;
    if (!take_bool("preserve_on_battery", p.preserve_on_battery)) return false;
    if (!take_bool("background_on_metered", p.background_on_metered)) return false;
    if (p.pause_gpu_threshold <= p.idle_gpu_threshold) {
        err = "pause_gpu_threshold must exceed idle_gpu_threshold";
        return false;
    }
    SetPolicy(p);
    return true;
}

bool ResourceGovernor::WritePermitFile(const std::string& path) const
{
    UniValue o(UniValue::VOBJ);
    const auto seed = Permit(GovernorJob::MODEL_SEED);
    const auto pres = Permit(GovernorJob::PRESERVATION);
    const auto mine = Permit(GovernorJob::MINING);
    o.pushKV("schema_version", 1);
    o.pushKV("generation", static_cast<int64_t>(m_generation));
    o.pushKV("mode", GovernorModeName(m_mode));
    o.pushKV("mining_allowed", mine.allowed);
    o.pushKV("mining_intensity", mine.max_intensity);
    o.pushKV("seeding_allowed", seed.allowed);
    o.pushKV("upload_bps", seed.max_bandwidth_bps);
    o.pushKV("preservation_allowed", pres.allowed);
    o.pushKV("pause_reason_mining", PauseReasonName(m_mining_reason));
    o.pushKV("pause_reason_seed", PauseReasonName(m_seed_reason));
    o.pushKV("pause_reason_preserve", PauseReasonName(m_preserve_reason));
    o.pushKV("automatic_spend_atoms", 0);
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << o.write();
    return bool(f);
}

SystemSignals SampleHostSignals()
{
    SystemSignals s;
#ifdef __linux__
    {
        std::ifstream f("/proc/loadavg");
        double a = -1;
        if (f >> a) {
            s.cpu_load_pct = ClampInt(int(a * 25.0), 0, 100);
            s.cpu_pressure = s.cpu_load_pct > 85 ? PressureState::HIGH : PressureState::OK;
        }
    }
    {
        std::ifstream f("/proc/meminfo");
        std::string k;
        int64_t avail = -1, total = -1, swap_free = -1, swap_total = -1;
        while (f >> k) {
            int64_t v = 0;
            std::string unit;
            f >> v >> unit;
            if (k == "MemAvailable:") avail = v * 1024;
            else if (k == "MemTotal:") total = v * 1024;
            else if (k == "SwapFree:") swap_free = v * 1024;
            else if (k == "SwapTotal:") swap_total = v * 1024;
        }
        s.memory_available_bytes = avail;
        if (total > 0 && avail >= 0) {
            const int used_pct = int((total - avail) * 100 / total);
            s.memory_pressure = used_pct > 95 ? PressureState::CRITICAL : used_pct > 85 ? PressureState::HIGH : PressureState::OK;
        }
        s.swap_pressure = swap_total > 0 && swap_free >= 0 && swap_free * 10 < swap_total;
    }
    {
        const char* ps_c = std::getenv("BTX_POWER_SUPPLY_DIR");
        const std::string ps = (ps_c && ps_c[0]) ? std::string(ps_c) : std::string("/sys/class/power_supply");
        std::ifstream ac(ps + "/AC/online");
        int v = 1;
        if (ac >> v) s.on_ac = v != 0;
        else {
            std::ifstream ac2(ps + "/ACAD/online");
            if (ac2 >> v) s.on_ac = v != 0;
        }
        std::ifstream cap(ps + "/BAT0/capacity");
        int pct = -1;
        if (cap >> pct) s.battery_percent = ClampInt(pct, 0, 100);
    }
    s.gpu.type = "UNKNOWN";
    s.gpu.utilization_pct = -1; // NVML optional; conservative if mining gated on unknown
    const char* nv_en = std::getenv("BTX_GOV_NVIDIA_SAMPLE");
    const bool want_nv = nv_en && nv_en[0] == '1';
    static int64_t nv_next_ms = 0;
    static AcceleratorSample nv_cache;
    static bool nv_have = false;
    if (want_nv) {
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now().time_since_epoch())
                              .count();
        if (!nv_have || now >= nv_next_ms) {
            nv_next_ms = now + 5000;
            nv_have = false;
            if (FILE* nv = popen("nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>/dev/null", "r")) {
                char line[256]{};
                if (fgets(line, sizeof(line), nv)) {
                    int util = -1, temp = -1;
                    long used = -1, total = -1;
                    if (std::sscanf(line, "%d, %ld, %ld, %d", &util, &used, &total, &temp) == 4) {
                        nv_cache.type = "NVIDIA";
                        nv_cache.utilization_pct = ClampInt(util, 0, 100);
                        nv_cache.memory_used = used * 1024 * 1024;
                        nv_cache.memory_total = total * 1024 * 1024;
                        nv_cache.temperature_c = temp;
                        nv_cache.thermal = temp >= 85 ? ThermalState::HOT : temp >= 70 ? ThermalState::WARM : ThermalState::NORMAL;
                        nv_have = true;
                    }
                }
                pclose(nv);
            }
        }
        if (nv_have) s.gpu = nv_cache;
    }
#endif
    if (const char* path = std::getenv("BTX_GOV_SIGNALS_FILE"); path && path[0]) {
        std::ifstream f(path);
        std::stringstream buf;
        buf << f.rdbuf();
        UniValue j;
        if (j.read(buf.str()) && j.isObject()) {
            if (j.exists("on_ac") && j["on_ac"].isBool()) s.on_ac = j["on_ac"].get_bool();
            if (j.exists("battery_percent")) s.battery_percent = ClampInt(j["battery_percent"].getInt<int>(), 0, 100);
            if (j.exists("gpu_type") && j["gpu_type"].isStr()) s.gpu.type = j["gpu_type"].get_str();
            if (j.exists("gpu_utilization_pct")) s.gpu.utilization_pct = ClampInt(j["gpu_utilization_pct"].getInt<int>(), 0, 100);
            if (j.exists("gpu_temperature_c")) s.gpu.temperature_c = j["gpu_temperature_c"].getInt<int>();
            if (j.exists("latency_baseline_ms")) s.latency_baseline_ms = j["latency_baseline_ms"].getInt<int>();
            if (j.exists("latency_current_ms")) s.latency_current_ms = j["latency_current_ms"].getInt<int>();
            if (j.exists("validation_active") && j["validation_active"].isBool()) s.validation_active = j["validation_active"].get_bool();
            if (j.exists("foreground_ai") && j["foreground_ai"].isBool()) s.foreground_ai = j["foreground_ai"].get_bool();
        }
    }
    return s;
}

} // namespace node
