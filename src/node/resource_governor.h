// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_RESOURCE_GOVERNOR_H
#define BITCOIN_NODE_RESOURCE_GOVERNOR_H

#include <sync.h>
#include <univalue.h>

#include <cstdint>
#include <string>

namespace node {

/** Local resource policy only. Never consensus, never automatic spend. */
enum class GovernorMode { AUTO = 0, PERFORMANCE, BALANCED, ECO, MANUAL, OFF };

enum class PauseReason {
    NONE = 0,
    FOREGROUND_GPU_LOAD,
    VALIDATION_PRIORITY,
    THERMAL_PRESSURE,
    BATTERY_POLICY,
    USER_DISABLED,
    GOVERNOR_COOLDOWN,
    GPU_MEMORY_PRESSURE,
    NETWORK_BUSY,
    LATENCY_PRESSURE,
    DISK_PRESSURE,
    STORAGE_FULL,
    USER_TRANSFER_PRIORITY,
    POWER_POLICY,
    METERED_NETWORK,
    GOVERNOR_UNAVAILABLE,
};

enum class GovernorJob {
    MINING = 0,
    MODEL_SEED,
    PRESERVATION,
    QUALIFICATION,
    CACHE_GC,
    SEARCH_MAINTENANCE,
};

enum class ThermalState { UNKNOWN = 0, NORMAL, WARM, HOT, CRITICAL };
enum class PressureState { UNKNOWN = 0, OK, ELEVATED, HIGH, CRITICAL };
enum class DimIdle { ACTIVE = 0, BECOMING_IDLE, IDLE, BECOMING_ACTIVE };

struct AcceleratorSample {
    std::string id{"gpu0"};
    std::string type{"UNKNOWN"};
    int utilization_pct{-1}; // -1 = UNKNOWN
    int64_t memory_used{-1};
    int64_t memory_total{-1};
    int temperature_c{-1};
    ThermalState thermal{ThermalState::UNKNOWN};
    bool reserved_for_validation{false};
    bool excluded{false};
};

struct SystemSignals {
    int cpu_load_pct{-1};
    PressureState cpu_pressure{PressureState::UNKNOWN};
    int64_t memory_available_bytes{-1};
    PressureState memory_pressure{PressureState::UNKNOWN};
    bool swap_pressure{false};
    AcceleratorSample gpu;
    int64_t ingress_bps{0};
    int64_t egress_bps{0};
    int latency_baseline_ms{-1};
    int latency_current_ms{-1};
    int64_t model_io_bps{0};
    PressureState disk_pressure{PressureState::UNKNOWN};
    bool on_ac{true};
    int battery_percent{-1};
    bool metered{false};
    int64_t user_idle_ms{-1};
    bool validation_active{false};
    bool foreground_ai{false};
    bool user_retrieval_active{false};
    int storage_free_pct{100};
};

struct GovernorPolicy {
    int idle_gpu_threshold{10};
    int pause_gpu_threshold{35};
    int idle_resume_seconds{30};
    int pause_seconds{3};
    int cooldown_seconds{10};
    int mining_max_intensity{100};
    bool upload_auto{true};
    int64_t upload_max_bps{0}; // 0 = no extra cap (connection ceilings still apply)
    bool latency_backoff_enabled{true};
    bool battery_background_allowed{false};
    bool preserve_on_battery{false};
    bool background_on_metered{false};
    int64_t background_upload_floor_bps{256 * 1024};
    int64_t background_upload_auto_bps{20 * 1024 * 1024};
};

struct BackgroundPermit {
    bool allowed{false};
    int max_intensity{0};
    int64_t max_bandwidth_bps{0};
    int max_concurrency{1};
    PauseReason reason{PauseReason::GOVERNOR_UNAVAILABLE};
    uint64_t generation{0};
};

struct GovernorMetrics {
    int64_t mining_allowed_seconds{0};
    int64_t mining_active_seconds{0};
    int64_t mining_paused_foreground_seconds{0};
    int64_t mining_paused_validation_seconds{0};
    int64_t mining_paused_thermal_seconds{0};
    int64_t model_seed_throttled_seconds{0};
    int64_t preservation_paused_seconds{0};
    int64_t transitions{0};
};

class ResourceGovernor
{
    // RPC threads, the scheduler tick, validation and the miner all use the
    // global governor. Recursive: the JSON reports call MiningAllowed()/Permit().
    mutable RecursiveMutex m_mutex;
    GovernorMode m_mode GUARDED_BY(m_mutex){GovernorMode::AUTO};
    GovernorPolicy m_policy GUARDED_BY(m_mutex);
    SystemSignals m_sig GUARDED_BY(m_mutex);
    bool m_mining_consent GUARDED_BY(m_mutex){false}; // product: do not enable mining without consent
    bool m_auto_schedule GUARDED_BY(m_mutex){true};   // idle hysteresis when true
    bool m_unavailable GUARDED_BY(m_mutex){false};   // fail-closed optional work
    bool m_user_pause GUARDED_BY(m_mutex){false};
    int64_t m_user_pause_until_ms GUARDED_BY(m_mutex){0};
    bool m_foreground_ai GUARDED_BY(m_mutex){false};
    bool m_validation GUARDED_BY(m_mutex){false};
    bool m_user_retrieval GUARDED_BY(m_mutex){false};
    bool m_mining_active GUARDED_BY(m_mutex){false};
    int m_intensity GUARDED_BY(m_mutex){0};
    PauseReason m_mining_reason GUARDED_BY(m_mutex){PauseReason::NONE};
    PauseReason m_seed_reason GUARDED_BY(m_mutex){PauseReason::NONE};
    PauseReason m_preserve_reason GUARDED_BY(m_mutex){PauseReason::NONE};
    int64_t m_low_util_since_ms GUARDED_BY(m_mutex){-1};
    int64_t m_high_util_since_ms GUARDED_BY(m_mutex){-1};
    int64_t m_last_pause_ms GUARDED_BY(m_mutex){-1};
    int64_t m_last_resume_ms GUARDED_BY(m_mutex){-1};
    int64_t m_last_tick_ms GUARDED_BY(m_mutex){0};
    uint64_t m_generation GUARDED_BY(m_mutex){1};
    uint64_t m_status_seq GUARDED_BY(m_mutex){0};
    bool m_have_sample GUARDED_BY(m_mutex){false};
    GovernorMetrics m_metrics GUARDED_BY(m_mutex);
    int64_t m_effective_upload_bps GUARDED_BY(m_mutex){0};
    DimIdle m_gpu_idle GUARDED_BY(m_mutex){DimIdle::ACTIVE};

    void MaybeTransition(int64_t now_ms) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    void SetMode(GovernorMode m);
    GovernorMode Mode() const { LOCK(m_mutex); return m_mode; }
    void SetPolicy(const GovernorPolicy& p);
    GovernorPolicy Policy() const { LOCK(m_mutex); return m_policy; }
    void ResetPolicy();
    void SetMiningConsent(bool on);
    bool MiningConsent() const { LOCK(m_mutex); return m_mining_consent; }
    void SetAutoSchedule(bool on) { LOCK(m_mutex); m_auto_schedule = on; }
    bool AutoSchedule() const { LOCK(m_mutex); return m_auto_schedule; }
    void SetUnavailable(bool on);

    void BeginForegroundAiWork();
    void EndForegroundAiWork();
    void BeginValidationWork();
    void EndValidationWork();
    void SetUserRetrievalActive(bool on);

    void PauseBackground(int64_t now_ms, int64_t duration_ms);
    void ResumeBackground();

    void Observe(const SystemSignals& s, int64_t now_ms);
    BackgroundPermit Permit(GovernorJob job) const;

    bool MiningAllowed() const;
    int MiningIntensity() const { LOCK(m_mutex); return m_intensity; }
    PauseReason MiningPauseReason() const { LOCK(m_mutex); return m_mining_reason; }
    int64_t BackgroundUploadLimitBps() const { LOCK(m_mutex); return m_effective_upload_bps; }
    uint64_t StatusSequence() const { LOCK(m_mutex); return m_status_seq; }
    GovernorMetrics Metrics() const { LOCK(m_mutex); return m_metrics; }

    UniValue InfoJson() const;
    UniValue PolicyJson() const;
    UniValue JobsJson() const;
    UniValue MiningInfoJson() const;
    UniValue BandwidthJson() const;
    bool ApplyPolicyJson(const UniValue& o, std::string& err);
    /** Helper-facing permit. Missing file on the helper side is conservative static limits. */
    bool WritePermitFile(const std::string& path) const;
};

const char* GovernorModeName(GovernorMode m);
bool ParseGovernorMode(const std::string& s, GovernorMode& out);
const char* PauseReasonName(PauseReason r);
const char* ThermalStateName(ThermalState t);
const char* PressureStateName(PressureState p);

bool GovernorTouchesConsensus();
bool GovernorAuthorizesSpend();

/** Process-wide governor used by mining (pow.cpp) and RPCs. Fail-closed if unset. */
ResourceGovernor& GlobalResourceGovernor();
void ResetGlobalResourceGovernorForTest();

/** Linux best-effort sample. Unknown metrics stay -1 / UNKNOWN. Never throws. */
SystemSignals SampleHostSignals();

} // namespace node

#endif // BITCOIN_NODE_RESOURCE_GOVERNOR_H
