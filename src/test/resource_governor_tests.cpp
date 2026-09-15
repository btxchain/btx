// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/resource_governor.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(resource_governor_tests, BasicTestingSetup)

using node::BackgroundPermit;
using node::GovernorJob;
using node::GovernorMode;
using node::GovernorPolicy;
using node::GovernorTouchesConsensus;
using node::GovernorAuthorizesSpend;
using node::ParseGovernorMode;
using node::PauseReason;
using node::PauseReasonName;
using node::PressureState;
using node::ResourceGovernor;
using node::SampleHostSignals;
using node::SystemSignals;
using node::ThermalState;

namespace {

SystemSignals QuietDesktop()
{
    SystemSignals s;
    s.cpu_load_pct = 8;
    s.cpu_pressure = PressureState::OK;
    s.memory_available_bytes = 16LL * 1024 * 1024 * 1024;
    s.memory_pressure = PressureState::OK;
    s.gpu.id = "gpu0";
    s.gpu.type = "NVIDIA";
    s.gpu.utilization_pct = 4;
    s.gpu.memory_used = 256 * 1024 * 1024;
    s.gpu.memory_total = 24LL * 1024 * 1024 * 1024;
    s.gpu.temperature_c = 42;
    s.gpu.thermal = ThermalState::NORMAL;
    s.ingress_bps = 100 * 1024;
    s.egress_bps = 50 * 1024;
    s.latency_baseline_ms = 20;
    s.latency_current_ms = 21;
    s.on_ac = true;
    s.metered = false;
    s.storage_free_pct = 40;
    s.disk_pressure = PressureState::OK;
    return s;
}

void IdleFor(ResourceGovernor& g, SystemSignals s, int64_t start_ms, int seconds)
{
    s.gpu.utilization_pct = 4;
    g.Observe(s, start_ms);
    g.Observe(s, start_ms + int64_t(seconds) * 1000);
}

} // namespace

BOOST_AUTO_TEST_CASE(gov_consensus_and_spend_never)
{
    BOOST_CHECK(!GovernorTouchesConsensus());
    BOOST_CHECK(!GovernorAuthorizesSpend());
    BOOST_CHECK_EQUAL(ResourceGovernor{}.InfoJson()["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!ResourceGovernor{}.InfoJson()["touches_consensus"].get_bool());
}

BOOST_AUTO_TEST_CASE(gov_pol_01_idle_gpu_permits_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MINING).reason, PauseReason::NONE);
}

BOOST_AUTO_TEST_CASE(gov_pol_02_foreground_gpu_blocks_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    s.gpu.utilization_pct = 70;
    g.Observe(s, 31000);
    BOOST_CHECK(g.MiningAllowed()); // 1s spike
    g.Observe(s, 35000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::FOREGROUND_GPU_LOAD);
}

BOOST_AUTO_TEST_CASE(gov_pol_03_validation_blocks_immediately)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    g.BeginValidationWork();
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::VALIDATION_PRIORITY);
    g.EndValidationWork();
    g.Observe(QuietDesktop(), 35000); // still in cooldown
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_pol_04_thermal_hot_blocks_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.thermal = ThermalState::HOT;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::THERMAL_PRESSURE);
}

BOOST_AUTO_TEST_CASE(gov_pol_05_battery_blocks_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    s.on_ac = false;
    s.battery_percent = 40;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::BATTERY_POLICY);
}

BOOST_AUTO_TEST_CASE(gov_pol_06_network_busy_throttles_seeding)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    s.egress_bps = quiet; // > 65% of ceiling
    g.Observe(s, 6000);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), quiet);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::NETWORK_BUSY);
}

BOOST_AUTO_TEST_CASE(gov_pol_07_foreground_download_outranks_seeding)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int64_t before = g.BackgroundUploadLimitBps();
    g.SetUserRetrievalActive(true);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), before);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::USER_TRANSFER_PRIORITY);
}

BOOST_AUTO_TEST_CASE(gov_pol_08_preservation_lowest_network_priority)
{
    ResourceGovernor g;
    g.SetUserRetrievalActive(true);
    g.Observe(QuietDesktop(), 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK(g.Permit(GovernorJob::MODEL_SEED).allowed);
}

BOOST_AUTO_TEST_CASE(gov_pol_09_fixed_operator_limits_override_auto)
{
    ResourceGovernor g;
    GovernorPolicy p;
    p.upload_auto = false;
    p.upload_max_bps = 12345;
    g.SetPolicy(p);
    g.Observe(QuietDesktop(), 0);
    BOOST_CHECK_EQUAL(g.BackgroundUploadLimitBps(), 12345);
}

BOOST_AUTO_TEST_CASE(gov_pol_10_off_prevents_optional_background)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    g.SetMode(GovernorMode::OFF);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK(!g.Permit(GovernorJob::MODEL_SEED).allowed);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
}

BOOST_AUTO_TEST_CASE(gov_hys_01_short_spike_does_not_flap)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    s.gpu.utilization_pct = 90;
    g.Observe(s, 30500);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_hys_02_sustained_pressure_pauses)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.utilization_pct = 90;
    g.Observe(s, 31000);
    BOOST_CHECK(g.MiningAllowed());
    g.Observe(s, 34000);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_hys_03_brief_idle_does_not_resume)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.utilization_pct = 4;
    g.Observe(s, 0);
    g.Observe(s, 5000);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_hys_04_sustained_idle_resumes)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_hys_05_cooldown_enforced)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.utilization_pct = 80;
    g.Observe(s, 31000);
    g.Observe(s, 34000);
    BOOST_CHECK(!g.MiningAllowed());
    s.gpu.utilization_pct = 3;
    g.Observe(s, 34000 + 5000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::GOVERNOR_COOLDOWN);
    g.Observe(s, 34000 + 10000 + 30000);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_hys_06_rapid_alternating_samples_stable)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    const uint64_t seq0 = g.StatusSequence();
    for (int i = 0; i < 20; ++i) {
        s.gpu.utilization_pct = (i % 2) ? 22 : 18; // between 10 and 35
        g.Observe(s, 30000 + i * 200);
    }
    BOOST_CHECK(g.MiningAllowed());
    BOOST_CHECK_LE(g.StatusSequence() - seq0, 4);
}

BOOST_AUTO_TEST_CASE(gov_mine_01_starts_after_idle_threshold)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    BOOST_CHECK(!g.MiningAllowed());
    g.Observe(s, 29999);
    BOOST_CHECK(!g.MiningAllowed());
    g.Observe(s, 30000);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_mine_02_ramps_intensity)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    g.Observe(s, 30000);
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 25);
    g.Observe(s, 60000);
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 50);
    g.Observe(s, 90000);
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 75);
    g.Observe(s, 120000);
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 100);
}

BOOST_AUTO_TEST_CASE(gov_mine_03_foreground_ai_pauses)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    g.BeginForegroundAiWork();
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::FOREGROUND_GPU_LOAD);
    g.EndForegroundAiWork();
}

BOOST_AUTO_TEST_CASE(gov_mine_04_validation_signal_pauses)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    SystemSignals s = QuietDesktop();
    s.validation_active = true;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::VALIDATION_PRIORITY);
}

BOOST_AUTO_TEST_CASE(gov_mine_05_cancel_does_not_leave_active)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    g.BeginForegroundAiWork();
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 0);
}

BOOST_AUTO_TEST_CASE(gov_mine_06_intensity_zero_on_stop)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK_GT(g.MiningIntensity(), 0);
    g.SetMode(GovernorMode::OFF);
    BOOST_CHECK_EQUAL(g.MiningIntensity(), 0);
}

BOOST_AUTO_TEST_CASE(gov_mine_07_resumes_cleanly)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    g.BeginForegroundAiWork();
    g.EndForegroundAiWork();
    s.gpu.utilization_pct = 3;
    g.Observe(s, 80000);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_mine_08_policy_has_no_stale_submit_flag)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    g.BeginValidationWork();
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK(g.MiningInfoJson()["active"].isBool());
}

BOOST_AUTO_TEST_CASE(gov_mine_09_reserved_validator_never_mined)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.reserved_for_validation = true;
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_net_01_idle_link_increases_allowance)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    s.egress_bps = 1024;
    g.Observe(s, 0);
    const int64_t a = g.BackgroundUploadLimitBps();
    BOOST_CHECK_GT(a, 1024);
}

BOOST_AUTO_TEST_CASE(gov_net_02_busy_link_reduces_allowance)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    s.egress_bps = quiet;
    g.Observe(s, 8000);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), quiet);
}

BOOST_AUTO_TEST_CASE(gov_net_03_latency_inflation_reduces_upload)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    s.latency_current_ms = 200;
    g.Observe(s, 1000);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), quiet);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::LATENCY_PRESSURE);
}

BOOST_AUTO_TEST_CASE(gov_net_04_explicit_cap_always_respected)
{
    ResourceGovernor g;
    GovernorPolicy p;
    p.upload_max_bps = 4096;
    g.SetPolicy(p);
    g.Observe(QuietDesktop(), 0);
    BOOST_CHECK_LE(g.BackgroundUploadLimitBps(), 4096);
}

BOOST_AUTO_TEST_CASE(gov_net_05_foreground_retrieval_retains_bandwidth)
{
    ResourceGovernor g;
    g.SetUserRetrievalActive(true);
    g.Observe(QuietDesktop(), 0);
    BOOST_CHECK(g.BandwidthJson()["foreground_download"].get_bool());
    BOOST_CHECK_GT(g.BackgroundUploadLimitBps(), 0); // control/ack traffic remains
}

BOOST_AUTO_TEST_CASE(gov_net_06_seeding_resumes_after_pressure)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    s.latency_current_ms = 400;
    g.Observe(s, 0);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::LATENCY_PRESSURE);
    s.latency_current_ms = 20;
    s.egress_bps = 1024;
    g.Observe(s, 40000);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::NONE);
}

BOOST_AUTO_TEST_CASE(gov_net_07_preservation_throttled_before_seeding)
{
    ResourceGovernor g;
    g.SetUserRetrievalActive(true);
    g.Observe(QuietDesktop(), 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK(g.Permit(GovernorJob::MODEL_SEED).max_bandwidth_bps > 0);
}

BOOST_AUTO_TEST_CASE(gov_net_08_no_thread_explosion_in_permit)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int c0 = g.Permit(GovernorJob::MODEL_SEED).max_concurrency;
    s.egress_bps = 1024;
    g.Observe(s, 40000);
    BOOST_CHECK_LE(g.Permit(GovernorJob::MODEL_SEED).max_concurrency, c0);
    BOOST_CHECK_LE(g.Permit(GovernorJob::MODEL_SEED).max_concurrency, 8);
}

BOOST_AUTO_TEST_CASE(gov_pwr_01_desktop_ac_permits)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_pwr_02_laptop_battery_pauses_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.on_ac = false;
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_pwr_03_ac_restore_permits_later_resume)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.on_ac = false;
    IdleFor(g, s, 0, 30);
    s.on_ac = true;
    g.Observe(s, 80000);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_pwr_04_hot_reduces_background)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.thermal = ThermalState::HOT;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_pwr_05_critical_stops_optional)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.thermal = ThermalState::CRITICAL;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.Permit(GovernorJob::MINING).allowed);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
}

BOOST_AUTO_TEST_CASE(gov_pwr_06_thermal_recovery_obeys_cooldown)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.gpu.thermal = ThermalState::HOT;
    g.Observe(s, 31000);
    s.gpu.thermal = ThermalState::NORMAL;
    g.Observe(s, 35000);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_mem_01_memory_pressure_reduces_concurrency)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int c0 = g.Permit(GovernorJob::MODEL_SEED).max_concurrency;
    s.memory_pressure = PressureState::HIGH;
    g.Observe(s, 1000);
    BOOST_CHECK_LT(g.Permit(GovernorJob::MODEL_SEED).max_concurrency, c0);
}

BOOST_AUTO_TEST_CASE(gov_mem_02_swap_pressure_pauses_heavy)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    IdleFor(g, s, 0, 30);
    s.swap_pressure = true;
    g.Observe(s, 31000);
    BOOST_CHECK(!g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_disk_01_high_io_reduces_preservation)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    s.disk_pressure = PressureState::HIGH;
    g.Observe(s, 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
}

BOOST_AUTO_TEST_CASE(gov_disk_02_emergency_storage_allows_gc)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    s.storage_free_pct = 3;
    s.disk_pressure = PressureState::CRITICAL;
    g.Observe(s, 0);
    BOOST_CHECK(g.Permit(GovernorJob::CACHE_GC).allowed);
}

BOOST_AUTO_TEST_CASE(gov_disk_03_governor_does_not_evict_pins)
{
    ResourceGovernor g;
    g.Observe(QuietDesktop(), 0);
    const std::string jobs = g.JobsJson().write();
    BOOST_CHECK(jobs.find("evict_pin") == std::string::npos);
    BOOST_CHECK(jobs.find("unpin") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(gov_disk_04_gc_bounded_vs_foreground)
{
    ResourceGovernor g;
    g.SetUserRetrievalActive(true);
    SystemSignals s = QuietDesktop();
    s.storage_free_pct = 40;
    g.Observe(s, 0);
    BOOST_CHECK_LE(g.Permit(GovernorJob::CACHE_GC).max_concurrency, 1);
}

BOOST_AUTO_TEST_CASE(gov_fail_01_unavailable_pauses_mining)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    g.SetUnavailable(true);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::GOVERNOR_UNAVAILABLE);
}

BOOST_AUTO_TEST_CASE(gov_fail_02_unavailable_does_not_touch_consensus)
{
    ResourceGovernor g;
    g.SetUnavailable(true);
    BOOST_CHECK(!GovernorTouchesConsensus());
}

BOOST_AUTO_TEST_CASE(gov_fail_03_modeld_independence_documented)
{
    BOOST_CHECK(!GovernorTouchesConsensus());
}

BOOST_AUTO_TEST_CASE(gov_fail_04_unknown_gpu_conservative_intensity)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.utilization_pct = -1;
    s.gpu.type = "UNKNOWN";
    g.Observe(s, 30000);
    BOOST_CHECK(g.MiningAllowed());
    BOOST_CHECK_LE(g.MiningIntensity(), 25);
}

BOOST_AUTO_TEST_CASE(gov_fail_05_malformed_policy_rejected)
{
    ResourceGovernor g;
    UniValue o(UniValue::VOBJ);
    o.pushKV("idle_gpu_threshold", 200);
    std::string err;
    BOOST_CHECK(!g.ApplyPolicyJson(o, err));
    BOOST_CHECK(!err.empty());
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("pause_gpu_threshold", 5);
    bad.pushKV("idle_gpu_threshold", 10);
    BOOST_CHECK(!g.ApplyPolicyJson(bad, err));
}

BOOST_AUTO_TEST_CASE(gov_mode_parse_and_rpc_shape)
{
    GovernorMode m;
    BOOST_CHECK(ParseGovernorMode("auto", m) && m == GovernorMode::AUTO);
    BOOST_CHECK(ParseGovernorMode("ECO", m) && m == GovernorMode::ECO);
    BOOST_CHECK(!ParseGovernorMode("warp", m));
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_CHECK(g.InfoJson().exists("gpu"));
    BOOST_CHECK(g.PolicyJson().exists("idle_gpu_threshold"));
    BOOST_CHECK(g.JobsJson().isArray());
    BOOST_CHECK_EQUAL(g.JobsJson().size(), 6);
}

BOOST_AUTO_TEST_CASE(gov_metered_pauses_preservation)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    s.metered = true;
    g.Observe(s, 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::PRESERVATION).reason, PauseReason::METERED_NETWORK);
}

BOOST_AUTO_TEST_CASE(gov_e2e_overnight_12h)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.type = "NVIDIA";
    int64_t t = 0;
    g.Observe(s, t);
    g.Observe(s, t + 30 * 1000);
    BOOST_REQUIRE(g.MiningAllowed());
    // Compressed 12h overnight: one sample per minute, GPU idle, AC.
    for (int i = 0; i < 720; ++i) {
        t += 60 * 1000;
        s.gpu.utilization_pct = 3 + (i % 3);
        g.Observe(s, t);
        BOOST_CHECK(g.MiningAllowed());
        BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MINING).reason, PauseReason::NONE);
        BOOST_CHECK(g.Permit(GovernorJob::MODEL_SEED).allowed);
    }
}

BOOST_AUTO_TEST_CASE(gov_e2e_active_day)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.type = "NVIDIA";
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());

    // Morning: foreground inference yields mining immediately after pause window.
    s.gpu.utilization_pct = 80;
    s.foreground_ai = true;
    g.BeginForegroundAiWork();
    g.Observe(s, 35'000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::FOREGROUND_GPU_LOAD);
    g.EndForegroundAiWork();
    s.foreground_ai = false;
    s.gpu.utilization_pct = 4;

    // Midday: ExactReplay/validation outranks mining in the same tick.
    const auto t0 = std::chrono::steady_clock::now();
    s.validation_active = true;
    g.BeginValidationWork();
    g.Observe(s, 80'000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::VALIDATION_PRIORITY);
    const auto val_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK_LT(val_us, 50'000);
    g.EndValidationWork();
    s.validation_active = false;

    // Afternoon: user retrieve keeps seed up but preservation down.
    g.SetUserRetrievalActive(true);
    g.Observe(s, 120'000);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    g.SetUserRetrievalActive(false);

    // Evening idle: resume after cooldown + 30s idle.
    s.gpu.utilization_pct = 3;
    g.Observe(s, 180'000);
    g.Observe(s, 220'000);
    BOOST_CHECK(g.MiningAllowed());
}

BOOST_AUTO_TEST_CASE(gov_e2e_val_lat)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, QuietDesktop(), 0, 30);
    BOOST_REQUIRE(g.MiningAllowed());
    const auto t0 = std::chrono::steady_clock::now();
    g.BeginValidationWork();
    const auto permit = g.Permit(GovernorJob::MINING);
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK(!permit.allowed);
    BOOST_CHECK_EQUAL(permit.reason, PauseReason::VALIDATION_PRIORITY);
    BOOST_CHECK_LT(us, 20'000);
}

BOOST_AUTO_TEST_CASE(gov_e2e_nvidia_workstation)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.type = "NVIDIA";
    s.gpu.id = "gpu0";
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());

    s.gpu.utilization_pct = 88; // inference
    g.Observe(s, 31'000);
    g.Observe(s, 35'000);
    BOOST_CHECK(!g.MiningAllowed());

    s.gpu.utilization_pct = 4;
    g.Observe(s, 80'000);
    g.Observe(s, 110'000);
    BOOST_CHECK(g.MiningAllowed());

    s.validation_active = true;
    g.BeginValidationWork();
    BOOST_CHECK(!g.MiningAllowed());
    g.EndValidationWork();
    s.validation_active = false;

    s.gpu.thermal = ThermalState::HOT;
    s.gpu.temperature_c = 92;
    g.Observe(s, 120'000);
    BOOST_CHECK(!g.MiningAllowed());

    s.gpu.thermal = ThermalState::NORMAL;
    s.gpu.temperature_c = 42;
    g.Observe(s, 200'000);
    g.Observe(s, 230'000);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    s.latency_current_ms = 250;
    g.Observe(s, 231'000);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), quiet);
}

BOOST_AUTO_TEST_CASE(gov_e2e_apple_metal)
{
    ResourceGovernor g;
    g.SetMiningConsent(true);
    SystemSignals s = QuietDesktop();
    s.gpu.type = "METAL";
    s.gpu.id = "ane0";
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(g.MiningAllowed());
    s.gpu.thermal = ThermalState::HOT;
    s.gpu.temperature_c = 95;
    g.Observe(s, 40'000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::THERMAL_PRESSURE);
    s.gpu.thermal = ThermalState::NORMAL;
    s.gpu.temperature_c = 48;
    g.Observe(s, 90'000);
    g.Observe(s, 120'000);
    BOOST_CHECK(g.MiningAllowed());
    s.on_ac = false;
    s.battery_percent = 35;
    g.Observe(s, 121'000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::BATTERY_POLICY);
}

BOOST_AUTO_TEST_CASE(gov_e2e_bufferbloat_shaped)
{
    ResourceGovernor g;
    SystemSignals s = QuietDesktop();
    g.Observe(s, 0);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    s.latency_baseline_ms = 20;
    s.latency_current_ms = 180; // shaped uplink / bufferbloat
    g.Observe(s, 1000);
    BOOST_CHECK_LT(g.BackgroundUploadLimitBps(), quiet);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::LATENCY_PRESSURE);
    s.latency_current_ms = 22;
    s.egress_bps = 1024;
    g.Observe(s, 40'000);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::MODEL_SEED).reason, PauseReason::NONE);
}

BOOST_AUTO_TEST_CASE(gov_e2e_battery_sysfs)
{
#ifdef __linux__
    const fs::path dir = m_path_root / "power_supply";
    fs::create_directories(dir / "AC");
    fs::create_directories(dir / "BAT0");
    {
        std::ofstream f{dir / "AC" / "online"};
        f << "0\n";
    }
    {
        std::ofstream f{dir / "BAT0" / "capacity"};
        f << "41\n";
    }
    BOOST_REQUIRE_EQUAL(::setenv("BTX_POWER_SUPPLY_DIR", fs::PathToString(dir).c_str(), 1), 0);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_GOV_NVIDIA_SAMPLE", "0", 1), 0);
    const SystemSignals s = SampleHostSignals();
    BOOST_CHECK(!s.on_ac);
    BOOST_CHECK_EQUAL(s.battery_percent, 41);
    ResourceGovernor g;
    g.SetMiningConsent(true);
    IdleFor(g, s, 0, 30);
    BOOST_CHECK(!g.MiningAllowed());
    ::unsetenv("BTX_POWER_SUPPLY_DIR");
    ::unsetenv("BTX_GOV_NVIDIA_SAMPLE");
#else
    BOOST_TEST_MESSAGE("gov_e2e_battery_sysfs: not linux");
#endif
}

BOOST_AUTO_TEST_SUITE_END()
