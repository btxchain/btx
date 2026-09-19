// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// INFRA-01..12: operator profiles, -modelhost=auto, advertisement conditions.
// No production sockets.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <modelnet/piece_ranges.h>
#include <modelnet/profile.h>
#include <modelnet/reachability.h>
#include <modelnet/relay_reserve.h>
#include <modelnet/supervisor.h>
#include <node/resource_governor.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_infra_tests, BasicTestingSetup)

namespace {

void CheckOrdinaryProfileKeys(const UniValue& o)
{
    const std::set<std::string> allowed{
        "schema_version", "profile", "relay", "index", "host_mode",
        "storage_arg", "auto_cap_bytes", "upload_bps", "follow_peers",
        "preserve_rare", "seed",
    };
    BOOST_REQUIRE(o.isObject());
    const std::string dumped = o.write();
    BOOST_CHECK(dumped.find("wallet") == std::string::npos);
    BOOST_CHECK(dumped.find("consensus") == std::string::npos);
    BOOST_CHECK(dumped.find("bounty") == std::string::npos);
    BOOST_CHECK(dumped.find("automatic_spend") == std::string::npos);
    BOOST_CHECK(dumped.find("htlc") == std::string::npos);
    BOOST_CHECK(dumped.find("mandate") == std::string::npos);
    BOOST_CHECK(dumped.find("search_authority") == std::string::npos);
    for (const std::string& k : o.getKeys()) {
        BOOST_CHECK_MESSAGE(allowed.count(k) == 1, "unexpected profile key: " + k);
    }
}

bool ArgvHas(const std::vector<std::string>& argv, const std::string& needle)
{
    for (const auto& a : argv) {
        if (a == needle) return true;
    }
    return false;
}

node::SystemSignals QuietDesktop()
{
    node::SystemSignals s;
    s.cpu_load_pct = 8;
    s.cpu_pressure = node::PressureState::OK;
    s.memory_available_bytes = 16LL * 1024 * 1024 * 1024;
    s.memory_pressure = node::PressureState::OK;
    s.gpu.id = "gpu0";
    s.gpu.type = "NVIDIA";
    s.gpu.utilization_pct = 4;
    s.gpu.memory_used = 256 * 1024 * 1024;
    s.gpu.memory_total = 24LL * 1024 * 1024 * 1024;
    s.gpu.temperature_c = 42;
    s.gpu.thermal = node::ThermalState::NORMAL;
    s.ingress_bps = 100 * 1024;
    s.egress_bps = 50 * 1024;
    s.latency_baseline_ms = 20;
    s.latency_current_ms = 21;
    s.on_ac = true;
    s.metered = false;
    s.storage_free_pct = 40;
    s.disk_pressure = node::PressureState::OK;
    return s;
}

} // namespace

BOOST_AUTO_TEST_CASE(infra_01_relay_only_valid)
{
    using namespace modelnet;
    ProfileOverrides ov;
    ov.relay = true;
    ov.index = false;
    ov.host_mode = HostMode::OFF;
    const ProfilePolicy p = ResolveProfile(OperatorProfile::CUSTOM, ov);
    BOOST_CHECK(p.relay);
    BOOST_CHECK(!p.index);
    BOOST_CHECK(p.host_mode == HostMode::OFF);
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 64 * MIB, true, false));

    RelayTable table;
    RelayReservation rsvp;
    std::string err;
    BOOST_REQUIRE(table.Reserve("svc", "ng-a", "203.0.113.8:29447", 1000, rsvp, err));
    BOOST_REQUIRE(table.AllowForward(rsvp.reservation_id, 4096, 1100, err));
    BOOST_CHECK_EQUAL(table.ForwardedBytes(), 4096);
    // Relay forwarding is a byte counter, not a payload cache.
    BOOST_CHECK(table.Has(rsvp.reservation_id));
}

BOOST_AUTO_TEST_CASE(infra_02_infrastructure_roles_independent)
{
    using namespace modelnet;
    const ProfilePolicy p = ResolveProfile(OperatorProfile::INFRASTRUCTURE, {});
    BOOST_CHECK(p.relay);
    BOOST_CHECK(p.index);
    BOOST_CHECK(p.host_mode == HostMode::AUTO);
    BOOST_CHECK(p.follow_peers);
    BOOST_CHECK(p.preserve_rare);
    BOOST_CHECK_EQUAL(p.seed, "auto");
    BOOST_CHECK_EQUAL(p.auto_cap_bytes, INFRASTRUCTURE_AUTO_CAP_BYTES);
    BOOST_CHECK_GT(p.upload_bps, PERSONAL_UPLOAD_BPS);

    HelperLaunchConfig cfg;
    cfg.helper_exe = fs::PathFromString("/usr/bin/btx-modeld");
    ApplyProfileToLaunchConfig(p, cfg);
    const auto argv = BuildHelperArgv(cfg);
    BOOST_CHECK(ArgvHas(argv, "-modelrelay"));
    BOOST_CHECK(ArgvHas(argv, "-modelhost=auto"));
    BOOST_CHECK(!ArgvContainsWalletMaterial(argv));
    // Index is an independent policy bit, not a helper argv flag (unknown arg).
    for (const auto& a : argv) {
        BOOST_CHECK(a.find("-modelindex") == std::string::npos);
        BOOST_CHECK(a.find("wallet") == std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(infra_03_relay_does_not_imply_host)
{
    using namespace modelnet;
    const ProfilePolicy p = ResolveProfile(OperatorProfile::INFRASTRUCTURE, {});
    BOOST_CHECK(p.relay);
    BOOST_CHECK(p.host_mode == HostMode::AUTO);
    // Relay + index + host-auto are independent: auto still refuses without reachability.
    BOOST_CHECK(!MayAdvertiseHostAuto(true, true, INFRASTRUCTURE_AUTO_CAP_BYTES, true, false));

    HelperLaunchConfig cfg;
    cfg.relay = true;
    cfg.host_mode = HostMode::OFF;
    const auto argv = BuildHelperArgv(cfg);
    BOOST_CHECK(ArgvHas(argv, "-modelrelay"));
    BOOST_CHECK(!ArgvHas(argv, "-modelhost=auto"));
    BOOST_CHECK(!ArgvHas(argv, "-modelhost=1"));
}

BOOST_AUTO_TEST_CASE(infra_04_auto_refuses_before_reachability)
{
    using namespace modelnet;
    ReachabilityTracker t;
    t.NoteRelayHealthy(true, 1000);
    BOOST_CHECK_EQUAL(static_cast<int>(t.State()), static_cast<int>(ReachabilityState::RELAY_REACHABLE));
    BOOST_CHECK(!t.MayAdvertiseHost(true));
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 32 * GIB, true, t.MayAdvertiseHost(true)));
    BOOST_CHECK(!MayAdvertiseHostAuto(true, true, 32 * GIB, true, false));

    HostMode mode = HostMode::OFF;
    BOOST_REQUIRE(ParseHostMode("auto", mode));
    BOOST_CHECK(mode == HostMode::AUTO);
    BOOST_CHECK(HostModeWantsHosting(mode));
}

BOOST_AUTO_TEST_CASE(infra_05_advertise_after_reachability_and_seed)
{
    using namespace modelnet;
    BOOST_CHECK(AutoHostShouldAdvertise(true, true, 8 * MIB, true, true));
    BOOST_CHECK(MayAdvertiseHostAuto(true, true, 1, true, true));

    ReachabilityTracker direct;
    direct.SetListen("203.0.113.8:29447");
    DialbackReport a;
    a.request_id = "r1";
    a.observer_id = "o1";
    a.observer_netgroup = "n1";
    a.observed_endpoint = "203.0.113.8:29447";
    a.ok = true;
    a.at_ms = 10;
    DialbackReport b = a;
    b.request_id = "r2";
    b.observer_id = "o2";
    b.observer_netgroup = "n2";
    direct.NoteReport(a, 10);
    direct.NoteReport(b, 11);
    BOOST_CHECK(direct.State() == ReachabilityState::PUBLIC_DIRECT ||
                direct.State() == ReachabilityState::PUBLIC_MAPPED);
    BOOST_CHECK(direct.MayAdvertiseHost(true));
    BOOST_CHECK(AutoHostShouldAdvertise(true, true, 4 * MIB, true, direct.MayAdvertiseHost(true)));
}

BOOST_AUTO_TEST_CASE(infra_06_withdraw_after_helper_failure)
{
    using namespace modelnet;
    BOOST_CHECK(AutoHostShouldAdvertise(true, true, 16 * MIB, true, true));
    BOOST_CHECK(!AutoHostShouldAdvertise(true, false, 16 * MIB, true, true));

    HelperStatus st;
    UniValue info(UniValue::VOBJ);
    info.pushKV("advertised_host", true);
    info.pushKV("public_host_reachable", true);
    ApplyHelperNetworkInfo(st, info);
    BOOST_CHECK(st.advertised_host);
    BOOST_CHECK(st.public_host_reachable);

    SetNodeModelHostAdvertised(true);
    BOOST_CHECK(NodeModelHostAdvertisedWanted());
    SetNodeModelHostAdvertised(false);
    BOOST_CHECK(!NodeModelHostAdvertisedWanted());
    ApplyModelHostServiceBit(false);
    BOOST_CHECK(!NodeModelHostAdvertisedWanted());
}

BOOST_AUTO_TEST_CASE(infra_07_withdraw_after_store_failure)
{
    using namespace modelnet;
    BOOST_CHECK(AutoHostShouldAdvertise(true, true, 8 * MIB, true, true));
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 8 * MIB, false, true));

    HelperStatus st;
    UniValue info(UniValue::VOBJ);
    info.pushKV("advertised_host", true);
    info.pushKV("public_host_reachable", true);
    ApplyHelperNetworkInfo(st, info);
    BOOST_CHECK(st.advertised_host);
    info.pushKV("advertised_host", false);
    info.pushKV("public_host_reachable", false);
    ApplyHelperNetworkInfo(st, info);
    BOOST_CHECK(!st.advertised_host);
    BOOST_CHECK(!st.public_host_reachable);
}

BOOST_AUTO_TEST_CASE(infra_08_profile_resolve_no_extra_authority)
{
    using namespace modelnet;
    for (OperatorProfile prof : {OperatorProfile::PERSONAL, OperatorProfile::INFRASTRUCTURE,
                                   OperatorProfile::MIRROR, OperatorProfile::CUSTOM}) {
        const ProfilePolicy p = ResolveProfile(prof, {});
        const UniValue j = OperatorProfileToJson(prof, p);
        CheckOrdinaryProfileKeys(j);
        BOOST_CHECK_EQUAL(j["profile"].get_str(), OperatorProfileName(prof));
    }
    ProfileOverrides ov;
    ov.relay = true;
    ov.host_mode = HostMode::ON;
    ov.storage_arg = "80GiB";
    const ProfilePolicy custom = ResolveProfile(OperatorProfile::CUSTOM, ov);
    BOOST_CHECK(custom.relay);
    BOOST_CHECK(custom.host_mode == HostMode::ON);
    BOOST_CHECK_EQUAL(custom.storage_arg, "80GiB");
    CheckOrdinaryProfileKeys(OperatorProfileToJson(OperatorProfile::CUSTOM, custom));
}

BOOST_AUTO_TEST_CASE(infra_09_profile_ceilings_not_governor_bypass)
{
    using namespace modelnet;
    using node::GovernorJob;
    using node::GovernorMode;
    using node::GovernorPolicy;
    using node::PauseReason;
    using node::PressureState;
    using node::ResourceGovernor;
    using node::ThermalState;

    const auto personal = ResolveProfile(OperatorProfile::PERSONAL, {});
    const auto infra = ResolveProfile(OperatorProfile::INFRASTRUCTURE, {});
    const auto mirror = ResolveProfile(OperatorProfile::MIRROR, {});
    BOOST_CHECK_LT(personal.auto_cap_bytes, infra.auto_cap_bytes);
    BOOST_CHECK_LT(infra.auto_cap_bytes, mirror.auto_cap_bytes);
    BOOST_CHECK_LT(personal.upload_bps, infra.upload_bps);
    BOOST_CHECK_LT(infra.upload_bps, mirror.upload_bps);
    BOOST_CHECK(personal.host_mode == HostMode::AUTO);
    BOOST_CHECK(infra.host_mode == HostMode::AUTO);
    BOOST_CHECK(mirror.host_mode == HostMode::AUTO);
    BOOST_CHECK(mirror.preserve_rare);
    BOOST_CHECK(infra.preserve_rare);
    BOOST_CHECK(!personal.preserve_rare);
    // AutoHostShouldAdvertise has no profile/governor-bypass argument: ceilings
    // never skip thermal/battery/congestion/disk. MODEL_SEED still goes through
    // the resource governor.
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, personal.auto_cap_bytes, true, false));

    const UniValue mj = OperatorProfileToJson(OperatorProfile::MIRROR, mirror);
    CheckOrdinaryProfileKeys(mj);
    BOOST_CHECK(!mj.exists("bypass_governor"));
    BOOST_CHECK(!mj.exists("governor_mode"));
    BOOST_CHECK(!mj.exists("thermal"));
    BOOST_CHECK(!mj.exists("battery"));

    ResourceGovernor g;
    GovernorPolicy pol;
    pol.upload_auto = false;
    pol.upload_max_bps = static_cast<int64_t>(mirror.upload_bps);
    g.SetPolicy(pol);
    g.Observe(QuietDesktop(), 0);
    auto seed = g.Permit(GovernorJob::MODEL_SEED);
    BOOST_CHECK(seed.allowed);
    BOOST_CHECK_EQUAL(EffectiveHostUploadBps(mirror.upload_bps, seed.max_bandwidth_bps, seed.allowed),
                      static_cast<uint64_t>(seed.max_bandwidth_bps));

    node::SystemSignals metered = QuietDesktop();
    metered.metered = true;
    g.Observe(metered, 1000);
    seed = g.Permit(GovernorJob::MODEL_SEED);
    BOOST_CHECK(!seed.allowed);
    BOOST_CHECK_EQUAL(seed.reason, PauseReason::METERED_NETWORK);
    BOOST_CHECK_EQUAL(EffectiveHostUploadBps(mirror.upload_bps, seed.max_bandwidth_bps, seed.allowed), 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);

    node::SystemSignals battery = QuietDesktop();
    battery.on_ac = false;
    battery.battery_percent = 40;
    g.Observe(battery, 2000);
    seed = g.Permit(GovernorJob::MODEL_SEED);
    BOOST_CHECK_LE(seed.max_bandwidth_bps, pol.background_upload_floor_bps);
    BOOST_CHECK_LT(static_cast<uint64_t>(seed.max_bandwidth_bps), mirror.upload_bps);
    BOOST_CHECK_EQUAL(EffectiveHostUploadBps(mirror.upload_bps, seed.max_bandwidth_bps, seed.allowed),
                      seed.allowed ? static_cast<uint64_t>(seed.max_bandwidth_bps) : 0);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::PRESERVATION).reason, PauseReason::BATTERY_POLICY);

    node::SystemSignals hot = QuietDesktop();
    hot.gpu.thermal = ThermalState::CRITICAL;
    g.SetMiningConsent(true);
    g.Observe(hot, 3000);
    BOOST_CHECK(!g.MiningAllowed());
    BOOST_CHECK_EQUAL(g.MiningPauseReason(), PauseReason::THERMAL_PRESSURE);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::PRESERVATION).reason, PauseReason::THERMAL_PRESSURE);

    node::SystemSignals disk = QuietDesktop();
    disk.disk_pressure = PressureState::CRITICAL;
    disk.storage_free_pct = 3;
    g.Observe(disk, 4000);
    BOOST_CHECK(!g.Permit(GovernorJob::PRESERVATION).allowed);
    BOOST_CHECK_EQUAL(g.Permit(GovernorJob::PRESERVATION).reason, PauseReason::STORAGE_FULL);

    node::SystemSignals busy = QuietDesktop();
    g.ResetPolicy();
    g.Observe(busy, 5000);
    const int64_t quiet = g.BackgroundUploadLimitBps();
    busy.egress_bps = quiet;
    g.Observe(busy, 11000);
    seed = g.Permit(GovernorJob::MODEL_SEED);
    BOOST_CHECK_EQUAL(seed.reason, PauseReason::NETWORK_BUSY);
    BOOST_CHECK_LT(seed.max_bandwidth_bps, quiet);
    BOOST_CHECK_LT(static_cast<uint64_t>(seed.max_bandwidth_bps), mirror.upload_bps);
    BOOST_CHECK_EQUAL(EffectiveHostUploadBps(mirror.upload_bps, seed.max_bandwidth_bps, seed.allowed),
                      seed.allowed ? static_cast<uint64_t>(seed.max_bandwidth_bps) : 0);

    g.SetMode(GovernorMode::OFF);
    g.Observe(QuietDesktop(), 12000);
    seed = g.Permit(GovernorJob::MODEL_SEED);
    BOOST_CHECK(!seed.allowed);
    BOOST_CHECK_EQUAL(EffectiveHostUploadBps(mirror.upload_bps, seed.max_bandwidth_bps, seed.allowed), 0);
}

BOOST_AUTO_TEST_CASE(infra_10_parse_host_mode_auto)
{
    using namespace modelnet;
    HostMode m = HostMode::OFF;
    BOOST_REQUIRE(ParseHostMode("auto", m));
    BOOST_CHECK(m == HostMode::AUTO);
    BOOST_REQUIRE(ParseHostMode("1", m));
    BOOST_CHECK(m == HostMode::ON);
    BOOST_REQUIRE(ParseHostMode("true", m));
    BOOST_CHECK(m == HostMode::ON);
    BOOST_REQUIRE(ParseHostMode("0", m));
    BOOST_CHECK(m == HostMode::OFF);
    BOOST_REQUIRE(ParseHostMode("false", m));
    BOOST_CHECK(m == HostMode::OFF);
    BOOST_CHECK(!ParseHostMode("maybe", m));
    BOOST_CHECK_EQUAL(HostModeName(HostMode::AUTO), "auto");

    HelperLaunchConfig auto_cfg;
    auto_cfg.host_mode = HostMode::AUTO;
    BOOST_CHECK(ArgvHas(BuildHelperArgv(auto_cfg), "-modelhost=auto"));
    HelperLaunchConfig on_cfg;
    on_cfg.host_mode = HostMode::ON;
    BOOST_CHECK(ArgvHas(BuildHelperArgv(on_cfg), "-modelhost=1"));
    HelperLaunchConfig off_cfg;
    BOOST_CHECK(!ArgvHas(BuildHelperArgv(off_cfg), "-modelhost=auto"));
    BOOST_CHECK(!ArgvHas(BuildHelperArgv(off_cfg), "-modelhost=1"));
}

BOOST_AUTO_TEST_CASE(infra_11_no_storage_no_advertise)
{
    using namespace modelnet;
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 0, true, true));
    BOOST_CHECK(!AutoHostShouldAdvertise(false, true, 8 * MIB, true, true));
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 8 * MIB, false, true));
    BOOST_CHECK(!MayAdvertiseHostAuto(true, true, 0, true, true));

    // Empty compact ranges are not a verified seeded range (INFRA-11 / A5).
    std::vector<PieceRange> none;
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 8 * MIB, !none.empty(), true));
    std::vector<uint32_t> have{0};
    std::vector<PieceRange> seeded;
    std::string err;
    BOOST_REQUIRE(CompactPieceRanges(have, seeded, err));
    BOOST_CHECK(RangesCover(seeded, 0, 0, 0));
    BOOST_CHECK(AutoHostShouldAdvertise(true, true, 8 * MIB, !seeded.empty(), true));
    BOOST_CHECK(!AutoHostShouldAdvertise(true, true, 8 * MIB, !seeded.empty(), false));
}

BOOST_AUTO_TEST_CASE(infra_12_profile_restart_persist)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "infra-12-profile";
    fs::create_directories(dir);
    const fs::path path = OperatorProfilePath(dir);
    const ProfilePolicy saved = ResolveProfile(OperatorProfile::INFRASTRUCTURE, {});
    std::string err;
    BOOST_REQUIRE_MESSAGE(SaveOperatorProfile(path, OperatorProfile::INFRASTRUCTURE, saved, err), err);
    BOOST_REQUIRE(fs::exists(path));

    OperatorProfile loaded_name = OperatorProfile::CUSTOM;
    ProfilePolicy loaded;
    BOOST_REQUIRE_MESSAGE(LoadOperatorProfile(path, loaded_name, loaded, err), err);
    BOOST_CHECK(loaded_name == OperatorProfile::INFRASTRUCTURE);
    BOOST_CHECK(loaded.relay);
    BOOST_CHECK(loaded.index);
    BOOST_CHECK(loaded.host_mode == HostMode::AUTO);
    BOOST_CHECK_EQUAL(loaded.auto_cap_bytes, saved.auto_cap_bytes);
    BOOST_CHECK_EQUAL(loaded.upload_bps, saved.upload_bps);
    BOOST_CHECK_EQUAL(loaded.seed, "auto");
    BOOST_CHECK(loaded.follow_peers);
    BOOST_CHECK(loaded.preserve_rare);
    CheckOrdinaryProfileKeys(OperatorProfileToJson(loaded_name, loaded));

    const auto personal = ResolveProfile(OperatorProfile::PERSONAL, {});
    BOOST_REQUIRE(SaveOperatorProfile(path, OperatorProfile::PERSONAL, personal, err));
    OperatorProfile name2 = OperatorProfile::CUSTOM;
    ProfilePolicy p2;
    BOOST_REQUIRE(LoadOperatorProfile(path, name2, p2, err));
    BOOST_CHECK(name2 == OperatorProfile::PERSONAL);
    BOOST_CHECK(!p2.relay);
    BOOST_CHECK_EQUAL(p2.auto_cap_bytes, PERSONAL_AUTO_CAP_BYTES);
    BOOST_CHECK(!p2.preserve_rare);
}

BOOST_AUTO_TEST_SUITE_END()
