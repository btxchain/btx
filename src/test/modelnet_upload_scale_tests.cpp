// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Deterministic upload-scheduler proofs for mixed peer populations and for
// 100 / 1000 / 10000 simulated peer *states* (no sockets, no threads, no
// wall clock). Every run below is a closed-form replay of
// UploadSchedulerDrr::RunEpoch/Select/NoteAcceptedWork/Release driven by a
// fixed peer table, so turn counts and byte totals are exact and a regression
// in the DRR credit arithmetic breaks an equality here rather than a heuristic.

#include <modelnet/bulk_controller.h>
#include <modelnet/policy.h>
#include <modelnet/reciprocity.h>
#include <modelnet/upload_scheduler.h>
#include <modelnet/upload_scheduler_drr.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace {

using namespace modelnet;

//! Scheduler quantum used by the simulations below (SUBPIECE_V1 sized).
constexpr uint64_t kUpQuantum = 256ull * 1024;
//! Bytes a peer absorbs per turn in the uniform simulations. kUpQuantum is an
//! exact multiple of it, which makes per-epoch service counts closed form.
constexpr uint64_t kUpGrant = 16ull * 1024;
//! Turns one weight-1 class can fund per epoch at the uniform grant.
constexpr int kUpTurnsPerEpoch = static_cast<int>(kUpQuantum / kUpGrant);

struct ScalePeer {
    std::string identity;
    std::string netgroup;
    UploadClass cls{UploadClass::NORMAL};
    HostAccountingClass accounting{HostAccountingClass::NATIVE_P2P};
    uint64_t grant{kUpGrant};
    bool writable{true};
    //! >0 simulates a slow receiver that keeps its slot for this many epochs.
    int hold_epochs{0};

    // Observations filled in by the simulator.
    int turns{0};
    uint64_t bytes{0};
    int last_epoch{-1};
    int max_gap{0};
};

struct ScaleTurn {
    int epoch{0};
    int round{0}; // -1 when the turn completed at end of epoch after a hold
    size_t peer{0};
    uint64_t bytes{0};
    UploadClass cls{UploadClass::NORMAL};
};

struct RoundTrace {
    int epoch{0};
    int round{0};
    int picked{0};
    int rare_concurrent{0};
    int non_rare_picked{0};
};

struct ScaleRun {
    std::vector<int> turns_per_epoch;
    std::vector<uint64_t> bytes_per_epoch;
    std::vector<ScaleTurn> served;
    std::vector<RoundTrace> rounds;
    int max_concurrent{0};
    int max_concurrent_rare{0};
    int total_turns{0};
    uint64_t total_bytes{0};
    uint64_t digest{1469598103934665603ull};
    size_t final_ready{0};
    int final_active{0};
    uint64_t class_deficit[4]{};
    uint64_t accounted_bytes[kHostAccountingClassCount]{};
    uint64_t accounted_count[kHostAccountingClassCount]{};
};

struct ScaleOptions {
    int epochs{10};
    int max_rounds{64};
};

uint64_t FnvMix(uint64_t h, uint64_t v)
{
    h ^= v;
    return h * 1099511628211ull;
}

/**
 * Replay a peer table against UploadSchedulerDrr.
 *
 * One epoch is RunEpoch() followed by rounds. A round fills every free slot
 * (Select until it refuses), then hands each admitted request its grant via
 * NoteAcceptedWork, releases it and re-queues the peer at the tail. A peer
 * with hold_epochs>0 keeps its slot instead, which is how a slow receiver is
 * modelled without a socket.
 */
ScaleRun RunUploadScaleSim(const DrrConfig& cfg, std::vector<ScalePeer>& peers, const ScaleOptions& opt)
{
    UploadSchedulerDrr sched(cfg);
    const DrrConfig& eff = sched.Config();
    std::map<uint64_t, size_t> owner;
    std::map<uint64_t, int> held;
    std::string err;
    ScaleRun run;

    auto enqueue = [&](size_t i) {
        const ScalePeer& p = peers[i];
        DrrUploadRequest r;
        r.identity = p.identity;
        r.netgroup = p.netgroup;
        r.schedule = p.cls;
        r.accounting = p.accounting;
        r.bytes = p.grant;
        r.receiver_writable = p.writable;
        uint64_t rid = 0;
        BOOST_REQUIRE(sched.Enqueue(r, rid, err));
        owner[rid] = i;
    };

    auto serve = [&](uint64_t rid, int epoch, int round, int& epoch_turns, uint64_t& epoch_bytes) {
        const size_t i = owner.at(rid);
        ScalePeer& p = peers[i];
        BOOST_REQUIRE(sched.NoteAcceptedWork(rid, p.grant, err));
        if (p.last_epoch >= 0) p.max_gap = std::max(p.max_gap, epoch - p.last_epoch);
        p.last_epoch = epoch;
        ++p.turns;
        p.bytes += p.grant;
        ScaleTurn t;
        t.epoch = epoch;
        t.round = round;
        t.peer = i;
        t.bytes = p.grant;
        t.cls = p.cls;
        run.served.push_back(t);
        ++run.total_turns;
        run.total_bytes += p.grant;
        run.digest = FnvMix(run.digest, static_cast<uint64_t>(epoch));
        run.digest = FnvMix(run.digest, static_cast<uint64_t>(i));
        run.digest = FnvMix(run.digest, p.grant);
        ++epoch_turns;
        epoch_bytes += p.grant;
        sched.Release(rid);
        owner.erase(rid);
        enqueue(i);
    };

    for (size_t i = 0; i < peers.size(); ++i) enqueue(i);

    for (int epoch = 0; epoch < opt.epochs; ++epoch) {
        sched.RunEpoch();
        int epoch_turns = 0;
        uint64_t epoch_bytes = 0;
        for (int round = 0; round < opt.max_rounds; ++round) {
            std::vector<DrrSelection> batch;
            DrrSelection sel;
            while (sched.Select(sel)) {
                BOOST_REQUIRE_LE(sched.Active(), eff.admission.slots);
                BOOST_REQUIRE_LE(sched.IdentityActive(sel.identity), eff.admission.per_identity);
                BOOST_REQUIRE_LE(sched.NetgroupActive(sel.netgroup), eff.admission.per_netgroup);
                BOOST_REQUIRE_EQUAL(sel.bytes, peers[owner.at(sel.request_id)].grant);
                batch.push_back(sel);
            }
            if (batch.empty()) break;
            run.max_concurrent = std::max(run.max_concurrent, sched.Active());

            RoundTrace tr;
            tr.epoch = epoch;
            tr.round = round;
            tr.picked = static_cast<int>(batch.size());
            for (const auto& s : batch) {
                if (s.schedule == UploadClass::RARE) ++tr.rare_concurrent;
                else ++tr.non_rare_picked;
            }
            for (const auto& kv : held) {
                if (peers[owner.at(kv.first)].cls == UploadClass::RARE) ++tr.rare_concurrent;
            }
            run.max_concurrent_rare = std::max(run.max_concurrent_rare, tr.rare_concurrent);
            run.rounds.push_back(tr);

            for (const auto& s : batch) {
                const size_t i = owner.at(s.request_id);
                if (peers[i].hold_epochs > 0) {
                    held[s.request_id] = peers[i].hold_epochs;
                    continue;
                }
                serve(s.request_id, epoch, round, epoch_turns, epoch_bytes);
            }
        }
        std::vector<uint64_t> expired;
        for (auto& kv : held) {
            if (--kv.second <= 0) expired.push_back(kv.first);
        }
        for (uint64_t rid : expired) {
            held.erase(rid);
            serve(rid, epoch, -1, epoch_turns, epoch_bytes);
        }
        run.turns_per_epoch.push_back(epoch_turns);
        run.bytes_per_epoch.push_back(epoch_bytes);
    }

    run.final_ready = sched.Ready();
    run.final_active = sched.Active();
    run.class_deficit[0] = sched.ClassDeficit(UploadClass::NEWCOMER);
    run.class_deficit[1] = sched.ClassDeficit(UploadClass::NORMAL);
    run.class_deficit[2] = sched.ClassDeficit(UploadClass::RARE);
    run.class_deficit[3] = sched.ClassDeficit(UploadClass::EXPLORATORY);
    for (int i = 0; i < kHostAccountingClassCount; ++i) {
        const HostAccountingClass c = static_cast<HostAccountingClass>(i);
        run.accounted_bytes[i] = sched.AccountedBytes(c);
        run.accounted_count[i] = sched.AccountedCount(c);
    }
    return run;
}

DrrConfig UpCfg(int slots, uint64_t quantum)
{
    DrrConfig cfg;
    cfg.admission.slots = slots;
    cfg.admission.max_slots = std::max(slots, 16);
    cfg.admission.per_identity = 2;
    cfg.admission.per_netgroup = 4;
    cfg.quantum_bytes = quantum;
    return cfg;
}

std::vector<ScalePeer> UniformPeers(size_t n, const std::string& tag, uint64_t grant)
{
    std::vector<ScalePeer> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        ScalePeer p;
        p.identity = tag + "-id-" + std::to_string(i);
        p.netgroup = tag + "-ng-" + std::to_string(i);
        p.grant = grant;
        v.push_back(p);
    }
    return v;
}

//! Slot and byte budget the host governor derives from the §8.2 background
//! share. Deliberately banded: a share that wanders inside one band must not
//! reconfigure the scheduler.
struct GovernorBudget {
    int slots{2};
    uint64_t quantum_bytes{2 * kUpGrant};
};

GovernorBudget BudgetForShare(double share)
{
    GovernorBudget b;
    if (share >= 0.18) b.slots = 16;
    else if (share >= 0.10) b.slots = 8;
    else b.slots = 2;
    b.quantum_bytes = kUpGrant * static_cast<uint64_t>(b.slots);
    return b;
}

int TurnsInEpochExcluding(const ScaleRun& run, int epoch, const std::vector<size_t>& skip)
{
    int n = 0;
    for (const auto& t : run.served) {
        if (t.epoch != epoch) continue;
        if (std::find(skip.begin(), skip.end(), t.peer) != skip.end()) continue;
        ++n;
    }
    return n;
}

uint64_t ClassBytes(const ScaleRun& run, UploadClass c)
{
    uint64_t b = 0;
    for (const auto& t : run.served) {
        if (t.cls == c) b += t.bytes;
    }
    return b;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_upload_scale_tests, BasicTestingSetup)

// The slot budget adapts: concurrency follows the configured slot count across
// a 1..16 ladder while the per-epoch byte cap stays pinned to the class
// credit. Slots buy parallelism, never extra bandwidth.
BOOST_AUTO_TEST_CASE(upsched_scale_slot_ladder_adapts_concurrency_not_byte_budget)
{
    using namespace modelnet;
    const int ladder[] = {1, 2, 4, 8, 16};
    std::vector<uint64_t> totals;
    for (int slots : ladder) {
        auto peers = UniformPeers(100, "ladder" + std::to_string(slots), kUpGrant);
        ScaleOptions opt;
        opt.epochs = 6;
        const ScaleRun run = RunUploadScaleSim(UpCfg(slots, kUpQuantum), peers, opt);

        BOOST_CHECK_EQUAL(run.max_concurrent, slots);
        // The first epoch holds a single quantum of credit, so it is slot bound.
        BOOST_CHECK_EQUAL(run.turns_per_epoch[0], slots);
        BOOST_CHECK_EQUAL(run.bytes_per_epoch[0], static_cast<uint64_t>(slots) * kUpGrant);
        // Steady state is credit bound and identical at every slot count.
        for (size_t e = 1; e < run.turns_per_epoch.size(); ++e) {
            BOOST_CHECK_EQUAL(run.turns_per_epoch[e], kUpTurnsPerEpoch);
            BOOST_CHECK_EQUAL(run.bytes_per_epoch[e], kUpQuantum);
        }
        BOOST_CHECK_EQUAL(run.final_active, 0);
        BOOST_CHECK_EQUAL(run.final_ready, static_cast<size_t>(100));
        totals.push_back(run.total_bytes);
    }
    // Sixteen times the concurrency bought less than one batch of extra bytes.
    BOOST_REQUIRE_EQUAL(totals.size(), static_cast<size_t>(5));
    BOOST_CHECK_EQUAL(totals.back() - totals.front(), 15 * kUpGrant);

    // Degenerate budgets are clamped, not accepted.
    DrrConfig bad = UpCfg(0, kUpQuantum);
    bad.admission.max_slots = 0;
    bad.admission.per_identity = 0;
    bad.admission.per_netgroup = 0;
    UploadSchedulerDrr clamped(bad);
    BOOST_CHECK_EQUAL(clamped.Slots(), 1);
    BOOST_CHECK_EQUAL(clamped.Config().admission.max_slots, 1);
    BOOST_CHECK_EQUAL(clamped.Config().admission.per_identity, 1);
    BOOST_CHECK_EQUAL(clamped.Config().admission.per_netgroup, 1);
}

// A peer that absorbs eight times the bytes of everyone else still gets the
// same number of turns and a bounded slice of the epoch budget.
BOOST_AUTO_TEST_CASE(upsched_scale_fast_peer_cannot_capture_turns_or_bytes)
{
    using namespace modelnet;
    auto peers = UniformPeers(100, "fast", kUpGrant);
    peers[0].identity = "fast-greedy";
    peers[0].grant = 8 * kUpGrant;
    ScaleOptions opt;
    opt.epochs = 40;
    const ScaleRun run = RunUploadScaleSim(UpCfg(8, kUpQuantum), peers, opt);

    int min_turns = run.total_turns;
    int max_turns = 0;
    int unserved = 0;
    for (const auto& p : peers) {
        min_turns = std::min(min_turns, p.turns);
        max_turns = std::max(max_turns, p.turns);
        if (p.turns == 0) ++unserved;
    }
    BOOST_CHECK_EQUAL(unserved, 0);
    BOOST_CHECK_GT(min_turns, 0);
    BOOST_CHECK_LE(max_turns - min_turns, 1);
    // The greedy peer sits at the head of the queue and still cannot pull ahead
    // of the slowest peer by more than a single turn.
    BOOST_CHECK_LE(peers[0].turns, min_turns + 1);

    // Bytes: an oversized grant buys a bounded share, never the epoch.
    BOOST_CHECK_GT(peers[0].bytes, peers[1].bytes);
    BOOST_CHECK_LT(peers[0].bytes * 8, run.total_bytes);
    // And it never takes two turns inside one epoch: its identity deficit is
    // drained by what it accepted.
    for (int e = 0; e < opt.epochs; ++e) {
        int greedy_turns = 0;
        for (const auto& t : run.served) {
            if (t.epoch == e && t.peer == 0) ++greedy_turns;
        }
        BOOST_CHECK_LE(greedy_turns, 1);
    }
}

// Three peers pin their slots for three epochs at a time. The rest of the
// swarm keeps its service rate: a stalled receiver burns a slot, not the epoch.
BOOST_AUTO_TEST_CASE(upsched_scale_slow_holder_does_not_stall_the_swarm)
{
    using namespace modelnet;
    const std::vector<size_t> holders{0, 1, 2};
    ScaleOptions opt;
    opt.epochs = 20;

    auto base_peers = UniformPeers(100, "stall", kUpGrant);
    for (size_t i : holders) base_peers[i].grant = kUpGrant / 4;
    const ScaleRun base = RunUploadScaleSim(UpCfg(8, kUpQuantum), base_peers, opt);

    auto slow_peers = UniformPeers(100, "stall", kUpGrant);
    for (size_t i : holders) {
        slow_peers[i].grant = kUpGrant / 4;
        slow_peers[i].hold_epochs = 3;
    }
    const ScaleRun slow = RunUploadScaleSim(UpCfg(8, kUpQuantum), slow_peers, opt);

    BOOST_CHECK_LE(slow.max_concurrent, 8);
    int base_others = 0;
    int slow_others = 0;
    for (int e = 0; e < opt.epochs; ++e) {
        const int s = TurnsInEpochExcluding(slow, e, holders);
        // No epoch goes dark while slots are pinned by slow receivers.
        BOOST_CHECK_GT(s, 0);
        slow_others += s;
        base_others += TurnsInEpochExcluding(base, e, holders);
    }
    BOOST_CHECK_GT(base_others, 0);
    // Held slots cost the rest of the swarm nothing measurable: the class byte
    // budget, not the slot count, is the binding cap.
    BOOST_CHECK_GE(slow_others * 100, base_others * 95);

    // The holders sit at the head of the queue and are skipped while active,
    // so there is no head-of-line blocking, and their work still completes.
    int base_hold_turns = 0;
    int slow_hold_turns = 0;
    for (size_t i : holders) {
        BOOST_CHECK_GT(slow_peers[i].turns, 0);
        base_hold_turns += base_peers[i].turns;
        slow_hold_turns += slow_peers[i].turns;
    }
    BOOST_CHECK_LT(slow_hold_turns, base_hold_turns);
    int behind_holders = 0;
    for (const auto& t : slow.served) {
        if (t.peer >= holders.size()) ++behind_holders;
    }
    BOOST_CHECK_GT(behind_holders, slow.total_turns / 2);
    // Nothing is lost while a slot is pinned: every peer is queued or active.
    BOOST_CHECK_EQUAL(slow.final_ready + static_cast<size_t>(slow.final_active),
                      static_cast<size_t>(100));
}

// Newcomers are admitted with no credit at all, but the optimism is a class
// budget rather than a per-peer grant: flooding 900 newcomers instead of 20
// does not enlarge the newcomer share by one byte. The flood run is also the
// 1000 peer-state mixed-class simulation.
BOOST_AUTO_TEST_CASE(upsched_scale_newcomer_optimism_is_bounded_under_sybil_flood)
{
    using namespace modelnet;
    ScaleOptions opt;
    opt.epochs = 40;
    auto build = [](size_t newcomers, const std::string& tag) {
        std::vector<ScalePeer> v = UniformPeers(newcomers, tag + "-new", kUpGrant);
        for (auto& p : v) p.cls = UploadClass::NEWCOMER;
        std::vector<ScalePeer> normals = UniformPeers(100, tag + "-old", kUpGrant);
        v.insert(v.end(), normals.begin(), normals.end());
        return v;
    };

    auto few = build(20, "few");
    const ScaleRun run_few = RunUploadScaleSim(UpCfg(8, kUpQuantum), few, opt);
    auto flood = build(900, "flood");
    const ScaleRun run_flood = RunUploadScaleSim(UpCfg(8, kUpQuantum), flood, opt);
    BOOST_CHECK_EQUAL(flood.size(), static_cast<size_t>(1000));

    const uint64_t few_new = ClassBytes(run_few, UploadClass::NEWCOMER);
    const uint64_t flood_new = ClassBytes(run_flood, UploadClass::NEWCOMER);
    BOOST_CHECK_GT(few_new, static_cast<uint64_t>(0));
    // The same optimistic budget survives a 45x sybil flood (within 10%).
    BOOST_CHECK_GE(flood_new * 10, few_new * 9);
    BOOST_CHECK_LE(flood_new * 10, few_new * 11);
    // Per newcomer the optimism is diluted, never multiplied.
    BOOST_CHECK_GE(few_new / 20, (flood_new / 900) * 10);

    // Optimism is bounded in credit as well: the class deficit cannot grow past
    // the cap while newcomers queue up.
    BOOST_CHECK_LE(run_flood.class_deficit[0], kDrrMaxDeficitBytes);
    BOOST_CHECK_LE(run_few.class_deficit[0], kDrrMaxDeficitBytes);

    // Every newcomer in the small population is admitted with no history.
    for (size_t i = 0; i < 20; ++i) BOOST_CHECK_GT(few[i].turns, 0);
    // Under the flood the newcomers rotate instead of a fixed cohort winning.
    size_t flood_served = 0;
    for (size_t i = 0; i < 900; ++i) {
        if (flood[i].turns > 0) ++flood_served;
    }
    BOOST_CHECK_GT(flood_served, static_cast<size_t>(400));
    // Established traffic keeps its own class credit during the flood.
    const uint64_t few_normal = ClassBytes(run_few, UploadClass::NORMAL);
    const uint64_t flood_normal = ClassBytes(run_flood, UploadClass::NORMAL);
    BOOST_CHECK_GT(flood_normal, static_cast<uint64_t>(0));
    BOOST_CHECK_GE(flood_normal * 10, few_normal * 9);
}

// Endangered (RARE) ranges get a weighted class budget and a guaranteed lane,
// but the lane caps their concurrency while any other class still has credit.
BOOST_AUTO_TEST_CASE(upsched_scale_endangered_ranges_lead_but_lane_is_capped)
{
    using namespace modelnet;
    BOOST_CHECK_EQUAL(DrrClassWeight(UploadClass::RARE, 4), static_cast<uint32_t>(4));
    BOOST_CHECK_EQUAL(DrrClassWeight(UploadClass::RARE, 99), kDrrRareWeightMax);
    BOOST_CHECK_EQUAL(DrrClassWeight(UploadClass::NORMAL, 4), static_cast<uint32_t>(1));

    DrrConfig cfg = UpCfg(8, kUpQuantum);
    cfg.rare_weight = 4;
    cfg.rare_lane_slots = 1;

    std::vector<ScalePeer> mixed = UniformPeers(100, "mix-normal", kUpGrant);
    std::vector<ScalePeer> rare = UniformPeers(20, "mix-rare", kUpGrant);
    for (auto& p : rare) p.cls = UploadClass::RARE;
    mixed.insert(mixed.end(), rare.begin(), rare.end());

    ScaleOptions opt;
    opt.epochs = 20;
    opt.max_rounds = 256;
    const ScaleRun run = RunUploadScaleSim(cfg, mixed, opt);

    const uint64_t rare_bytes = ClassBytes(run, UploadClass::RARE);
    const uint64_t normal_bytes = ClassBytes(run, UploadClass::NORMAL);
    // Weighted credit: endangered ranges lead, by a bounded multiplier.
    BOOST_CHECK_GT(normal_bytes, static_cast<uint64_t>(0));
    BOOST_CHECK_GE(rare_bytes, 3 * normal_bytes);
    BOOST_CHECK_LE(rare_bytes, 6 * normal_bytes);

    // While another class still has credit, the rare lane is the binding cap.
    int lane_checked = 0;
    for (const auto& r : run.rounds) {
        if (r.non_rare_picked == 0) continue;
        BOOST_CHECK_LE(r.rare_concurrent, cfg.rare_lane_slots);
        ++lane_checked;
    }
    BOOST_CHECK_GE(lane_checked, opt.epochs);

    // Neither class is shut out of an epoch.
    for (int e = 0; e < opt.epochs; ++e) {
        int rare_turns = 0;
        int normal_turns = 0;
        for (const auto& t : run.served) {
            if (t.epoch != e) continue;
            if (t.cls == UploadClass::RARE) ++rare_turns;
            else ++normal_turns;
        }
        BOOST_CHECK_GT(rare_turns, 0);
        BOOST_CHECK_GT(normal_turns, 0);
    }

    // With nothing else asking, the lane relaxes so capacity is not wasted.
    std::vector<ScalePeer> only_rare = UniformPeers(40, "only-rare", kUpGrant);
    for (auto& p : only_rare) p.cls = UploadClass::RARE;
    const ScaleRun solo = RunUploadScaleSim(cfg, only_rare, opt);
    BOOST_CHECK_EQUAL(solo.max_concurrent, 8);
    BOOST_CHECK_EQUAL(solo.max_concurrent_rare, 8);
}

// Reciprocity weight scales what a peer is handed per turn. It never decides
// whether the peer is handed anything: a zero-credit peer, and a peer holding
// only self-reported third-party receipts, get exactly as many turns as the
// largest contributor.
BOOST_AUTO_TEST_CASE(upsched_scale_reciprocity_shapes_grants_but_never_gates)
{
    using namespace modelnet;
    ReciprocityLedger ledger;
    auto contribute = [&](const std::string& peer, int file, int events) {
        for (int k = 0; k < events; ++k) {
            BOOST_REQUIRE(ledger.Received(peer, "endangered-artifact", file, k,
                                          64ll * 1024 * 1024, 0, true, true, false, 3));
        }
    };
    contribute("generous", 1, 64);
    contribute("mid", 2, 32);
    // "leech" uploaded nothing; "claimer" only presents third-party receipts.
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("claimer", 4ll << 30, 0));
    BOOST_CHECK_EQUAL(ledger.Weight("generous", 0), 4);
    BOOST_CHECK_EQUAL(ledger.Weight("mid", 0), 2);
    BOOST_CHECK_EQUAL(ledger.Weight("leech", 0), 1);
    BOOST_CHECK_EQUAL(ledger.Weight("claimer", 0), 1);

    const std::string names[] = {"generous", "mid", "leech", "claimer"};
    std::vector<ScalePeer> peers;
    for (const auto& n : names) {
        ScalePeer p;
        p.identity = n;
        p.netgroup = "recip-ng-" + n;
        p.grant = 8ull * 1024 * static_cast<uint64_t>(ledger.Weight(n, 0));
        peers.push_back(p);
    }
    ScaleOptions opt;
    opt.epochs = 20;
    const ScaleRun run = RunUploadScaleSim(UpCfg(4, kUpQuantum), peers, opt);

    // Not a gate: identical turn counts regardless of credit.
    BOOST_CHECK_EQUAL(peers[0].turns, peers[2].turns);
    BOOST_CHECK_EQUAL(peers[1].turns, peers[2].turns);
    BOOST_CHECK_EQUAL(peers[3].turns, peers[2].turns);
    BOOST_CHECK_GT(peers[2].turns, opt.epochs);
    // An influence: bytes per turn track the weight exactly.
    BOOST_CHECK_EQUAL(peers[0].bytes, 4 * peers[2].bytes);
    BOOST_CHECK_EQUAL(peers[1].bytes, 2 * peers[2].bytes);
    // Self-reported receipts buy nothing over the zero-credit peer.
    BOOST_CHECK_EQUAL(peers[3].bytes, peers[2].bytes);
    BOOST_CHECK_EQUAL(run.total_bytes,
                      peers[0].bytes + peers[1].bytes + peers[2].bytes + peers[3].bytes);
    BOOST_CHECK(!ledger.TouchesBanMan());
    BOOST_CHECK(!ledger.TouchesAddrMan());
}

// A peer that can only absorb 1 KiB per turn keeps the same turn count as a
// 16 KiB peer and a bounded gap between services. Low bandwidth costs bytes,
// never membership.
BOOST_AUTO_TEST_CASE(upsched_scale_low_bandwidth_peer_keeps_bounded_service_gap)
{
    using namespace modelnet;
    auto peers = UniformPeers(200, "lowbw", kUpGrant);
    peers[77].identity = "lowbw-dialup";
    peers[77].grant = 1024;
    ScaleOptions opt;
    opt.epochs = 60;
    const ScaleRun run = RunUploadScaleSim(UpCfg(8, kUpQuantum), peers, opt);

    int min_turns = run.total_turns;
    int max_turns = 0;
    int max_gap = 0;
    for (const auto& p : peers) {
        min_turns = std::min(min_turns, p.turns);
        max_turns = std::max(max_turns, p.turns);
        max_gap = std::max(max_gap, p.max_gap);
    }
    BOOST_CHECK_LE(max_turns - min_turns, 1);
    BOOST_CHECK_GE(peers[77].turns, min_turns);
    BOOST_CHECK_GE(peers[77].turns, 4);
    // Rotation period for 200 peers at kUpTurnsPerEpoch turns per epoch.
    const int rotation = 200 / kUpTurnsPerEpoch;
    BOOST_CHECK_LE(peers[77].max_gap, rotation + 3);
    BOOST_CHECK_LE(max_gap, rotation + 3);
    // Cheap to serve, not excluded: same turns, a sixteenth of the bytes.
    BOOST_CHECK_EQUAL(peers[77].bytes, static_cast<uint64_t>(peers[77].turns) * 1024);
    BOOST_CHECK_LT(peers[77].bytes * 10, peers[78].bytes);
}

// The host upload cap holds even when every peer asks for four quanta at once:
// an epoch can overshoot by at most the single batch already admitted, and the
// overshoot never compounds into the next epoch.
BOOST_AUTO_TEST_CASE(upsched_scale_epoch_byte_cap_bounds_oversized_grants)
{
    using namespace modelnet;
    const uint64_t big = 1024ull * 1024; // four times the quantum
    auto peers = UniformPeers(100, "oversize", big);
    for (size_t i = 0; i < peers.size(); ++i) {
        peers[i].accounting = static_cast<HostAccountingClass>(i % kHostAccountingClassCount);
    }
    const int slots = 8;
    ScaleOptions opt;
    opt.epochs = 10;
    const ScaleRun run = RunUploadScaleSim(UpCfg(slots, kUpQuantum), peers, opt);

    const uint64_t batch_cap = static_cast<uint64_t>(slots) * big;
    for (size_t e = 0; e < run.bytes_per_epoch.size(); ++e) {
        BOOST_CHECK_EQUAL(run.turns_per_epoch[e], slots);
        BOOST_CHECK_EQUAL(run.bytes_per_epoch[e], batch_cap);
        BOOST_CHECK_LE(run.bytes_per_epoch[e], kUpQuantum + batch_cap);
    }
    BOOST_CHECK_EQUAL(run.total_bytes, batch_cap * static_cast<uint64_t>(opt.epochs));
    BOOST_CHECK_EQUAL(run.total_turns, slots * opt.epochs);
    BOOST_CHECK_EQUAL(run.max_concurrent, slots);

    // Accounting classes are counters, not a pick key: rotation spreads the 80
    // turns evenly over the five classes.
    uint64_t sum_bytes = 0;
    uint64_t sum_count = 0;
    for (int i = 0; i < kHostAccountingClassCount; ++i) {
        BOOST_CHECK_EQUAL(run.accounted_count[i], static_cast<uint64_t>(16));
        BOOST_CHECK_EQUAL(run.accounted_bytes[i], static_cast<uint64_t>(16) * big);
        sum_bytes += run.accounted_bytes[i];
        sum_count += run.accounted_count[i];
    }
    BOOST_CHECK_EQUAL(sum_bytes, run.total_bytes);
    BOOST_CHECK_EQUAL(sum_count, static_cast<uint64_t>(run.total_turns));
}

// The §8.2 governor can cut the upload budget: a congestion signal shrinks both
// the slot count and the per-epoch byte cap by 8x, and not one queued request
// is dropped on the way down.
BOOST_AUTO_TEST_CASE(upsched_scale_governor_reduction_shrinks_budget_without_dropping_queue)
{
    using namespace modelnet;
    LowPriorityBulkController bulk;
    bulk.ObserveRtt(50);
    bulk.ObserveRtt(50);
    const GovernorBudget calm = BudgetForShare(bulk.BackgroundShare());
    BOOST_CHECK_EQUAL(calm.slots, 16);
    BOOST_CHECK_EQUAL(calm.quantum_bytes, kUpQuantum);

    bulk.ObserveRtt(150);
    const double congested_share = bulk.BackgroundShare();
    const GovernorBudget tight = BudgetForShare(congested_share);
    BOOST_CHECK_LT(congested_share, 0.10);
    BOOST_CHECK_GE(congested_share, 0.05); // reduced, never zero
    BOOST_CHECK_EQUAL(tight.slots, 2);
    BOOST_CHECK_EQUAL(tight.quantum_bytes, 2 * kUpGrant);
    BOOST_CHECK_LT(tight.slots, calm.slots);
    BOOST_CHECK_LT(tight.quantum_bytes, calm.quantum_bytes);

    ScaleOptions opt;
    opt.epochs = 8;
    auto calm_peers = UniformPeers(100, "gov", kUpGrant);
    const ScaleRun calm_run = RunUploadScaleSim(UpCfg(calm.slots, calm.quantum_bytes), calm_peers, opt);
    auto tight_peers = UniformPeers(100, "gov", kUpGrant);
    const ScaleRun tight_run = RunUploadScaleSim(UpCfg(tight.slots, tight.quantum_bytes), tight_peers, opt);

    for (size_t e = 0; e < calm_run.bytes_per_epoch.size(); ++e) {
        BOOST_CHECK_EQUAL(calm_run.turns_per_epoch[e], calm.slots);
        BOOST_CHECK_EQUAL(calm_run.bytes_per_epoch[e], calm.quantum_bytes);
        BOOST_CHECK_EQUAL(tight_run.turns_per_epoch[e], tight.slots);
        BOOST_CHECK_EQUAL(tight_run.bytes_per_epoch[e], tight.quantum_bytes);
    }
    BOOST_CHECK_EQUAL(calm_run.total_bytes, 8 * tight_run.total_bytes);
    BOOST_CHECK_EQUAL(tight_run.max_concurrent, tight.slots);

    // A reduced budget, not a dropped queue: every peer is still enqueued and
    // the peers that were served are distinct.
    BOOST_CHECK_EQUAL(tight_run.final_ready, static_cast<size_t>(100));
    BOOST_CHECK_EQUAL(tight_run.final_active, 0);
    int served_under_pressure = 0;
    for (const auto& p : tight_peers) {
        if (p.turns > 0) ++served_under_pressure;
    }
    BOOST_CHECK_GT(served_under_pressure, 0);
    BOOST_CHECK_EQUAL(served_under_pressure, tight_run.total_turns);
}

// After congestion clears the budget walks back up monotonically and the
// scheduler returns to byte-for-byte the pre-congestion schedule.
BOOST_AUTO_TEST_CASE(upsched_scale_throughput_recovers_after_congestion_clears)
{
    using namespace modelnet;
    LowPriorityBulkController bulk;
    bulk.ObserveRtt(50);
    bulk.ObserveRtt(50);
    const GovernorBudget before = BudgetForShare(bulk.BackgroundShare());
    BOOST_CHECK_EQUAL(before.slots, 16);

    bulk.ObserveBackpressure(true);
    bulk.ObserveRtt(200);
    const GovernorBudget floor_budget = BudgetForShare(bulk.BackgroundShare());
    BOOST_CHECK_EQUAL(floor_budget.slots, 2);
    BOOST_CHECK_LT(floor_budget.quantum_bytes, before.quantum_bytes);

    bulk.ObserveBackpressure(false);
    std::vector<int> recovery_slots;
    double last_share = bulk.BackgroundShare();
    int ticks_to_full = -1;
    for (int tick = 1; tick <= 8; ++tick) {
        bulk.ObserveRtt(50);
        const double share = bulk.BackgroundShare();
        BOOST_CHECK_GE(share, last_share); // monotone climb, no sawtooth
        last_share = share;
        const GovernorBudget b = BudgetForShare(share);
        recovery_slots.push_back(b.slots);
        if (ticks_to_full < 0 && b.slots == before.slots) ticks_to_full = tick;
    }
    // Hysteresis: a single good tick does not restore the budget.
    BOOST_REQUIRE_EQUAL(recovery_slots.size(), static_cast<size_t>(8));
    BOOST_CHECK_EQUAL(recovery_slots[0], floor_budget.slots);
    BOOST_REQUIRE_GT(ticks_to_full, 1);
    BOOST_CHECK_LE(ticks_to_full, 5);
    for (size_t i = 1; i < recovery_slots.size(); ++i) {
        BOOST_CHECK_GE(recovery_slots[i], recovery_slots[i - 1]);
    }
    const GovernorBudget after = BudgetForShare(bulk.BackgroundShare());
    BOOST_CHECK_EQUAL(after.slots, before.slots);
    BOOST_CHECK_EQUAL(after.quantum_bytes, before.quantum_bytes);

    ScaleOptions opt;
    opt.epochs = 8;
    auto pre_peers = UniformPeers(100, "recover", kUpGrant);
    const ScaleRun pre = RunUploadScaleSim(UpCfg(before.slots, before.quantum_bytes), pre_peers, opt);
    auto mid_peers = UniformPeers(100, "recover", kUpGrant);
    const ScaleRun mid = RunUploadScaleSim(UpCfg(floor_budget.slots, floor_budget.quantum_bytes), mid_peers, opt);
    auto post_peers = UniformPeers(100, "recover", kUpGrant);
    const ScaleRun post = RunUploadScaleSim(UpCfg(after.slots, after.quantum_bytes), post_peers, opt);

    BOOST_CHECK_LT(mid.total_bytes, pre.total_bytes);
    BOOST_CHECK_EQUAL(post.total_bytes, pre.total_bytes);
    BOOST_CHECK_EQUAL(post.total_turns, pre.total_turns);
    BOOST_CHECK_EQUAL(post.max_concurrent, pre.max_concurrent);
    BOOST_CHECK_EQUAL(post.digest, pre.digest);
    // Recovery is a return to the same schedule, not a catch-up burst.
    for (size_t e = 0; e < post.bytes_per_epoch.size(); ++e) {
        BOOST_CHECK_EQUAL(post.bytes_per_epoch[e], pre.bytes_per_epoch[e]);
    }
}

// Borderline RTT must not reconfigure the scheduler. The share may drift inside
// one governor band, but the derived budget changes only on a real pressure
// transition, and leaving pressure takes two consecutive clear ticks.
BOOST_AUTO_TEST_CASE(upsched_scale_governor_hysteresis_does_not_flap_on_borderline_rtt)
{
    using namespace modelnet;
    LowPriorityBulkController bulk;
    bulk.ObserveRtt(50);
    bulk.ObserveRtt(50);
    GovernorBudget budget = BudgetForShare(bulk.BackgroundShare());
    const int calm_slots = budget.slots;

    // Twenty ticks straddling the trip point (ratio 1.4 / 1.04) without
    // crossing it.
    int budget_changes = 0;
    double min_share = bulk.BackgroundShare();
    for (int i = 0; i < 20; ++i) {
        bulk.ObserveRtt((i % 2 == 0) ? 70.0 : 52.0);
        min_share = std::min(min_share, bulk.BackgroundShare());
        const GovernorBudget next = BudgetForShare(bulk.BackgroundShare());
        if (next.slots != budget.slots) ++budget_changes;
        budget = next;
    }
    // At most the single step out of the top band, never a per-tick sawtooth.
    BOOST_CHECK_LE(budget_changes, 1);
    BOOST_CHECK_GE(min_share, 0.10);
    BOOST_CHECK(!bulk.StatusJson()["pressure_latched"].get_bool());
    BOOST_CHECK(bulk.StatusJson()["hysteresis"].get_bool());
    BOOST_CHECK_LE(budget.slots, calm_slots);

    // One real spike trips the latch.
    bulk.ObserveRtt(400);
    const double latched_share = bulk.BackgroundShare();
    BOOST_CHECK_LT(latched_share, min_share);
    BOOST_CHECK_EQUAL(BudgetForShare(latched_share).slots, 2);
    BOOST_CHECK(bulk.StatusJson()["pressure_latched"].get_bool());

    // Twelve ticks of alternating marginal recovery restore nothing.
    int pinned_changes = 0;
    for (int i = 0; i < 12; ++i) {
        bulk.ObserveRtt((i % 2 == 0) ? 52.0 : 56.0);
        BOOST_CHECK_CLOSE(bulk.BackgroundShare(), latched_share, 1e-9);
        if (BudgetForShare(bulk.BackgroundShare()).slots != 2) ++pinned_changes;
        BOOST_CHECK(bulk.StatusJson()["pressure_latched"].get_bool());
    }
    BOOST_CHECK_EQUAL(pinned_changes, 0);

    // Two consecutive clear ticks, and only then, release the latch.
    bulk.ObserveRtt(50);
    BOOST_CHECK_CLOSE(bulk.BackgroundShare(), latched_share, 1e-9);
    BOOST_CHECK_EQUAL(bulk.StatusJson()["clear_ticks"].getInt<int>(), 1);
    bulk.ObserveRtt(50);
    BOOST_CHECK_GT(bulk.BackgroundShare(), latched_share);
    BOOST_CHECK(!bulk.StatusJson()["pressure_latched"].get_bool());
    BOOST_CHECK_GT(BudgetForShare(bulk.BackgroundShare()).slots, 2);
}

// 1000 peer states: strict rotation. Nobody takes a second turn while anybody
// is still waiting for a first, and the service order is the queue order.
BOOST_AUTO_TEST_CASE(upsched_scale_thousand_peer_states_rotate_in_queue_order)
{
    using namespace modelnet;
    const size_t n = 1000;
    auto peers = UniformPeers(n, "kilo", kUpGrant);
    ScaleOptions opt;
    opt.epochs = 30;
    const ScaleRun run = RunUploadScaleSim(UpCfg(8, kUpQuantum), peers, opt);

    const int expected_turns = 8 + (opt.epochs - 1) * kUpTurnsPerEpoch;
    BOOST_CHECK_EQUAL(run.total_turns, expected_turns);
    BOOST_REQUIRE_LT(static_cast<size_t>(expected_turns), n);
    for (size_t k = 0; k < run.served.size(); ++k) {
        BOOST_REQUIRE_EQUAL(run.served[k].peer, k);
    }
    size_t served_peers = 0;
    for (const auto& p : peers) {
        BOOST_REQUIRE_LE(p.turns, 1);
        if (p.turns == 1) ++served_peers;
    }
    BOOST_CHECK_EQUAL(served_peers, run.served.size());
    BOOST_CHECK_EQUAL(run.max_concurrent, 8);
    BOOST_CHECK_EQUAL(run.final_ready, n);
    BOOST_CHECK_EQUAL(run.final_active, 0);
    BOOST_CHECK_EQUAL(run.total_bytes, static_cast<uint64_t>(expected_turns) * kUpGrant);
}

// 10000 peer states in one queue: admission stays bounded, the shared-netgroup
// cap holds, nothing is lost, and two independent replays are identical.
BOOST_AUTO_TEST_CASE(upsched_scale_ten_thousand_peer_states_bounded_and_replayable)
{
    using namespace modelnet;
    const size_t n = 10000;
    auto build = [&]() {
        std::vector<ScalePeer> v;
        v.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            ScalePeer p;
            p.identity = "myriad-id-" + std::to_string(i);
            p.netgroup = "myriad-ng-" + std::to_string(i % 64);
            p.accounting = static_cast<HostAccountingClass>(i % kHostAccountingClassCount);
            p.grant = kUpGrant;
            v.push_back(p);
        }
        return v;
    };

    const DrrConfig cfg = UpCfg(16, kUpQuantum);
    ScaleOptions opt;
    opt.epochs = 3;
    opt.max_rounds = 8;

    auto peers_a = build();
    const ScaleRun a = RunUploadScaleSim(cfg, peers_a, opt);
    auto peers_b = build();
    const ScaleRun b = RunUploadScaleSim(cfg, peers_b, opt);

    // Deterministic replay of the same 10000 peer states.
    BOOST_CHECK_EQUAL(a.digest, b.digest);
    BOOST_CHECK_EQUAL(a.total_turns, b.total_turns);
    BOOST_CHECK_EQUAL(a.total_bytes, b.total_bytes);
    BOOST_REQUIRE_EQUAL(a.served.size(), b.served.size());
    for (size_t k = 0; k < a.served.size(); ++k) {
        BOOST_REQUIRE_EQUAL(a.served[k].peer, b.served[k].peer);
        BOOST_REQUIRE_EQUAL(a.served[k].epoch, b.served[k].epoch);
    }

    // 10000 queued states, 16 concurrent transfers: the queue is a queue, and
    // the connection count is not the capacity.
    BOOST_CHECK_EQUAL(a.max_concurrent, cfg.admission.slots);
    BOOST_CHECK_EQUAL(a.final_active, 0);
    BOOST_CHECK_EQUAL(a.final_ready, n);
    BOOST_CHECK_EQUAL(a.total_turns, kUpTurnsPerEpoch * opt.epochs);
    for (size_t e = 0; e < a.turns_per_epoch.size(); ++e) {
        BOOST_CHECK_EQUAL(a.turns_per_epoch[e], kUpTurnsPerEpoch);
        BOOST_CHECK_EQUAL(a.bytes_per_epoch[e], kUpQuantum);
    }
    // The head of the queue is served first even at this depth.
    for (size_t k = 0; k < a.served.size(); ++k) {
        BOOST_REQUIRE_EQUAL(a.served[k].peer, k);
    }
    // A 156-peer netgroup never exceeds its share of the live slots.
    std::map<std::string, int> per_ng;
    for (const auto& t : a.served) {
        if (t.epoch != 0) continue;
        ++per_ng[peers_a[t.peer].netgroup];
    }
    BOOST_CHECK_GT(per_ng.size(), static_cast<size_t>(1));
    for (const auto& kv : per_ng) {
        BOOST_CHECK_LE(kv.second, cfg.admission.per_netgroup);
    }
}

BOOST_AUTO_TEST_SUITE_END()
