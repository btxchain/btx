// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing.h>
#include <node/chain_staleness.h>

#include <algorithm>
#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(assumeutxo_capacity_tests)

namespace {

struct DualChainstateSim {
    static constexpr int kBudget{2};
    static constexpr int kSnapshotBase{110};

    int active_height{kSnapshotBase};
    int best_header{kSnapshotBase};
    int background_height{50};
    int inflight_active{0};
    int inflight_background{0};
    bool historical_body_available{false};
    int background_connected{0};
    int active_connected{0};
    int64_t now{1'000};
    int64_t yield_since{0};
    uint64_t background_yields{0};
    uint64_t background_abc_batches{0};

    [[nodiscard]] bool IsStale() const
    {
        return (best_header - active_height) > node::CHAIN_STALE_BEHIND_HEADERS;
    }

    [[nodiscard]] int ReservedActiveCapacity() const
    {
        return kBudget - inflight_background;
    }

    void CompleteInflight()
    {
        if (inflight_active > 0) {
            --inflight_active;
            ++active_height;
            ++active_connected;
        }
        if (inflight_background > 0 && historical_body_available) {
            --inflight_background;
            ++background_height;
            ++background_connected;
        }
    }

    void AllocateDownloads()
    {
        const int remaining{std::max(0, kBudget - inflight_active - inflight_background)};
        const int active_want{std::max(0, best_header - active_height - inflight_active)};
        const int active_queued{std::min(remaining, active_want)};
        const int extra_bg{BackgroundSnapshotAdditionalSlots(
            remaining, active_queued, inflight_background, inflight_background,
            active_height, best_header)};
        inflight_active += active_queued;
        inflight_background += extra_bg;
    }

    void MaybeBackgroundAbc()
    {
        const bool pending{best_header > active_height};
        const bool timeout_expired{
            yield_since != 0 &&
            now >= yield_since + node::BACKGROUND_ACTIVATION_YIELD_TIMEOUT_SECONDS};
        const bool yield{node::ShouldYieldBackgroundActivationToActiveTip(
            /*background_sync=*/true, IsStale(),
            /*active_behind_with_pending_work=*/pending, timeout_expired)};
        if (yield) {
            if (yield_since == 0) yield_since = now;
            ++background_yields;
            return;
        }
        yield_since = 0;
        ++background_abc_batches;
        if (historical_body_available && background_height < kSnapshotBase) {
            ++background_height;
            ++background_connected;
        }
    }

    void Round(int announce_active, bool release_historical)
    {
        if (release_historical) historical_body_available = true;
        best_header += announce_active;
        CompleteInflight();
        AllocateDownloads();
        MaybeBackgroundAbc();
        ++now;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(two_invariant_reserved_capacity_and_background_progress)
{
    // Dual chainstate under simulated peer scarcity (one full-NODE_NETWORK
    // peer, 2 inflight slots). Stall background on a missing historical body,
    // then announce active-tip headers and later release the historical
    // bodies. Both invariants must hold: the active tip keeps reserved
    // capacity and never goes is_stale, AND background still makes forward
    // progress (the property a height-gate deadlock would fail).
    DualChainstateSim sim;

    BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
        true, false, false, sim.active_height, sim.best_header));

    // Stall: historical body missing. Background still gets the floor of 1.
    sim.Round(/*announce_active=*/0, /*release_historical=*/false);
    BOOST_CHECK_EQUAL(sim.inflight_background, 1);
    BOOST_CHECK_GE(sim.ReservedActiveCapacity(), 1);
    BOOST_CHECK(!sim.IsStale());
    BOOST_CHECK_EQUAL(sim.background_connected, 0);

    // Announce six active-tip headers one per round (would go is_stale if
    // background occupied both scarce slots). Active keeps the reserved slot.
    for (int i = 0; i < node::CHAIN_STALE_BEHIND_HEADERS; ++i) {
        sim.Round(/*announce_active=*/1, /*release_historical=*/false);
        BOOST_CHECK_MESSAGE(!sim.IsStale(),
                            "active tip went is_stale while background held "
                            "the scarce inflight window");
        BOOST_CHECK_GE(sim.ReservedActiveCapacity(), 1);
        BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
            true, false, false, sim.active_height, sim.best_header));
    }
    BOOST_CHECK_GE(sim.active_connected, 1);
    BOOST_CHECK_EQUAL(sim.inflight_background, 1);
    BOOST_CHECK_EQUAL(sim.background_connected, 0);

    // Release historical bodies while more tip blocks are announced.
    const int bg_before{sim.background_height};
    for (int i = 0; i < 6; ++i) {
        sim.Round(/*announce_active=*/1, /*release_historical=*/true);
        BOOST_CHECK(!sim.IsStale());
        BOOST_CHECK(ShouldFetchBackgroundSnapshotBlocks(
            true, false, false, sim.active_height, sim.best_header));
    }
    BOOST_CHECK_GT(sim.background_height, bg_before);
    BOOST_CHECK_GT(sim.background_connected, 0);
    BOOST_CHECK_GT(sim.active_connected, 0);
    BOOST_CHECK(!sim.IsStale());

    // Timeout expired: even while the active chain was behind, background
    // ABC was allowed to run (bounded resume, not a height-gate deadlock).
    BOOST_CHECK_GT(sim.background_abc_batches, 0);
}

BOOST_AUTO_TEST_CASE(uncapped_background_would_starve_active_tip)
{
    // Control: the same scarcity window without the share cap fills both
    // slots with background and the active tip goes is_stale. Documents
    // why asserting only background progress is not enough.
    constexpr int kBudget{2};
    int active_height{110};
    int best_header{110};
    int inflight_bg{0};
    int inflight_active{0};

    auto leftover = [&] {
        return std::max(0, kBudget - inflight_active - inflight_bg);
    };
    // First pass, no active announcements: uncapped leftover all goes to bg.
    inflight_bg = leftover();
    BOOST_CHECK_EQUAL(inflight_bg, 2);

    for (int i = 0; i < node::CHAIN_STALE_BEHIND_HEADERS + 1; ++i) {
        ++best_header;
        const int remaining{leftover()};
        const int active_want{best_header - active_height - inflight_active};
        inflight_active += std::min(remaining, std::max(0, active_want));
    }
    BOOST_CHECK_EQUAL(inflight_active, 0);
    BOOST_CHECK_GT(best_header - active_height, node::CHAIN_STALE_BEHIND_HEADERS);
}

BOOST_AUTO_TEST_SUITE_END()
