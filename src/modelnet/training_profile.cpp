// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/training_profile.h>

#include <string>
#include <string_view>

namespace modelnet {
namespace {

constexpr char FIXTURE_TEXT[] = "btx-035-fixture";

std::string StepState(uint64_t index)
{
    return "s" + std::to_string(index);
}

} // namespace

ReferenceProfile FrozenReferenceProfile()
{
    ReferenceProfile profile;
    profile.name = REFERENCE_PROFILE_NAME;
    profile.rng = REFERENCE_RNG;
    profile.optimizer = REFERENCE_OPTIMIZER;
    profile.data_cursor = REFERENCE_DATA_CURSOR;
    return profile;
}

FixtureResult RunReferenceFixture(const ReferenceProfile& profile)
{
    FixtureResult result;
    Interval probe;
    probe.profile = profile.name;
    probe.rng = profile.rng;
    probe.optimizer = profile.optimizer;
    probe.data_cursor = profile.data_cursor;
    probe.ancestry = FIXTURE_ANCESTRY;
    probe.publisher_only = false;
    std::string err;
    if (!AcceptInterval(probe, REFERENCE_RNG, REFERENCE_OPTIMIZER, REFERENCE_DATA_CURSOR, err)) {
        result.code = err;
        return result;
    }

    unsigned char acc = 0;
    result.steps.reserve(FIXTURE_STEP_COUNT);
    result.intervals.reserve(FIXTURE_STEP_COUNT);
    for (uint64_t step = 0; step < FIXTURE_STEP_COUNT; ++step) {
        for (const char ch : std::string_view{FIXTURE_TEXT}) {
            acc = static_cast<unsigned char>(acc + static_cast<unsigned char>(ch) + static_cast<unsigned char>(step + 1));
        }
        FixtureStep recorded;
        recorded.index = step;
        recorded.byte = acc;
        recorded.covered = true;
        result.steps.push_back(recorded);

        Interval interval = probe;
        interval.start_inclusive = step;
        interval.end_exclusive = step + 1;
        interval.start_state = StepState(step);
        interval.end_state = StepState(step + 1);
        result.intervals.push_back(std::move(interval));
    }
    result.ok = true;
    result.start_state = FIXTURE_START_STATE;
    result.final_state = FIXTURE_FINAL_STATE;
    return result;
}

FixtureResult MutatedRngRejected()
{
    ReferenceProfile profile = FrozenReferenceProfile();
    profile.rng += "-mutated";
    return RunReferenceFixture(profile);
}

} // namespace modelnet
