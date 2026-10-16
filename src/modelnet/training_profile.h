// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRAINING_PROFILE_H
#define BITCOIN_MODELNET_TRAINING_PROFILE_H

#include <modelnet/training_evidence.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

// Toy fixture: a fixed byte loop, not a production model and not a claim of scientific quality.

inline constexpr char REFERENCE_PROFILE_NAME[] = "EXACT_CHECKS";
inline constexpr char REFERENCE_RNG[] = "fixture-rng";
inline constexpr char REFERENCE_OPTIMIZER[] = "fixture-optimizer";
inline constexpr char REFERENCE_DATA_CURSOR[] = "fixture-data-cursor";
inline constexpr char FIXTURE_ANCESTRY[] = "fixture-root";
inline constexpr char FIXTURE_START_STATE[] = "s0";
inline constexpr char FIXTURE_FINAL_STATE[] = "s4";
inline constexpr uint64_t FIXTURE_STEP_COUNT = 4;

/** Frozen inputs for the reference fixture. name must stay EXACT_CHECKS. */
struct ReferenceProfile {
    std::string name;
    std::string rng;
    std::string optimizer;
    std::string data_cursor;
};

/** One byte of the fixture loop. covered stays false when the profile is rejected. */
struct FixtureStep {
    uint64_t index{0};
    unsigned char byte{0};
    bool covered{false};
};

/**
 * Accepted runs carry intervals covering [0, FIXTURE_STEP_COUNT) from s0 to s4.
 * A rejected run leaves steps unmarked and intervals empty.
 */
struct FixtureResult {
    bool ok{false};
    std::string code;
    std::string start_state;
    std::string final_state;
    std::vector<FixtureStep> steps;
    std::vector<Interval> intervals;
};

ReferenceProfile FrozenReferenceProfile();

/**
 * Four deterministic byte updates over the ASCII string "btx-035-fixture".
 * A profile name other than EXACT_CHECKS fails BTX035_PROFILE. A rng,
 * optimizer, or data_cursor other than the frozen values fails BTX035_RNG
 * before any step is marked covered.
 */
FixtureResult RunReferenceFixture(const ReferenceProfile& profile);

/** Negative path: frozen profile with rng changed, so RunReferenceFixture rejects it. */
FixtureResult MutatedRngRejected();

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRAINING_PROFILE_H
