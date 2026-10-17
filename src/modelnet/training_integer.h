// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRAINING_INTEGER_H
#define BITCOIN_MODELNET_TRAINING_INTEGER_H

#include <modelnet/training_evidence.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Deterministic integer linear profile. This is not the EXACT_CHECKS byte fixture. */
inline constexpr char INTEGER_PROFILE[] = "INTEGER_LINEAR";

/**
 * Same transitions as INTEGER_LINEAR, plus a canonical artifact a peer can rehash.
 * This is still not a language-model benchmark.
 */
inline constexpr char INTEGER_MODEL_PROFILE[] = "INTEGER_MODEL";

struct IntegerExample {
    int32_t x{0};
    int32_t y{0};
};

/**
 * Full trainer state. state_hash covers the weights, both momentum terms,
 * the data cursor, and the step index. A file hash of the final weights
 * alone is not this commitment.
 */
struct IntegerState {
    int64_t weight{0};
    int64_t bias{0};
    int64_t momentum_w{0};
    int64_t momentum_b{0};
    uint64_t cursor{0};
    uint64_t step{0};
    std::string state_hash;
};

struct IntegerRun {
    bool ok{false};
    std::string code;
    IntegerState state;
    std::vector<Interval> intervals;
};

/** Eight frozen pairs. The trainer never fetches a name for them. */
const std::vector<IntegerExample>& IntegerDataset();

/** SHA-384 of the canonical state line. */
std::string IntegerStateHash(const IntegerState& state);

/**
 * Most steps one integer trainer runs, counting the steps of a resumed
 * checkpoint. A lab run is IntegerDataset().size() == 8 steps; the cap
 * matches LaunchTrainer's 4096.
 */
inline constexpr uint64_t INTEGER_MAX_STEPS = 4096;

class IntegerTrainer {
public:
    IntegerTrainer() = default;

    const IntegerState& State() const { return m_state; }
    const std::vector<Interval>& Intervals() const { return m_intervals; }

    /** One committed step. The first call starts from the zero state. */
    bool Step(std::string& err);

    /**
     * Run exactly `steps` updates from the current state. A total past
     * INTEGER_MAX_STEPS is BTX035_LIMIT_EXCEEDED and runs nothing.
     */
    bool Run(uint64_t steps, std::string& err);

    /**
     * Continue a committed checkpoint. step == 0 is NOT_RESUMABLE and does
     * not change this object. A checkpoint whose hash does not match a
     * replay of its own step is BTX035_ID_MISMATCH.
     */
    bool Resume(const IntegerState& checkpoint, std::string& err);

    /** Replay from zero and require the same final hash. */
    bool ReplayMatches(const IntegerState& published, std::string& err) const;

    /**
     * Recompute `published.step` updates. A cursor that is not the recomputed
     * cursor is BTX035_RNG. A weight, bias, or momentum mismatch is
     * BTX035_ID_MISMATCH. An empty hash is BTX035_ID_MISMATCH. A step past
     * INTEGER_MAX_STEPS is BTX035_LIMIT_EXCEEDED before any replay.
     */
    static bool CheckState(const IntegerState& published, std::string& err);

private:
    IntegerState m_state;
    std::vector<Interval> m_intervals;
};

/**
 * One line: v1|INTEGER_MODEL|<weight>|<bias>|<momentum_w>|<momentum_b>|<cursor>|<step>|<state_hash>
 * A peer rehashes these bytes. The line is not a model-quality claim.
 */
bool EncodeModelArtifact(const IntegerState& state, std::string& bytes, std::string& err);

/**
 * Most pieces one model may have; valid indexes are 0 to MODEL_MAX_PIECES - 1.
 * At 32 bytes a piece this is 128 KiB. The lab's own model artifacts are one
 * line of a few hundred bytes, and lab.artifact_acquire stops at this count.
 */
inline constexpr size_t MODEL_MAX_PIECES = 4096;

/** Split into 32-byte chunks. The last chunk may be shorter. */
bool SplitModelPieces(const std::string& bytes, std::vector<std::string>& pieces, std::string& err);

/** Join chunks in order. A short chunk is allowed only as the last piece. */
bool JoinModelPieces(const std::vector<std::string>& pieces, std::string& bytes, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRAINING_INTEGER_H
