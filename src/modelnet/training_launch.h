// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRAINING_LAUNCH_H
#define BITCOIN_MODELNET_TRAINING_LAUNCH_H

#include <modelnet/training_evidence.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Frozen launch profile from planning/launch_profile.json.
 * Two-layer causal byte-token decoder: vocabulary 256, context 64, width 64,
 * four heads, feed-forward 128, no dropout, SGD without momentum.
 * The mandatory lane is CPU_SERIAL_FROZEN_BUILD. This is not a CUDA profile
 * and it is not the INTEGER_LINEAR fixture.
 *
 * Arithmetic lock, fixed before the first trajectory:
 *   activations are int32 with scale 32
 *   L1_NORM_V1, INTEGER_SOFTMAX_V1 (scores clipped to [-8, 8]), RELU_FF_V1
 *   weights stay in [-64, 64]; a step subtracts a gradient clipped to [-4, 4]
 */
inline constexpr char LAUNCH_PROFILE[] = "BTX035-LAUNCH-DECODER-2x64";
inline constexpr uint64_t LAUNCH_STEPS = 1024;
inline constexpr uint64_t LAUNCH_CONTINUE_STEPS = 64;
inline constexpr char LAUNCH_CORPUS_SHA384[] =
    "03b84076bcfa451ebcf45bb1613ba15f12167b823813a898bab6753ca62a70ea6dd45cef894a77078ba6e2e1d5f1beb3";

struct LaunchCheckpoint {
    uint64_t step{0};
    uint64_t cursor{0};
    std::string rng{"0"};
    std::string optimizer{"SGD_WITHOUT_MOMENTUM"};
    std::string weight_hash;
    std::string state_hash;
    /** Empty on a run from initialization. A continuation names the parent hash. */
    std::string inherited_state;
    uint64_t inherited_step{0};
    int64_t hits{0};
    int64_t miss_mass{0};
};

class LaunchTrainer {
public:
    const LaunchCheckpoint& Checkpoint() const { return m_published; }
    const std::vector<Interval>& Intervals() const { return m_intervals; }
    const std::vector<int32_t>& Weights() const { return m_weights; }

    /** Train `steps` more updates from the current weights. */
    bool Run(uint64_t steps, std::string& err);

    /**
     * Replay `checkpoint` from initialization. step == 0 is BTX035_NOT_RESUMABLE.
     * A cursor or rng that is not the recomputed value is BTX035_RNG.
     * An optimizer, weight, or hash mismatch is BTX035_ID_MISMATCH.
     */
    static bool CheckState(const LaunchCheckpoint& checkpoint, std::string& err);

    /** Continue a checkpoint that CheckState accepts. Further Run() calls inherit it. */
    bool Resume(const LaunchCheckpoint& checkpoint, std::string& err);

    bool ReplayMatches(const LaunchCheckpoint& published, std::string& err) const;

private:
    void Publish();

    std::vector<int32_t> m_weights;
    uint64_t m_step{0};
    uint64_t m_cursor{0};
    int64_t m_hits{0};
    int64_t m_miss{0};
    std::string m_inherited_state;
    uint64_t m_inherited_step{0};
    LaunchCheckpoint m_published;
    std::vector<Interval> m_intervals;
};

/** Frozen corpus bytes. The digest is the git blob id of these bytes. */
std::string LaunchCorpusBytes();
/** Byte-token recipe. Vocabulary is 256. */
std::string LaunchTokenizerBytes();

/** Git blob id of the frozen corpus. */
bool LaunchDatasetDigest(std::string& digest, std::string& err);

/** Git blob id of the byte-token recipe. Vocabulary is 256. */
bool LaunchTokenizerDigest(std::string& digest, std::string& err);

/** Canonical model bytes a peer can rehash. The line names the weight hash.
 *  The weights themselves are the replay, so the piece set stays small. Not a quality claim. */
bool EncodeLaunchArtifact(const LaunchCheckpoint& checkpoint, const std::vector<int32_t>& weights,
                          std::string& bytes, std::string& err);

/** One snapshot line. A v1 integer train line does not decode as this. */
bool EncodeLaunchLine(const std::string& trajectory_id, const LaunchCheckpoint& checkpoint,
                      std::string& line, std::string& err);
bool DecodeLaunchLine(const std::string& line, std::string& trajectory_id, LaunchCheckpoint& checkpoint,
                      std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRAINING_LAUNCH_H
