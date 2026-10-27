// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROGRESS_CODES_H
#define BITCOIN_MODELNET_SWARM_PROGRESS_CODES_H

namespace modelnet {

/** An empty id. Nothing is stored and the recipe is unchanged. */
inline constexpr char kSwarmProgressWork[] = "WORK";

/** loss_ppm < 0 or step < 0. Nothing is stored. */
inline constexpr char kSwarmProgressSample[] = "SAMPLE";

/**
 * The same loss_ppm and step again, or the same loss_ppm with a lower step.
 * Nothing new is stored. This is not a correction trigger.
 */
inline constexpr char kSwarmProgressReplay[] = "REPLAY";

/**
 * same_count < 3, or no sample is stored.
 * correcting() is not set. killed() stays false.
 */
inline constexpr char kSwarmProgressPlateau[] = "PLATEAU";

/** Correct while correcting() is false. The recipe is unchanged. */
inline constexpr char kSwarmProgressNotCorrecting[] = "NOT_CORRECTING";

/** A recipe that differs from the stored recipe. The stored recipe stays. */
inline constexpr char kSwarmProgressSecret[] = "SECRET";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROGRESS_CODES_H
