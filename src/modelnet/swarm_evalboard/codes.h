// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_CODES_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_CODES_H

namespace modelnet {

/** Subject, author, or domain is empty. Nothing is stored. */
inline constexpr char kSwarmEvalReport[] = "REPORT";

/** The author is the subject. The score is not stored. */
inline constexpr char kSwarmEvalNotScored[] = "NOT_SCORED";

/** The report is not independent. It is not stored. */
inline constexpr char kSwarmEvalHeld[] = "HELD";

/** The report is not from a rotating author. It is not stored. */
inline constexpr char kSwarmEvalNotRotating[] = "NOT_ROTATING";

/** This author already scored the subject. The first score stays. */
inline constexpr char kSwarmEvalReplay[] = "REPLAY";

/** The score is outside 0..1000000. Nothing is stored. */
inline constexpr char kSwarmEvalRange[] = "RANGE";

/** Attach was asked for a subject that is not accepted. Nothing is attached. */
inline constexpr char kSwarmEvalAttach[] = "ATTACH";

/** A regression flag blocks attach. Stored scores stay. */
inline constexpr char kSwarmEvalRegression[] = "REGRESSION";

/** Graduation is refused. The active id stays base. */
inline constexpr char kSwarmEvalRealm[] = "REALM";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_CODES_H
