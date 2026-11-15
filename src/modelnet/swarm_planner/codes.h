// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PLANNER_CODES_H
#define BITCOIN_MODELNET_SWARM_PLANNER_CODES_H

namespace modelnet {

/** View name is outside resource, work, topology, and evidence. Nothing is stored. */
inline constexpr char kSwarmPlannerView[] = "VIEW";

/** Id is empty, or an evidence id is unknown. Nothing is stored. */
inline constexpr char kSwarmPlannerId[] = "ID";

/** The same id, edge, event, or epoch was already stored. The first record stays. */
inline constexpr char kSwarmPlannerReplay[] = "REPLAY";

/** A dependency endpoint is absent from the work view. Nothing is stored. */
inline constexpr char kSwarmPlannerWork[] = "WORK";

/** The edge would cycle, or a stored cycle was walked. The edge is not stored and does not dispatch. */
inline constexpr char kSwarmPlannerCycle[] = "CYCLE";

/** A predecessor is unfinished. Dispatch does not proceed. */
inline constexpr char kSwarmPlannerBlocked[] = "BLOCKED";

/** Wake was given an empty event id. The outbox is unchanged. */
inline constexpr char kSwarmPlannerEvent[] = "EVENT";

/** Proposal epoch is older than the current epoch. The current body stays. */
inline constexpr char kSwarmPlannerStale[] = "STALE";

/** A work id depends on an evidence id that has been retracted. Dispatch does not proceed. */
inline constexpr char kSwarmPlannerInvalid[] = "INVALID";

/**
 * Search refused the id.
 * A disallowed search and an allowed search of an absent id both use this code.
 */
inline constexpr char kSwarmPlannerNotVisible[] = "NOT_VISIBLE";

/** Resource graph view. Ids here are distinct from the same ids in other views. */
inline constexpr char kSwarmPlannerResource[] = "resource";

/** Work graph view. Dependencies and dispatch use this view. */
inline constexpr char kSwarmPlannerWorkView[] = "work";

/** Topology graph view. Ids here are distinct from the same ids in other views. */
inline constexpr char kSwarmPlannerTopology[] = "topology";

/** Evidence graph view. Retract applies to ids in this view. */
inline constexpr char kSwarmPlannerEvidence[] = "evidence";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PLANNER_CODES_H
