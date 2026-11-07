// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_CODES_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_CODES_H

namespace modelnet {

/** Empty task id, or a task that was never stored. Nothing is stored. */
inline constexpr char kAgentRunTask[] = "TASK";

/** Parent is non-empty and is not already a task. Nothing is stored. */
inline constexpr char kAgentRunDependency[] = "DEPENDENCY";

/** The id, lease, assignment, receipt, branch, tool, or cancel is already stored. */
inline constexpr char kAgentRunReplay[] = "REPLAY";

/** Worker is empty. The lease is not stored. */
inline constexpr char kAgentRunWorker[] = "WORKER";

/** Epoch is below 0. The lease is not stored. */
inline constexpr char kAgentRunEpoch[] = "EPOCH";

/** now_ms is at or after until_ms. The lease is not stored. */
inline constexpr char kAgentRunExpired[] = "EXPIRED";

/** Assignment worker and epoch do not match the stored lease. Nothing is assigned. */
inline constexpr char kAgentRunFence[] = "FENCE";

/** Receipt is empty. Nothing is stored. */
inline constexpr char kAgentRunReceipt[] = "RECEIPT";

/** Task is unknown or has no assignment. The receipt is not stored. */
inline constexpr char kAgentRunNotAssigned[] = "NOT_ASSIGNED";

/** Receipt differs from the receipt already stored. The first receipt stays. */
inline constexpr char kAgentRunConflict[] = "CONFLICT";

/** At least one lease is stored. LeaderGone deletes nothing. */
inline constexpr char kAgentRunDurable[] = "DURABLE";

/** No lease is stored. LeaderGone deletes nothing. */
inline constexpr char kAgentRunLost[] = "LOST";

/** Branch id is empty, or the branch was never stored. */
inline constexpr char kAgentRunBranch[] = "BRANCH";

/** The branch task already has a receipt. The branch is dropped. The receipt stays. */
inline constexpr char kAgentRunDropped[] = "DROPPED";

/** Tool digest is empty. Nothing is stored. */
inline constexpr char kAgentRunTool[] = "TOOL";

/** Digest is private. Nothing is stored. */
inline constexpr char kAgentRunPrivateData[] = "PRIVATE_DATA";

/** Run refuses because no sandbox is present. Nothing is launched. */
inline constexpr char kAgentRunSandboxAbsent[] = "SANDBOX_ABSENT";

/** Trace name for a stored task. */
inline constexpr char kAgentRunEvAddTask[] = "AddTask";

/** Trace name for a stored lease. */
inline constexpr char kAgentRunEvLease[] = "Lease";

/** Trace name for a stored assignment. */
inline constexpr char kAgentRunEvAssign[] = "Assign";

/** Trace name for a stored receipt. */
inline constexpr char kAgentRunEvCommit[] = "CommitResult";

/** Trace name for a stored speculative branch. */
inline constexpr char kAgentRunEvSpeculate[] = "Speculate";

/** Trace name for a stored public tool digest. */
inline constexpr char kAgentRunEvTool[] = "ReuseTool";

/** Trace name for a stored cancel. */
inline constexpr char kAgentRunEvCancel[] = "Cancel";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_CODES_H
