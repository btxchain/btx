// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFWORK_CODES_H
#define BITCOIN_MODELNET_SWARM_DEFWORK_CODES_H

namespace modelnet {

/** The level is not D0, D1, D2, D3, or D4. Nothing is stored. */
inline constexpr char kSwarmDefWorkLevel[] = "LEVEL";

/** The case, action, or asset is empty, or the action is unknown. */
inline constexpr char kSwarmDefWorkAction[] = "ACTION";

/** blast is negative. Nothing is stored. */
inline constexpr char kSwarmDefWorkBlast[] = "BLAST";

/** D3 is proposed and still needs a human, or human was false. */
inline constexpr char kSwarmDefWorkNeedApproval[] = "NEED_APPROVAL";

/** D4 is prohibited. Nothing is stored and it cannot execute. */
inline constexpr char kSwarmDefWorkRefused[] = "REFUSED";

/** The action was already proposed, already approved, or already executed. */
inline constexpr char kSwarmDefWorkReplay[] = "REPLAY";

/** The case, asset, or blast does not match the stored proposal. Nothing executes. */
inline constexpr char kSwarmDefWorkPrecondition[] = "PRECONDITION";

/** An external result was unknown. Execute does not retry. */
inline constexpr char kSwarmDefWorkAmbiguous[] = "AMBIGUOUS";

/** The canary failed, or the action is already rolled back. */
inline constexpr char kSwarmDefWorkRollback[] = "ROLLBACK";

/** The call is outside this broker. Nothing is stored. */
inline constexpr char kSwarmDefWorkOutOfScope[] = "OUT_OF_SCOPE";

/** Risk class D0. Propose stores it and returns true. */
inline constexpr char kSwarmDefWorkD0[] = "D0";

/** Risk class D1. Propose stores it and returns true. */
inline constexpr char kSwarmDefWorkD1[] = "D1";

/** Risk class D2. Propose stores it and returns true. */
inline constexpr char kSwarmDefWorkD2[] = "D2";

/** Risk class D3. Propose stores it and returns false until a human approves. */
inline constexpr char kSwarmDefWorkD3[] = "D3";

/** Risk class D4. Propose stores nothing. */
inline constexpr char kSwarmDefWorkD4[] = "D4";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFWORK_CODES_H
