// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_CODES_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_CODES_H

namespace modelnet {

/** session or model_id is empty. Nothing is stored. */
inline constexpr char kSwarmTokenGateModel[] = "MODEL";

/** The same session, engine name, or public prompt is already stored. The first value stays. */
inline constexpr char kSwarmTokenGateReplay[] = "REPLAY";

/** The session is not open. Nothing is stored. */
inline constexpr char kSwarmTokenGateSession[] = "SESSION";

/** engine_name is empty or not a catalog name. Nothing is stored. */
inline constexpr char kSwarmTokenGateEngine[] = "ENGINE";

/** The prompt is private. Nothing is stored. */
inline constexpr char kSwarmTokenGatePrivateData[] = "PRIVATE_DATA";

/** The public prompt is empty. Nothing is stored. */
inline constexpr char kSwarmTokenGatePrompt[] = "PROMPT";

/** A different public prompt or a different catalog engine is already held. The first value stays. */
inline constexpr char kSwarmTokenGateHeld[] = "HELD";

/** Decode does not run an engine. tokens stay 0 and generated text stays empty. */
inline constexpr char kSwarmTokenGateEngineAbsent[] = "ENGINE_ABSENT";

/** Measure does not record a latency. ttft, p50, and p95 stay -1. measured stays false. */
inline constexpr char kSwarmTokenGateNotMeasured[] = "NOT_MEASURED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_CODES_H
