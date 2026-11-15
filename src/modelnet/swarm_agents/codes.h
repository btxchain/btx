// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_CODES_H
#define BTX_MODELNET_SWARM_AGENTS_CODES_H

namespace modelnet {

inline constexpr char kAgentTask[] = "TASK";
inline constexpr char kAgentDep[] = "DEP";
inline constexpr char kAgentCycle[] = "CYCLE";
inline constexpr char kAgentReplay[] = "REPLAY";
inline constexpr char kAgentConflict[] = "CONFLICT";
inline constexpr char kAgentNetwork[] = "NETWORK";
inline constexpr char kAgentHost[] = "HOST";
inline constexpr char kAgentCapped[] = "CAPPED";
inline constexpr char kAgentEscape[] = "ESCAPE";
inline constexpr char kAgentUnknown[] = "UNKNOWN";
inline constexpr char kAgentExpired[] = "EXPIRED";
inline constexpr char kAgentStaleEpoch[] = "STALE_EPOCH";
inline constexpr char kAgentRange[] = "RANGE";
inline constexpr char kAgentTrace[] = "TRACE";
inline constexpr char kAgentHash[] = "HASH";
inline constexpr char kAgentNotReady[] = "NOT_READY";
inline constexpr char kAgentCancelled[] = "CANCELLED";
inline constexpr char kAgentCommitted[] = "COMMITTED";
inline constexpr char kAgentAgent[] = "AGENT";
inline constexpr char kAgentLease[] = "LEASE";
inline constexpr char kAgentInteger[] = "INTEGER";
inline constexpr char kAgentConsumer[] = "CONSUMER";

inline constexpr char kAgentEventCommit[] = "commit";
inline constexpr char kAgentEventCancel[] = "cancel";
inline constexpr char kAgentKindHold[] = "hold";
inline constexpr char kAgentKindIntegerStep[] = "integer-step";

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_CODES_H
