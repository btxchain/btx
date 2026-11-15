// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_CODES_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_CODES_H

namespace modelnet {

/** worker is empty. Nothing is stored. */
inline constexpr char kSwarmSandboxGateWorker[] = "WORKER";

/** path_prefix is empty. Nothing is stored. */
inline constexpr char kSwarmSandboxGatePath[] = "PATH";

/** until_ms is below 0. Nothing is stored. */
inline constexpr char kSwarmSandboxGateTimeout[] = "TIMEOUT";

/** The capability list or the capability name is empty. Nothing is stored. */
inline constexpr char kSwarmSandboxGateCapability[] = "CAPABILITY";

/** This worker and path_prefix are already stored. The first grant stays. */
inline constexpr char kSwarmSandboxGateReplay[] = "REPLAY";

/** The worker has no stored grant. */
inline constexpr char kSwarmSandboxGateNotGranted[] = "NOT_GRANTED";

/** now_ms is at or past until_ms. The action is not recorded. */
inline constexpr char kSwarmSandboxGateExpired[] = "EXPIRED";

/** No stored prefix is a strict bytewise prefix of the path. */
inline constexpr char kSwarmSandboxGateDenied[] = "DENIED";

/** The path begins with the private prefix. Nothing is recorded. */
inline constexpr char kSwarmSandboxGatePrivateData[] = "PRIVATE_DATA";

/** No live matching grant lists the capability. Nothing is recorded. */
inline constexpr char kSwarmSandboxGateNotActed[] = "NOT_ACTED";

/** host_id is empty. This is not a connection. */
inline constexpr char kSwarmSandboxGateNet[] = "NET";

/** The worker has no network grant. This is not a connection. */
inline constexpr char kSwarmSandboxGateNetDenied[] = "NET_DENIED";

/** Run does not start a sandbox. launched stays false. */
inline constexpr char kSwarmSandboxGateSandboxAbsent[] = "SANDBOX_ABSENT";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_CODES_H
