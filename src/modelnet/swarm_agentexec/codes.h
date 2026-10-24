// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_CODES_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_CODES_H

namespace modelnet {

/** prefix is empty. Nothing is stored. */
inline constexpr char kSwarmAgentExecPath[] = "PATH";

/** This prefix, or this path and payload, was already accepted. The first stays. */
inline constexpr char kSwarmAgentExecReplay[] = "REPLAY";

/** tool is empty, or it is not the in-process sha256 tool. Nothing is stored. */
inline constexpr char kSwarmAgentExecTool[] = "TOOL";

/** tool is net. This is not a connection. ran() is not set by this call. */
inline constexpr char kSwarmAgentExecNetDenied[] = "NET_DENIED";

/** path begins with the bytes private/. Nothing is stored. */
inline constexpr char kSwarmAgentExecPrivateData[] = "PRIVATE_DATA";

/** path does not begin with a stored Allow prefix. Nothing is stored. */
inline constexpr char kSwarmAgentExecDenied[] = "DENIED";

/** payload is empty. The sha256 tool does not run. ran() is not set by this call. */
inline constexpr char kSwarmAgentExecPayload[] = "PAYLOAD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_CODES_H
