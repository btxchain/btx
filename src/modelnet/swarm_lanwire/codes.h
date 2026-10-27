// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LANWIRE_CODES_H
#define BITCOIN_MODELNET_SWARM_LANWIRE_CODES_H

namespace modelnet {

/** An empty Exchange payload. No socket is opened. */
inline constexpr char kSwarmLanWirePayload[] = "PAYLOAD";

/** Wan has no route. No socket is opened. */
inline constexpr char kSwarmLanWireNoRoute[] = "NO_ROUTE";

/** Scan does not send. */
inline constexpr char kSwarmLanWireNotScan[] = "NOT_SCAN";

/** socket or close failed. The descriptor is not left open. */
inline constexpr char kSwarmLanWireSocket[] = "SOCKET";

/** bind to 127.0.0.1 failed. The descriptor is closed. */
inline constexpr char kSwarmLanWireBind[] = "BIND";

/** getsockname did not yield a 127.0.0.1 port. Nothing is sent. */
inline constexpr char kSwarmLanWirePort[] = "PORT";

/** The datagram was not sent. The descriptor is closed. */
inline constexpr char kSwarmLanWireSend[] = "SEND";

/** The datagram was not received before the timeout. The descriptor is closed. */
inline constexpr char kSwarmLanWireRecv[] = "RECV";

/** Received bytes differ from the payload. Nothing is stored. */
inline constexpr char kSwarmLanWireBytes[] = "BYTES";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LANWIRE_CODES_H
