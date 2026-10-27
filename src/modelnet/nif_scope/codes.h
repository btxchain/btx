// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_SCOPE_CODES_H
#define BITCOIN_MODELNET_NIF_SCOPE_CODES_H

namespace modelnet {

/** SetPolicy(LocalOnly) stores this label. It is also the label before SetPolicy. */
inline constexpr char kNifScopeLocalOnly[] = "LOCAL_ONLY";

/** SetPolicy(LanOnly) stores this label. */
inline constexpr char kNifScopeLanOnly[] = "LAN_ONLY";

/** SetPolicy(PeerNetwork) stores this label. */
inline constexpr char kNifScopePeerNetwork[] = "PEER_NETWORK";

/** ObserveBeacon refused an empty endpoint. Nothing is stored. */
inline constexpr char kNifScopeEndpoint[] = "ENDPOINT";

/** SendLocal refused an empty payload. Nothing is opened and nothing is stored. */
inline constexpr char kNifScopePayload[] = "PAYLOAD";

/** launched() stays this value. Nothing is started. */
inline constexpr bool kNifScopeLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kNifScopeGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kNifScopeBroadcast = false;

/** connected() stays this value. No socket is kept open. */
inline constexpr bool kNifScopeConnected = false;

/** granted() stays this value. A beacon is not permission. */
inline constexpr bool kNifScopeGranted = false;

static_assert(kNifScopeLocalOnly[0] == 'L', "local policy label");
static_assert(kNifScopeLanOnly[0] == 'L', "lan policy label");
static_assert(kNifScopePeerNetwork[0] == 'P', "peer policy label");
static_assert(kNifScopeEndpoint[0] == 'E', "empty endpoint code");
static_assert(kNifScopePayload[0] == 'P', "empty payload code");
static_assert(!kNifScopeLaunched, "this scope does not launch");
static_assert(!kNifScopeGpu, "this scope does not use a gpu");
static_assert(!kNifScopeBroadcast, "this scope does not broadcast");
static_assert(!kNifScopeConnected, "this scope does not stay connected");
static_assert(!kNifScopeGranted, "a beacon is not permission");

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_SCOPE_CODES_H
