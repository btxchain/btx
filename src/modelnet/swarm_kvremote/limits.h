// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVREMOTE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_KVREMOTE_LIMITS_H

namespace modelnet {

/** launched() stays this value. Nothing starts. */
inline constexpr bool kSwarmKvRemoteLaunched = false;

/** gpu() stays this value. No device is used. */
inline constexpr bool kSwarmKvRemoteGpu = false;

/** broadcast() stays this value. Nothing is published. */
inline constexpr bool kSwarmKvRemoteBroadcast = false;

/** automatic_spend() stays this value. Nothing is spent. */
inline constexpr char kSwarmKvRemoteAutomaticSpend[] = "0";

/**
 * Fingerprint Transfer stores on both slots.
 * One fingerprint makes the following memory move compatible.
 */
inline constexpr char kSwarmKvRemoteFingerprint[] = "fp";

static_assert(!kSwarmKvRemoteLaunched, "this plane does not launch");
static_assert(!kSwarmKvRemoteGpu, "this plane does not use a gpu");
static_assert(!kSwarmKvRemoteBroadcast, "this plane does not broadcast");
static_assert(kSwarmKvRemoteAutomaticSpend[0] == '0' && kSwarmKvRemoteAutomaticSpend[1] == '\0',
              "automatic spend stays 0");
static_assert(kSwarmKvRemoteFingerprint[0] != '\0', "transfer fingerprint is not empty");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVREMOTE_LIMITS_H
