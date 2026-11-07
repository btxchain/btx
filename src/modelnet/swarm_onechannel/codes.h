// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_CODES_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_CODES_H

namespace modelnet {

/** Empty channel id, or a pool bind before any channel is reserved. Nothing new is stored. */
inline constexpr char SWARM_ONECHANNEL_CHANNEL[] = "CHANNEL";

/** The same channel was reserved again, or the same pool was bound again. The first value stays. */
inline constexpr char SWARM_ONECHANNEL_REPLAY[] = "REPLAY";

/** A second channel id, or any network open. The first channel id stays. The network stays closed. */
inline constexpr char SWARM_ONECHANNEL_NOT_OPENED[] = "NOT_OPENED";

/** Empty pool, or a pool that is not bound to the reserved channel. Nothing new is stored. */
inline constexpr char SWARM_ONECHANNEL_POOL[] = "POOL";

/** Funding was asked for without a refund bound. The pool is not marked funded. */
inline constexpr char SWARM_ONECHANNEL_FUNDING[] = "FUNDING";

/** A quote was asked for with an empty usd string. Nothing is stored. */
inline constexpr char SWARM_ONECHANNEL_QUOTE[] = "QUOTE";

/** A non-empty usd string was stored and is not an atom balance. holds_money stays as it was. */
inline constexpr char SWARM_ONECHANNEL_NOT_BALANCE[] = "NOT_BALANCE";

static_assert(sizeof(SWARM_ONECHANNEL_CHANNEL) == 8, "CHANNEL");
static_assert(sizeof(SWARM_ONECHANNEL_REPLAY) == 7, "REPLAY");
static_assert(sizeof(SWARM_ONECHANNEL_NOT_OPENED) == 11, "NOT_OPENED");
static_assert(sizeof(SWARM_ONECHANNEL_POOL) == 5, "POOL");
static_assert(sizeof(SWARM_ONECHANNEL_FUNDING) == 8, "FUNDING");
static_assert(sizeof(SWARM_ONECHANNEL_QUOTE) == 6, "QUOTE");
static_assert(sizeof(SWARM_ONECHANNEL_NOT_BALANCE) == 12, "NOT_BALANCE");
static_assert(SWARM_ONECHANNEL_CHANNEL[0] == 'C', "channel code");
static_assert(SWARM_ONECHANNEL_REPLAY[0] == 'R', "replay code");
static_assert(SWARM_ONECHANNEL_NOT_OPENED[0] == 'N', "not opened code");
static_assert(SWARM_ONECHANNEL_POOL[0] == 'P', "pool code");
static_assert(SWARM_ONECHANNEL_FUNDING[0] == 'F', "funding code");
static_assert(SWARM_ONECHANNEL_QUOTE[0] == 'Q', "quote code");
static_assert(SWARM_ONECHANNEL_NOT_BALANCE[0] == 'N', "not balance code");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_CODES_H
