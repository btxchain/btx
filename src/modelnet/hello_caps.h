// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HELLO_CAPS_H
#define BITCOIN_MODELNET_HELLO_CAPS_H

#include <univalue.h>

#include <string>

namespace modelnet {

/** Advertised hello capabilities: array of {name, min, max} (version range). */
UniValue HelloCapabilityArray();
/** True if hello advertises `name`. Accepts string entries and {name,min,max} objects. */
bool HelloHasCapability(const UniValue& hello, const std::string& name);
/** Name from a legacy string entry or an object with a string "name" field. */
bool HelloCapabilityEntryName(const UniValue& entry, std::string& name);
/** Clamp advertised {name,min,max} against a peer hello. Empty intersection drops the name. */
UniValue IntersectHelloCapabilities(const UniValue& local, const UniValue& remote);
/** Advertise local {name,min,max}. If `peer` carries a capabilities array, return the intersection. */
UniValue HelloCapabilityArrayMaybeIntersect(const UniValue& peer);

} // namespace modelnet

#endif // BITCOIN_MODELNET_HELLO_CAPS_H
