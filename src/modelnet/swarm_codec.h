// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CODEC_H
#define BITCOIN_MODELNET_SWARM_CODEC_H

#include <map>
#include <string>
#include <string_view>

namespace modelnet {

/** Canonical JSON object of string fields, keys sorted, no extra whitespace. */
std::string SwarmCanonical(const std::map<std::string, std::string>& fields);

/** SHA-384 hex of domain || 0x00 || canonical body. */
std::string SwarmDigest(std::string_view domain, std::string_view canonical);

bool SwarmFixedId(std::string_view id);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CODEC_H
