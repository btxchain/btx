// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_CODEC_H
#define BITCOIN_MODELNET_SWARM_FORM_CODEC_H

#include <modelnet/swarm_form/types.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Compact JSON for a membership record. automatic_spend is the string "0". */
std::string EncodeMember(const SwarmFormMember& member);

/**
 * Parse a membership record. A spend value other than "0" is SPEND and out is unchanged.
 * Any other mismatch is SCHEMA and out is unchanged.
 */
bool DecodeMember(const std::string& raw, SwarmFormMember& out, std::string& err);

/** Compact JSON for the coordinator epoch. Leader may be empty. Epoch is at least 1. */
std::string EncodeElection(const std::string& leader, uint64_t epoch);

/**
 * Parse an election record. Epoch below 1 is SCHEMA. A spend value other than "0" is SPEND.
 * leader and epoch are unchanged on failure.
 */
bool DecodeElection(const std::string& raw, std::string& leader, uint64_t& epoch, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_CODEC_H
