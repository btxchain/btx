// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFENSE_CODES_H
#define BITCOIN_MODELNET_SWARM_DEFENSE_CODES_H

namespace modelnet {

/** An empty customer, case, asset, or policy generation. Nothing is stored. */
inline constexpr char kSwarmDefenseMandate[] = "MANDATE";

/** now_ms >= until_ms, including equality. Nothing is stored. */
inline constexpr char kSwarmDefenseExpired[] = "EXPIRED";

/** The case or evidence id is already stored. The first record stays. */
inline constexpr char kSwarmDefenseReplay[] = "REPLAY";

/** The peer id is empty. Nothing is stored. */
inline constexpr char kSwarmDefensePeer[] = "PEER";

/** The case has no stored mandate. Nothing is stored. */
inline constexpr char kSwarmDefenseCase[] = "CASE";

/** The peer is not in the family. Admission is not stored. */
inline constexpr char kSwarmDefenseNotAdmitted[] = "NOT_ADMITTED";

/** The evidence id is empty, the bytes are empty, or the id is not in this case. */
inline constexpr char kSwarmDefenseEvidence[] = "EVIDENCE";

/** Export was not granted. No bytes are copied. */
inline constexpr char kSwarmDefensePrivateData[] = "PRIVATE_DATA";

/** Model text is not an instruction. Nothing is executed. */
inline constexpr char kSwarmDefenseNotAuthorized[] = "NOT_AUTHORIZED";

/** Sanitization and independent validation were not both present. Nothing is stored. */
inline constexpr char kSwarmDefenseNotPublished[] = "NOT_PUBLISHED";

/** The evidence id is absent or belongs to another case. Both answers use this code. */
inline constexpr char kSwarmDefenseNotVisible[] = "NOT_VISIBLE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFENSE_CODES_H
