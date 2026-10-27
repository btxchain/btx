// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_CODES_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_CODES_H

namespace modelnet {

/** peer or family is empty. Nothing is stored. */
inline constexpr char kSwarmFamilyAdmitFamily[] = "FAMILY";

/** claims_compatible is true and advertised_family differs from family. Nothing is stored. */
inline constexpr char kSwarmFamilyAdmitFalseCompat[] = "FALSE_COMPAT";

/** claims_compatible is false. Nothing is stored, even when the family strings match. */
inline constexpr char kSwarmFamilyAdmitNotAdmitted[] = "NOT_ADMITTED";

/** The peer is already stored. The first family stays. */
inline constexpr char kSwarmFamilyAdmitReplay[] = "REPLAY";

/** AddSeed holds the name. The DNS list stays empty. */
inline constexpr char kSwarmFamilyAdmitHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_CODES_H
