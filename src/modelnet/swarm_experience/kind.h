// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_KIND_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_KIND_H

#include <string>

namespace modelnet {

inline constexpr char kExperiencePublic[] = "public_trajectory";
inline constexpr char kExperienceSynthetic[] = "synthetic_trajectory";

/**
 * True only for public_trajectory and synthetic_trajectory.
 * Every other kind, including private_prompt, sets err to PRIVATE_DATA.
 */
bool ExperienceKindAllowed(const std::string& kind, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_KIND_H
