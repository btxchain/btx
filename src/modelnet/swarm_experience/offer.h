// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_OFFER_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_OFFER_H

#include <modelnet/swarm_experience/row.h>

#include <string>

namespace modelnet {

/**
 * Record that a stored public or synthetic trajectory was offered to
 * training. This does not run a GPU and does not add an integer pair.
 * A row whose kind is refused is left unoffered.
 */
bool MarkExperienceOffered(ExperienceRow& row, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_OFFER_H
