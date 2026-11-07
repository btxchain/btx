// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_COVER_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_COVER_H

#include <modelnet/swarm_sigcover/types.h>

#include <string>

namespace modelnet {

/**
 * Plan a covers_outputs description.
 * covers_outputs false is NOT_SIGNED. The plan writes nothing, so a covered
 * row stays covered and an unknown id stays unstored.
 * covers_outputs true on an already covered id is REPLAY. The plan writes nothing.
 * covers_outputs true on an id that is not yet covered accepts a one-way cover mark.
 * The plan attaches no key and does not mark a signature.
 */
SwarmSigCoverPlan SwarmSigCoverPlanCover(bool already_covered, bool covers_outputs, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_COVER_H
