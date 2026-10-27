// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINCLUSIVE_H
#define BTX_MODELNET_SWARM_NOTNOINCLUSIVE_H

#include <string>

namespace modelnet {

/**
 * A local note about one cohort window. cohort_id names the cohort.
 * expired is true when now is greater than or equal to until.
 * want_keep asks this note to keep the cohort.
 *
 * This note keeps nothing and trains nothing. kept and trained stay
 * false on every path. Inclusive expiry, now greater than or equal
 * to until, keeps nothing.
 */
struct SwarmNotNoInclusive {
    std::string cohort_id;
    bool expired{false};
    bool want_keep{false};
};

/**
 * Outcome of noting a cohort. kept and trained stay false on every
 * path. Inclusive expiry, now greater than or equal to until, keeps
 * nothing.
 */
struct SwarmNotNoInclusiveResult {
    std::string code;
    bool kept{false};
    bool trained{false};
};

/**
 * Note a cohort without keeping it. Order, first match wins: an empty
 * cohort_id is COHORT. If expired is true, the note is EXPIRED even
 * when want_keep is false. want_keep is HELD. Otherwise the note is
 * NOTED and err is cleared.
 * kept and trained stay false on every path. Inclusive expiry, now
 * greater than or equal to until, keeps nothing.
 */
SwarmNotNoInclusiveResult SwarmNoteNotNoInclusive(const SwarmNotNoInclusive& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINCLUSIVE_H
