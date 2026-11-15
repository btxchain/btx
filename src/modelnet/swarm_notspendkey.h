// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSPENDKEY_H
#define BTX_MODELNET_SWARM_NOTSPENDKEY_H

#include <string>

namespace modelnet {

/**
 * A local note about one research scheduler. want_spend asks this note
 * to spend.
 *
 * The research scheduler never receives a spend key. This note does not
 * sign or broadcast. signed_spend and broadcast stay false on every path.
 */
struct SwarmNotSpendKey {
    std::string scheduler_id;
    bool want_spend{false};
};

/**
 * Outcome of noting a spend request. signed_spend and broadcast stay false
 * on every path. The research scheduler never receives a spend key. This
 * note does not sign or broadcast.
 */
struct SwarmNotSpendKeyResult {
    std::string code;
    bool signed_spend{false};
    bool broadcast{false};
};

/**
 * Note a spend request without handing over a spend key, signing, or
 * broadcasting. Order, first match wins: an empty scheduler_id is
 * SCHEDULER. want_spend is NO_KEY. Otherwise the note is NOTED and err
 * is clear. signed_spend and broadcast stay false on every path.
 * The research scheduler never receives a spend key. This note does not
 * sign or broadcast.
 */
SwarmNotSpendKeyResult SwarmNoteNotSpendKey(const SwarmNotSpendKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSPENDKEY_H
