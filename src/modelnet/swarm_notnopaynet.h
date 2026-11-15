// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPAYNET_H
#define BTX_MODELNET_SWARM_NOTNOPAYNET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one ledger. want_broadcast asks this note to
 * broadcast a paynet.
 *
 * An accounting-only paynet broadcasts nothing. broadcast stays false
 * and atoms stays 0 on every path.
 */
struct SwarmNotNoPaynet {
    std::string ledger_id;
    bool want_broadcast{false};
};

/**
 * Outcome of noting an accounting-only paynet. broadcast stays false and
 * atoms stays 0: an accounting-only paynet broadcasts nothing.
 */
struct SwarmNotNoPaynetResult {
    std::string code;
    bool broadcast{false};
    int64_t atoms{0};
};

/**
 * Note an accounting-only paynet without broadcasting it.
 * Order, first match wins: an empty ledger_id is LEDGER. want_broadcast
 * is NOT_BROADCAST. Otherwise the note is NOTED and err is clear.
 * broadcast stays false and atoms stays 0 on every path. An
 * accounting-only paynet broadcasts nothing.
 */
SwarmNotNoPaynetResult SwarmNoteNotNoPaynet(const SwarmNotNoPaynet& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPAYNET_H
