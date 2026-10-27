// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOSTNOTE2_H
#define BTX_MODELNET_SWARM_NOTNOHOSTNOTE2_H

#include <string>

namespace modelnet {

/**
 * A local note that might name an operator host or ask to record.
 * names_host records whether the note names an operator host.
 * want_record asks this note to record.
 *
 * A note that names an operator host is refused. recorded stays false
 * on every path.
 */
struct SwarmNotNoHostNote2 {
    std::string note_id;
    bool names_host{false};
    bool want_record{false};
};

/**
 * Outcome of noting without recording a host name. recorded stays false
 * on every path.
 */
struct SwarmNotNoHostNote2Result {
    std::string code;
    bool recorded{false};
};

/**
 * Note that no operator host is named or recorded.
 * Order, first match wins: an empty note_id is NOTE. names_host true is
 * REFUSED, even when want_record is false. want_record is HELD.
 * Otherwise the note is NOTED and err is cleared. recorded stays false
 * on every path. A note that names an operator host is refused.
 */
SwarmNotNoHostNote2Result SwarmNoteNotNoHostNote2(const SwarmNotNoHostNote2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOSTNOTE2_H
