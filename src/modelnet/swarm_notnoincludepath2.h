// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#ifndef BTX_MODELNET_SWARM_NOTNOINCLUDEPATH2_H
#define BTX_MODELNET_SWARM_NOTNOINCLUDEPATH2_H

#include <string>

namespace modelnet {

/**
 * A local note that might ask to record. note_id names the note.
 * want_record asks this note to record.
 *
 * A unit note records no include path. recorded stays false on every path.
 */
struct SwarmNotNoIncludePath2 {
    std::string note_id;
    bool want_record{false};
};

/**
 * Outcome of noting without recording. recorded stays false on every path.
 * A unit note records no include path.
 */
struct SwarmNotNoIncludePath2Result {
    std::string code;
    bool recorded{false};
};

/**
 * Note without recording.
 * Order, first match wins: an empty note_id is NOTE. want_record is HELD.
 * Otherwise the note is NOTED and err is cleared. recorded stays false
 * on every path. A unit note records no include path.
 */
SwarmNotNoIncludePath2Result SwarmNoteNotNoIncludePath2(const SwarmNotNoIncludePath2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINCLUDEPATH2_H
