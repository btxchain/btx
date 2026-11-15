// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ASSUMEDCLOSE_H
#define BTX_MODELNET_SWARM_ASSUMEDCLOSE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel close. assumed_bytes is a stated close
 * size. An 8000-byte close size is an assumption, not a measurement.
 * want_measure asks this note to measure the close.
 *
 * This note does not measure and does not broadcast. measured and
 * broadcast stay false on every path.
 */
struct SwarmAssumedClose {
    std::string channel_id;
    int64_t assumed_bytes{0};
    bool want_measure{false};
};

/**
 * Outcome of noting an assumed close. measured and broadcast stay false
 * on every path: this note does not measure and does not broadcast.
 */
struct SwarmAssumedCloseResult {
    std::string code;
    bool measured{false};
    bool broadcast{false};
};

/**
 * Note an assumed close without measuring or broadcasting.
 * Order, first match wins: an empty channel_id or assumed_bytes below 0
 * is SIZE. want_measure is MEASURE_REFUSED, including when assumed_bytes
 * is 8000. assumed_bytes other than 8000 is ASSUMPTION. Otherwise the
 * note is NOTED and err is clear. An 8000-byte close size is an
 * assumption, not a measurement. measured and broadcast stay false on
 * every path.
 */
SwarmAssumedCloseResult SwarmNoteAssumedClose(const SwarmAssumedClose& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ASSUMEDCLOSE_H
