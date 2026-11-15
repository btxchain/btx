// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQUOTE_H
#define BTX_MODELNET_SWARM_NOTNOQUOTE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one quality quote. want_publish asks this note to
 * treat a caller-supplied quality quote as a measurement.
 *
 * A caller-supplied quality quote is not a measurement. published stays
 * false and multiplier stays 0 on every path.
 */
struct SwarmNotNoQuote {
    std::string quote_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a quality quote. published stays false and multiplier
 * stays 0 on every path: a caller-supplied quality quote is not a measurement.
 */
struct SwarmNotNoQuoteResult {
    std::string code;
    bool published{false};
    int64_t multiplier{0};
};

/**
 * Note a quality quote without publishing a measurement.
 * Order, first match wins: an empty quote_id is QUOTE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and multiplier stays 0 on every path.
 * A caller-supplied quality quote is not a measurement.
 */
SwarmNotNoQuoteResult SwarmNoteNotNoQuote(const SwarmNotNoQuote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQUOTE_H
