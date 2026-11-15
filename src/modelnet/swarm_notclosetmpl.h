// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCLOSETMPL_H
#define BTX_MODELNET_SWARM_NOTCLOSETMPL_H

#include <string>

namespace modelnet {

/**
 * A local note about one close template. template_count is the number of
 * close templates recorded for the channel. want_close asks this note to
 * close.
 *
 * High-speed settlement keeps one close template. This note does not
 * close or broadcast. closed and broadcast stay false on every path.
 */
struct SwarmNotCloseTmpl {
    std::string channel_id;
    int template_count{0};
    bool want_close{false};
};

/**
 * Outcome of noting a close template. closed and broadcast stay false on
 * every path. High-speed settlement keeps one close template. This note
 * does not close or broadcast.
 */
struct SwarmNotCloseTmplResult {
    std::string code;
    bool closed{false};
    bool broadcast{false};
};

/**
 * Note a close template without closing or broadcasting.
 * Order, first match wins: an empty channel_id is CHANNEL. template_count
 * other than 1 is ONE_TEMPLATE even when want_close is false. want_close
 * is HELD. Otherwise the note is NOTED and err is clear.
 * closed and broadcast stay false on every path. High-speed settlement
 * keeps one close template. This note does not close or broadcast.
 */
SwarmNotCloseTmplResult SwarmNoteNotCloseTmpl(const SwarmNotCloseTmpl& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCLOSETMPL_H
