// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSCRIPTHOP_H
#define BTX_MODELNET_SWARM_NOTSCRIPTHOP_H

#include <string>

namespace modelnet {

/**
 * A local note about one invoice. want_qualify asks this note to qualify
 * a multi-hop script path.
 *
 * This note does not build a script, settle, or broadcast. Multi-hop stays
 * unqualified. qualified, multihop, and broadcast stay false on every path.
 */
struct SwarmNotScriptHop {
    std::string invoice_id;
    bool want_qualify{false};
};

/**
 * Outcome of noting a script-hop request. qualified, multihop, and broadcast
 * stay false on every path. This note does not build a script, settle, or
 * broadcast. Multi-hop stays unqualified.
 */
struct SwarmNotScriptHopResult {
    std::string code;
    bool qualified{false};
    bool multihop{false};
    bool broadcast{false};
};

/**
 * Note a script-hop request without building a script, settling, or broadcasting.
 * Order, first match wins: an empty invoice_id is INVOICE. want_qualify is
 * UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * qualified, multihop, and broadcast stay false on every path. This note does
 * not build a script, settle, or broadcast. Multi-hop stays unqualified.
 */
SwarmNotScriptHopResult SwarmNoteNotScriptHop(const SwarmNotScriptHop& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSCRIPTHOP_H
