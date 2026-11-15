// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLIVEFAULT_H
#define BTX_MODELNET_SWARM_NOTLIVEFAULT_H

#include <string>

namespace modelnet {

/**
 * A local note about one fault. want_inject asks this note to inject a
 * live fault.
 *
 * A code label is not a live fault injection. injected stays false on
 * every path.
 */
struct SwarmNotLiveFault {
    std::string fault_id;
    bool want_inject{false};
};

/**
 * Outcome of noting a fault. injected stays false on every path: a code
 * label is not a live fault injection.
 */
struct SwarmNotLiveFaultResult {
    std::string code;
    bool injected{false};
};

/**
 * Note a fault without injecting it.
 * Order, first match wins: an empty fault_id is FAULT.
 * want_inject is NOT_INJECTED.
 * Otherwise the note is NOTED and err is clear.
 * injected stays false on every path. A code label is not a live fault
 * injection.
 */
SwarmNotLiveFaultResult SwarmNoteNotLiveFault(const SwarmNotLiveFault& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLIVEFAULT_H
