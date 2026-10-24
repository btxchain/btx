// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSCHEDWIT_H
#define BTX_MODELNET_SWARM_NOTSCHEDWIT_H

#include <string>

namespace modelnet {

/**
 * A local note about one scheduler. want_sign asks this note to sign a
 * funding witness.
 *
 * The scheduler does not sign a funding witness. signed_witness and
 * broadcast stay false on every path.
 */
struct SwarmNotSchedWit {
    std::string scheduler_id;
    bool want_sign{false};
};

/**
 * Outcome of noting a funding-witness sign request. signed_witness and
 * broadcast stay false on every path. The scheduler does not sign a
 * funding witness.
 */
struct SwarmNotSchedWitResult {
    std::string code;
    bool signed_witness{false};
    bool broadcast{false};
};

/**
 * Note a funding-witness sign request without signing or broadcasting.
 * Order, first match wins: an empty scheduler_id is SCHEDULER. want_sign
 * is NO_WITNESS. Otherwise the note is NOTED and err is clear.
 * signed_witness and broadcast stay false on every path. The scheduler
 * does not sign a funding witness.
 */
SwarmNotSchedWitResult SwarmNoteNotSchedWit(const SwarmNotSchedWit& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSCHEDWIT_H
