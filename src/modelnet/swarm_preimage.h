// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PREIMAGE_H
#define BTX_MODELNET_SWARM_PREIMAGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one hashlock preimage. invoice_id names the invoice.
 * preimage_len is the claimed preimage length in bytes. want_route asks
 * this note to treat the preimage as a multi-hop route.
 *
 * This note does not route and does not broadcast. qualified stays false
 * on every path. No hostnames or IPs are used.
 */
struct SwarmPreimage {
    std::string invoice_id;
    int64_t preimage_len{0};
    bool want_route{false};
};

/**
 * Outcome of noting a preimage. qualified stays false: nothing is routed
 * and nothing is broadcast.
 */
struct SwarmPreimageResult {
    bool qualified{false};
    std::string code;
};

/**
 * Note a preimage without routing it.
 * Order, first match wins:
 * an empty invoice_id or preimage_len < 0 is PREIMAGE.
 * preimage_len other than 32 is LEN, including when want_route is true.
 * A routed hashlock needs a 32-byte preimage.
 * want_route is HELD and err is cleared. A 32-byte preimage is not a
 * qualified multi-hop route.
 * Otherwise the note is NOTED and err is cleared.
 * qualified stays false. Nothing is routed and nothing is broadcast.
 */
SwarmPreimageResult SwarmNotePreimage(const SwarmPreimage& preimage, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PREIMAGE_H
