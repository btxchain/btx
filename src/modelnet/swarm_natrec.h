// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#ifndef BTX_MODELNET_SWARM_NATREC_H
#define BTX_MODELNET_SWARM_NATREC_H

#include <string>

namespace modelnet {

/**
 * A local NAT record. node_id names the record. mapped notes that a
 * mapping was observed. want_publish asks this record to publish an
 * address. want_open asks this record to open a socket.
 *
 * A NAT record does not publish an address or open a socket, so
 * published stays false and opened stays false on every path.
 */
struct SwarmNatRec {
    std::string node_id;
    bool mapped{false};
    bool want_publish{false};
    bool want_open{false};
};

/**
 * Outcome of recording NAT state. published stays false and opened
 * stays false on every path. A NAT record does not publish an address
 * or open a socket.
 */
struct SwarmNatRecResult {
    std::string code;
    bool published{false};
    bool opened{false};
};

/**
 * Record NAT state without publishing an address or opening a socket.
 * Order, first match wins: an empty node_id is NODE. want_publish is
 * HELD. want_open is HELD. mapped is NOTED and err is cleared.
 * Otherwise the record is NOTED and err is cleared. published stays
 * false and opened stays false on every path.
 * A NAT record does not publish an address or open a socket.
 */
SwarmNatRecResult SwarmRecordNat(const SwarmNatRec& rec, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NATREC_H
