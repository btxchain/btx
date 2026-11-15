// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVWIRE_PAIR_H
#define BITCOIN_MODELNET_SWARM_KVWIRE_PAIR_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Move one non-empty body across a socketpair.
 * An empty body is PAGE and does not create a socket. out is unchanged.
 * Otherwise socketpair(AF_UNIX, SOCK_STREAM, 0, fds) joins the two ends.
 * The full body is written to one end. The other end is read in a loop
 * until every byte arrives or the read fails. Both fds are closed before
 * returning, including on failure.
 * On success, out is the bytes that arrived and err is clear.
 * On failure, out is unchanged.
 */
bool SwarmKvWireCarry(const std::vector<unsigned char>& body, std::vector<unsigned char>& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVWIRE_PAIR_H
