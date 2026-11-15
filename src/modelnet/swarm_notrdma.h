// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTRDMA_H
#define BTX_MODELNET_SWARM_NOTRDMA_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. rdma_present records whether RDMA is present.
 * want_transfer asks this note to move bytes.
 *
 * RDMA is not available, so this note does not transfer.
 * bytes_moved stays false on every path.
 */
struct SwarmNotRdma {
    std::string page_id;
    bool rdma_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting an RDMA request. bytes_moved stays false on every path:
 * RDMA is not available, so this note does not transfer.
 */
struct SwarmNotRdmaResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note an RDMA request without moving bytes.
 * Order, first match wins: an empty page_id is RDMA.
 * Absent RDMA is ENGINE_ABSENT, even when want_transfer is true.
 * want_transfer with RDMA present is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path.
 */
SwarmNotRdmaResult SwarmNoteNotRdma(const SwarmNotRdma& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTRDMA_H
