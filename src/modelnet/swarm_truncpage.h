// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TRUNCPAGE_H
#define BTX_MODELNET_SWARM_TRUNCPAGE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one page's byte length. Reusing a tensor and
 * moving bytes are not provided.
 */
struct SwarmTruncatedPage {
    std::string page_id;
    int64_t expected_bytes{0};
    int64_t received_bytes{0};
    bool compatible{false};
};

/**
 * A local truncated-page note. reusable and bytes_moved stay false:
 * a full compatible length is still not a reusable tensor and moves
 * no bytes.
 */
struct SwarmTruncatedPageResult {
    bool reusable{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order, first match wins: an empty page_id, expected_bytes below 1,
 * or received_bytes below 0 is PAGE. A length that does not match
 * (received_bytes not equal to expected_bytes) is TRUNCATED, including
 * when compatible is true. A matching length that is not compatible is
 * INCOMPATIBLE. Otherwise the note is HELD and err is clear. reusable
 * and bytes_moved stay false on every path. This records a local note.
 * It does not reuse a tensor and does not move bytes. No hostnames or
 * IPs are used.
 */
SwarmTruncatedPageResult SwarmNoteTruncatedPage(const SwarmTruncatedPage& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TRUNCPAGE_H
