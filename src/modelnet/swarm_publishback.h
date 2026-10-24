// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PUBLISHBACK_H
#define BTX_MODELNET_SWARM_PUBLISHBACK_H

#include <string>

namespace modelnet {

/**
 * A local note about a Hugging Face publish-back. model_id names the
 * model. hugging_face records that the caller treats the id as a Hugging
 * Face origin. want_publish_back asks this note to publish that origin
 * back.
 *
 * A Hugging Face publish-back is an origin, not lineage authority. This
 * note does not publish, does not fetch a model, and does not open a
 * socket.
 */
struct SwarmPublishBack {
    std::string model_id;
    bool hugging_face{false};
    bool want_publish_back{false};
};

/**
 * Outcome of noting a publish-back. published and authority stay false on
 * every path: this note does not publish, and a Hugging Face origin is
 * not lineage authority.
 */
struct SwarmPublishBackResult {
    std::string code;
    bool published{false};
    bool authority{false};
};

/**
 * Note a publish-back without publishing and without assigning lineage.
 * Order, first match wins: an empty model_id is ORIGIN. want_publish_back
 * is NOT_AUTHORITY, including when hugging_face is true. hugging_face is
 * HELD and err is cleared. Otherwise the note is NOTED and err is cleared.
 * published and authority stay false on every path. A Hugging Face
 * publish-back is an origin, not lineage authority, and this note does
 * not publish.
 */
SwarmPublishBackResult SwarmNotePublishBack(const SwarmPublishBack& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PUBLISHBACK_H
