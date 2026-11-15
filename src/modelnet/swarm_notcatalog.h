// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCATALOG_H
#define BTX_MODELNET_SWARM_NOTCATALOG_H

#include <string>

namespace modelnet {

/**
 * A local note about one model. want_emit asks this note to emit the model
 * into the catalog.
 *
 * A model has not been emitted into the catalog. emitted stays false on
 * every path.
 */
struct SwarmNotCatalog {
    std::string model_id;
    bool want_emit{false};
};

/**
 * Outcome of noting a catalog request. emitted stays false on every path:
 * a model has not been emitted into the catalog.
 */
struct SwarmNotCatalogResult {
    std::string code;
    bool emitted{false};
};

/**
 * Note a catalog request without emitting the model.
 * Order, first match wins: an empty model_id is MODEL. want_emit is
 * NOT_EMITTED. Otherwise the note is NOTED and err is clear.
 * emitted stays false on every path. A model has not been emitted into
 * the catalog.
 */
SwarmNotCatalogResult SwarmNoteNotCatalog(const SwarmNotCatalog& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCATALOG_H
