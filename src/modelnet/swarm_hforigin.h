// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HFORIGIN_H
#define BTX_MODELNET_SWARM_HFORIGIN_H

#include <string>

namespace modelnet {

/**
 * A local note about a Hugging Face import origin. model_id names the
 * model. hugging_face records that the caller treats the id as a Hugging
 * Face import origin. want_lineage_authority asks this note to treat that
 * origin as lineage authority.
 *
 * Hugging Face is an import origin, not lineage authority. This note does
 * not fetch a model, does not open a socket, and does not assign lineage.
 */
struct SwarmHfOrigin {
    std::string model_id;
    bool hugging_face{false};
    bool want_lineage_authority{false};
};

/**
 * Outcome of noting a Hugging Face origin. authority stays false on every
 * path: an import origin is not accepted as lineage authority.
 */
struct SwarmHfOriginResult {
    std::string code;
    bool authority{false};
};

/**
 * Note a Hugging Face origin without assigning lineage.
 * Order, first match wins: an empty model_id is ORIGIN. want_lineage_authority
 * is NOT_AUTHORITY, including when hugging_face is true. hugging_face is HELD
 * and err is cleared. Otherwise the note is NOTED and err is cleared.
 * authority stays false on every path. Hugging Face is an import origin, not
 * lineage authority.
 */
SwarmHfOriginResult SwarmNoteHfOrigin(const SwarmHfOrigin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HFORIGIN_H
