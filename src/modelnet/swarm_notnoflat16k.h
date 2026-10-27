// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFLAT16K_H
#define BTX_MODELNET_SWARM_NOTNOFLAT16K_H

#include <string>

namespace modelnet {

/**
 * A local note about one flat manifest. want_flatten asks this note to
 * flatten the manifest.
 *
 * The flat manifest cap is 16384. This note flattens nothing. flattened
 * stays false on every path.
 */
struct SwarmNotNoFlat16k {
    std::string manifest_id;
    int count{0};
    bool want_flatten{false};
};

/**
 * Outcome of noting a flat manifest. flattened stays false on every path.
 * The flat manifest cap is 16384. This note flattens nothing.
 */
struct SwarmNotNoFlat16kResult {
    std::string code;
    bool flattened{false};
};

/**
 * Note a flat manifest without flattening it. Order, first match wins:
 * an empty manifest_id is MANIFEST. If count is greater than 16384, the
 * note is NOT_FLAT even when want_flatten is false. want_flatten is HELD.
 * Otherwise the note is NOTED and err is cleared. flattened stays false
 * on every path. The flat manifest cap is 16384. This note flattens
 * nothing.
 */
SwarmNotNoFlat16kResult SwarmNoteNotNoFlat16k(const SwarmNotNoFlat16k& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFLAT16K_H
