// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOONECLOSE_H
#define BTX_MODELNET_SWARM_NOTNOONECLOSE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one clearing batch. want_close_many asks this note
 * to close more than the single close template.
 *
 * A clearing batch has one close template and this note closes nothing.
 * closed stays false and l1_txs stays 0 on every path.
 */
struct SwarmNotNoOneClose {
    std::string batch_id;
    bool want_close_many{false};
};

/**
 * Outcome of noting a close request. closed stays false and l1_txs stays
 * 0 on every path. A clearing batch has one close template and this note
 * closes nothing.
 */
struct SwarmNotNoOneCloseResult {
    std::string code;
    bool closed{false};
    int64_t l1_txs{0};
};

/**
 * Note a close request without closing.
 * Order, first match wins: an empty batch_id is BATCH. want_close_many
 * is ONE_CLOSE. Otherwise the note is NOTED and err is clear.
 * closed stays false and l1_txs stays 0 on every path. A clearing batch
 * has one close template and this note closes nothing.
 */
SwarmNotNoOneCloseResult SwarmNoteNotNoOneClose(const SwarmNotNoOneClose& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOONECLOSE_H
