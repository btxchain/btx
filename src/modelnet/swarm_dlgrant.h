// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DLGRANT_H
#define BTX_MODELNET_SWARM_DLGRANT_H

#include <string>

namespace modelnet {

/**
 * A local note about one download grant. Starting a GPU job and
 * broadcasting are not provided.
 */
struct SwarmDownloadGrant {
    std::string license_id;
    bool download_license{false};
    bool operator_grant{false};
    bool want_train{false};
};

/**
 * A local download-grant note. training_allowed stays false: a note
 * does not start a GPU job and does not broadcast.
 */
struct SwarmDownloadGrantResult {
    bool training_allowed{false};
    std::string code;
};

/**
 * Order, first match wins: an empty license_id is GRANT. A request
 * that wants training without an operator grant is NOT_TRAINING,
 * including when download_license is also true. A download license
 * alone is not a training grant. A request that wants training is
 * HELD and err is clear. An operator grant in this note still does
 * not start training. Otherwise the note is NOTED and err is clear.
 * training_allowed stays false on every path. This records a local
 * note. It does not start a GPU job and does not broadcast.
 */
SwarmDownloadGrantResult SwarmNoteDownloadGrant(const SwarmDownloadGrant& grant, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DLGRANT_H
