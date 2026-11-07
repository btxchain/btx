// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CKPTSAVE_H
#define BTX_MODELNET_SWARM_CKPTSAVE_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmCkptSave {
    std::string job_id;
    bool want_save;
};

struct SwarmCkptSaveResult {
    std::string code;
    bool saved;
    int64_t bytes_moved;
};

SwarmCkptSaveResult SwarmNoteCkptSave(const SwarmCkptSave& job, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CKPTSAVE_H
