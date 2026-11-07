// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PRIVFAM_H
#define BTX_MODELNET_SWARM_PRIVFAM_H

#include <string>

namespace modelnet {

struct SwarmPrivFam {
    std::string family_id;
    bool private_family;
    bool want_publish;
};

struct SwarmPrivFamResult {
    std::string code;
    bool published;
};

SwarmPrivFamResult SwarmNotePrivFam(const SwarmPrivFam& family, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PRIVFAM_H
