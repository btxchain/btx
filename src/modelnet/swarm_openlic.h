// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_OPENLIC_H
#define BITCOIN_MODELNET_SWARM_OPENLIC_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmOpenLic {
    std::string license_id;
    bool open_local;
    bool want_tax;
};

struct SwarmOpenLicResult {
    std::string code;
    bool taxed;
    int64_t atoms;
};

SwarmOpenLicResult SwarmNoteOpenLicense(const SwarmOpenLic& license, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_OPENLIC_H
