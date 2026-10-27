// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FABRIC_H
#define BTX_MODELNET_SWARM_FABRIC_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmPrefix {
    std::string fingerprint;
    std::string parent_fingerprint;
    int64_t length{0};
    bool causal{true};
};

struct SwarmPrefetch {
    bool bytes_moved{false};
    std::string code;
};

bool SwarmPrefixCompatible(const SwarmPrefix& held, const SwarmPrefix& wanted, std::string& err);
SwarmPrefetch SwarmPrefetchPages(bool engine_present, const SwarmPrefix& held, const SwarmPrefix& wanted, std::string& err);

struct SwarmLanCard {
    std::string artifact_id;
    std::string lineage_id;
    bool public_mapping{false};
    std::vector<unsigned char> pubkey;
    std::string signature_hex;
};

uint256 SwarmLanCardHash(const SwarmLanCard& card);
bool SwarmAcceptLanCard(const SwarmLanCard& card, std::string& err);

} // namespace modelnet

#endif
