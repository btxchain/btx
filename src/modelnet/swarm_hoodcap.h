// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HOODCAP_H
#define BTX_MODELNET_SWARM_HOODCAP_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct Offer {
    std::string node;
    std::string domain;
    int64_t rtt_ms;
    bool known;
};

class SwarmHoodCap {
public:
    bool Admit(const Offer& offer, std::string& err);
    int known_count() const;
    int new_count() const;
    bool bytes_moved() const;

private:
    struct Admission {
        std::string node;
        bool known;
    };
    std::vector<Admission> m_admissions;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HOODCAP_H
