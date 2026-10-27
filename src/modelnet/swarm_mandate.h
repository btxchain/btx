// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANDATE_H
#define BTX_MODELNET_SWARM_MANDATE_H

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmMandate {
    std::string mandate_id;
    std::string pool_id;
    std::string actor;
    std::vector<std::string> recipients;
    int64_t ceiling{0};
    int64_t expiry_height{0};
    std::string nonce;
    bool revoked{false};
    int64_t spent{0};
};

struct SwarmConservation {
    int64_t collateral{0};
    int64_t available{0};
    int64_t inflight{0};
    int64_t assigned{0};
    int64_t exit_reserve{0};
    int64_t fee_reserve{0};
    bool ok{false};
};

/**
 * Local authorization caps. A mandate ceiling is not a second copy of the coins.
 * Reserve moves atoms into assigned. Inflight stays 0 because this book creates
 * no HTLC. automatic_spend_atoms is the string "0". No spend key and no broadcast.
 */
class SwarmMandateBook {
public:
    bool Open(int64_t collateral, int64_t exit_reserve, int64_t fee_reserve, std::string& err);
    bool Grant(const SwarmMandate& mandate, std::string& err);
    bool Revoke(const std::string& mandate_id, std::string& err);
    bool Reserve(const std::string& mandate_id, const std::string& work_id, const std::string& recipient, int64_t atoms,
                 int64_t height, std::string& err);
    SwarmConservation Conserved() const;
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    struct Work {
        std::string mandate_id;
        std::string recipient;
        int64_t atoms{0};
    };
    bool m_open{false};
    int64_t m_collateral{0};
    int64_t m_exit{0};
    int64_t m_fee{0};
    std::map<std::string, SwarmMandate> m_mandates;
    std::map<std::string, Work> m_work;
};

} // namespace modelnet

#endif
