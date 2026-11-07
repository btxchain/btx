// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP38_GRP38_H
#define BITCOIN_MODELNET_GRP38_GRP38_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 38. In-memory record of the known DS-HIRE, DS-AUTH, DS-DATA, and
 * DS-PLAN ids. This class opens no file, socket, or process.
 *
 * Known ids: DS-HIRE-002, DS-HIRE-003, DS-HIRE-004, DS-HIRE-005, DS-HIRE-006,
 * DS-AUTH-001, DS-AUTH-002, DS-AUTH-003, DS-AUTH-004, DS-AUTH-005, DS-AUTH-006,
 * DS-DATA-001, DS-DATA-002, DS-DATA-003, DS-DATA-004, DS-DATA-005, DS-DATA-006,
 * DS-PLAN-001, DS-PLAN-002, DS-PLAN-003.
 *
 * Apply checks, in order:
 * an empty or unknown id is ID and stores nothing;
 * empty text is FIELD and stores nothing;
 * aux < 0 is BOUND and stores nothing;
 * aux > 100 is CAP and stores nothing;
 * flag false is ABSENT and stores nothing;
 * a remote engine name (NifDtEngineLinked is false) is NIFDT_ENGINE_ABSENT
 * and stores nothing;
 * text containing "private" is NIFDT_PRIVATE_DATA and stores nothing;
 * DS-AUTH-003 with aux <= 0 is EXPIRED and stores nothing (aux < 0 has
 * already returned BOUND, so the expiry result is aux 0);
 * a stored id with the same text is NIFDT_REPLAY and keeps the first;
 * a stored id with different text is UNCHANGED and keeps the first;
 * otherwise the id is stored once.
 *
 * Hosts: n other than 1 returns HOSTS. hosts() and physical_hosts() stay 1.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), hardware_qualified(), advertised(),
 * launched(), gpu(), and broadcast() stay false. bytes_moved() stays 0.
 * automatic_spend() is "0".
 */
class Grp38 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    int64_t aux_of(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string text;
        int64_t aux{0};
    };
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
