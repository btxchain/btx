// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_VIEWS_RESEARCH_VIEWS_H
#define BITCOIN_MODELNET_RESEARCH_VIEWS_RESEARCH_VIEWS_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local research rows and five named views.
 *
 * Results are local. They are not global consensus.
 * This class opens no file and no socket, and starts no process.
 * Assign returns AUTHORITY and stores nothing. It does not assign work.
 *
 * Put: an empty id or an empty topic returns FIELD and stores nothing.
 * A repeated id returns NIFDT_REPLAY and keeps the first row.
 * A private row is stored. Public(topic) does not return it.
 * A negative row stays queryable after a later positive summary on another id.
 *
 * View accepts only LEADING, CONTESTED, NEGLECTED, RECENT, and REPRODUCED.
 * Any other name returns VIEW.
 * RECENT returns ids for that topic ordered by descending now_ms.
 * REPRODUCED returns only reproduced public rows for that topic.
 * NEGLECTED returns a public topic that has only negative public rows.
 * LEADING returns the newest public non-negative id for that topic.
 * CONTESTED returns a topic that has both a negative and a non-negative public row.
 *
 * Release returns NIFDT_UNQUALIFIED. qualified() and release_qualified() stay false.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * launched(), gpu(), and broadcast() stay false.
 */
class ResearchViews {
public:
    bool Put(const std::string& id, const std::string& topic, const std::string& summary, bool negative, bool reproduced,
             int64_t now_ms, bool is_private, std::string& err);
    std::vector<std::string> View(const std::string& name, const std::string& topic, std::string& err) const;
    std::vector<std::string> Public(const std::string& topic) const;
    bool Assign(const std::string& author, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string id;
        std::string topic;
        std::string summary;
        bool negative{false};
        bool reproduced{false};
        int64_t now_ms{0};
        bool is_private{false};
        int64_t seq{0};
    };

    bool Known(const std::string& id) const;
    std::vector<Row> Select(const std::string& topic, bool public_only, bool reproduced_only) const;
    std::vector<std::string> IdsByTime(std::vector<Row> rows) const;
    std::vector<std::string> Topics(const std::string& topic, bool neglected) const;

    std::vector<Row> m_rows;
    int64_t m_seq{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_VIEWS_RESEARCH_VIEWS_H
