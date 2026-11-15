// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_RECORDS_RESEARCH_RECORDS_H
#define BITCOIN_MODELNET_RESEARCH_RECORDS_RESEARCH_RECORDS_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** An empty id, body, or author. Nothing is stored. */
inline constexpr char RESEARCH_RECORDS_FIELD[] = "FIELD";

/** sequence < 1. Nothing is stored. */
inline constexpr char RESEARCH_RECORDS_SEQUENCE[] = "SEQUENCE";

/** A second body for an id. The first body stays. */
inline constexpr char RESEARCH_RECORDS_MISMATCH[] = "MISMATCH";

/** A lower sequence for the same body. The first record stays. */
inline constexpr char RESEARCH_RECORDS_ROLLBACK[] = "ROLLBACK";

/**
 * In-memory research records.
 *
 * Publish stores one body and one sequence for an id.
 * An empty id, body, or author returns FIELD and stores nothing.
 * sequence < 1 returns SEQUENCE and stores nothing.
 * The same id with the same body and the same sequence returns NIFDT_REPLAY
 * and keeps the first record.
 * A different body returns MISMATCH and keeps the first body. Body is
 * compared before sequence, so a different body with a lower sequence is
 * still MISMATCH.
 * The same body with a lower sequence returns ROLLBACK and keeps the first
 * record.
 * The same body with a higher sequence stores that sequence and keeps the
 * first body and the first author.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND.
 * Release returns false with NIFDT_UNQUALIFIED.
 * Vendor and Gpu return false with NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * automatic_spend() is "0".
 * This class opens no file, socket, or process, and it holds no wallet key.
 * It has no method that assigns work to an author.
 */
class ResearchRecords {
public:
    bool Publish(const std::string& id, const std::string& body, const std::string& author, int64_t sequence, std::string& err);

    bool stored(const std::string& id) const;
    std::string body(const std::string& id) const;
    int64_t sequence(const std::string& id) const;
    std::string author(const std::string& id) const;

    bool Spend(std::string& err);
    bool Release(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string body;
        std::string author;
        int64_t sequence{0};
    };
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_RECORDS_RESEARCH_RECORDS_H
