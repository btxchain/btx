// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_LINEAGE_DT_LINEAGE_H
#define BITCOIN_MODELNET_DT_LINEAGE_DT_LINEAGE_H

#include <modelnet/nifdt_contract/contract.h>

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** The directory path was empty, the journal could not be written, or the journal file is missing. */
inline constexpr char DT_LINEAGE_JOURNAL[] = "JOURNAL";

/** The generation name was empty. Nothing is written. */
inline constexpr char DT_LINEAGE_GENERATION[] = "GENERATION";

/** A step failed. The committed generation and weight stay. */
inline constexpr char DT_LINEAGE_STEP[] = "STEP";

/** Journal file stored under the directory passed to Open. */
inline constexpr char DT_LINEAGE_JOURNAL_NAME[] = "lineage.journal";

/**
 * Committed generation lineage.
 *
 * Open(dir, err) creates dir when it is missing. An empty dir is JOURNAL.
 * The live weight starts at 1 and the live generation starts empty.
 *
 * Commit(generation, weight, journal_ok, err) appends one record.
 * An empty generation is GENERATION. journal_ok false is JOURNAL, writes
 * nothing, and leaves generation() and weight() unchanged. journal_ok true
 * appends one record by writing a temp file and fs::rename onto
 * lineage.journal. generation() and weight() then become the new values.
 * A second commit of the same generation is NIFDT_REPLAY and does not
 * change weight().
 *
 * Reload(err) reads the committed records back. The live generation and
 * weight become the last record. A missing journal file is JOURNAL and
 * leaves the live generation empty. The live weight returns to 1.
 *
 * StepFailed(err) returns false with STEP and does not change generation()
 * or weight().
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * "0". bytes_moved() stays 0. No socket is opened and no process is started.
 */
class DtLineage {
public:
    struct Record {
        std::string generation;
        int64_t weight{0};
    };

    bool Open(const fs::path& dir, std::string& err);
    bool Commit(const std::string& generation, int64_t weight, bool journal_ok, std::string& err);
    bool Reload(std::string& err);
    bool StepFailed(std::string& err);

    const std::string& generation() const { return m_generation; }
    int64_t weight() const { return m_weight; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    void ClearLive();
    void Apply(std::vector<Record> records);
    fs::path JournalPath() const;

    std::vector<Record> m_records;
    std::string m_generation;
    int64_t m_weight{static_cast<int64_t>(1)};
    fs::path m_dir;
    bool m_open{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_LINEAGE_DT_LINEAGE_H
