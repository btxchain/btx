// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_MOMENTS_DT_MOMENTS_H
#define BITCOIN_MODELNET_DT_MOMENTS_DT_MOMENTS_H

#include <modelnet/nifdt_contract/contract.h>

#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** The directory path was empty. Nothing is written. */
inline constexpr char DT_MOMENTS_DIR[] = "DIR";

/** One of the five state strings was empty. Nothing is written. */
inline constexpr char DT_MOMENTS_STATE[] = "STATE";

/** A state string contains the exact text "nan" or "inf". Nothing is written. */
inline constexpr char DT_MOMENTS_FINITE[] = "FINITE";

/** The journal did not accept this commit, or the journal file is missing. */
inline constexpr char DT_MOMENTS_JOURNAL[] = "JOURNAL";

/** Snapshot file stored under the directory passed to Commit and Reload. */
inline constexpr char DT_MOMENTS_JOURNAL_NAME[] = "moments.journal";

/**
 * DT-OPT-004. One snapshot of master weights, moments, scales, RNG, and
 * scheduler state.
 *
 * The five strings start empty. qualified() and hardware_qualified() stay
 * false. launched(), gpu(), and broadcast() stay false. automatic_spend()
 * is "0". bytes_moved() stays 0. hosts() stays 1. No socket is opened.
 *
 * Commit(dir, master, moment, scale, rng, scheduler, journal_ok, err)
 * checks the arguments in that order. An empty dir is DIR. Any empty
 * string among the five is STATE. The exact text "nan" or "inf" anywhere
 * in a string is FINITE. journal_ok false is JOURNAL. Each of those refusals
 * writes nothing and leaves the stored strings unchanged.
 *
 * A successful commit stores all five and writes them as five lines in
 * moments.journal. The directory is created with the one-argument
 * fs::create_directories. The bytes are written to a temp file in that
 * directory and published with fs::rename(tmp, final, ec). On a write or
 * rename failure the temp file is deleted and the previous moments.journal
 * is left byte-for-byte.
 *
 * A second commit of the same moment text is NIFDT_REPLAY and keeps the
 * file. A later commit with journal_ok false leaves the previous five
 * strings and the file unchanged.
 *
 * Reload(dir, err) reads moments.journal. A missing file is JOURNAL and
 * does not invent state. Gpu(err) returns false with NIFDT_ENGINE_ABSENT
 * and does not change the stored strings.
 */
class DtMoments {
public:
    bool Commit(const fs::path& dir, const std::string& master, const std::string& moment,
                const std::string& scale, const std::string& rng, const std::string& scheduler,
                bool journal_ok, std::string& err);
    bool Reload(const fs::path& dir, std::string& err);
    bool Gpu(std::string& err);

    const std::string& master() const { return m_master; }
    const std::string& moment() const { return m_moment; }
    const std::string& scale() const { return m_scale; }
    const std::string& rng() const { return m_rng; }
    const std::string& scheduler() const { return m_scheduler; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::string m_master;
    std::string m_moment;
    std::string m_scale;
    std::string m_rng;
    std::string m_scheduler;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_MOMENTS_DT_MOMENTS_H
