// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RAFTLOG_H
#define BTX_MODELNET_SWARM_RAFTLOG_H

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmLogEntry {
    int64_t index{0};
    int64_t term{0};
    std::string command;
};

/**
 * In-process command log for one static committee. Vote and append write the
 * log file before they return. A committed prefix cannot be truncated.
 * This does not open a socket and does not hold a spend key.
 */
class SwarmCommandLog {
public:
    bool Open(const fs::path& modeldir, int voters, std::string& err);
    bool Vote(int64_t term, const std::string& candidate, int64_t last_index, int64_t last_term, std::string& err);
    bool Append(int64_t term, int64_t prev_index, int64_t prev_term, const std::string& command, std::string& err);
    bool Commit(int64_t index, std::string& err);
    bool Truncate(int64_t index, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);
    int64_t Term() const { return m_term; }
    int64_t CommitIndex() const { return m_commit; }
    const std::string& VotedFor() const { return m_voted_for; }
    const std::vector<SwarmLogEntry>& Entries() const { return m_entries; }

private:
    bool Persist(std::string& err);
    bool m_open{false};
    fs::path m_dir;
    int m_voters{0};
    int64_t m_term{0};
    int64_t m_commit{0};
    std::string m_voted_for;
    std::vector<SwarmLogEntry> m_entries;
};

} // namespace modelnet

#endif
