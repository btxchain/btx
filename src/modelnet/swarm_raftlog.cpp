// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_raftlog.h>

#include <univalue.h>

#include <fstream>
#include <iterator>

namespace modelnet {
namespace {

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err)
{
    const fs::path tmp = fs::u8path(final_path.utf8string() + ".tmp");
    {
        std::ofstream file(tmp, std::ios::trunc);
        if (!file) {
            err = "WRITE";
            return false;
        }
        file << body;
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "RENAME";
        return false;
    }
    err.clear();
    return true;
}

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

} // namespace

bool SwarmCommandLog::Persist(std::string& err)
{
    fs::create_directories(m_dir / "swarm");
    if (!fs::exists(m_dir / "swarm")) {
        err = "SWARM_DIR";
        return false;
    }
    UniValue entries(UniValue::VARR);
    for (const SwarmLogEntry& entry : m_entries) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("command", entry.command);
        row.pushKV("index", entry.index);
        row.pushKV("term", entry.term);
        entries.push_back(std::move(row));
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("automatic_spend_atoms", "0");
    out.pushKV("commit", m_commit);
    out.pushKV("entries", entries);
    out.pushKV("term", m_term);
    out.pushKV("voted_for", m_voted_for);
    out.pushKV("voters", m_voters);
    return WriteAtomic(m_dir / "swarm" / "raft-log.json", out.write(0, 0) + "\n", err);
}

bool SwarmCommandLog::Open(const fs::path& modeldir, int voters, std::string& err)
{
    if (modeldir.empty() || voters < 1 || voters > 31) {
        err = "COMMITTEE";
        return false;
    }
    m_dir = modeldir;
    m_voters = voters;
    m_term = 0;
    m_commit = 0;
    m_voted_for.clear();
    m_entries.clear();
    m_open = true;
    return Persist(err);
}

bool SwarmCommandLog::Vote(int64_t term, const std::string& candidate, int64_t last_index, int64_t last_term, std::string& err)
{
    if (!m_open || candidate.empty() || term <= 0) {
        err = "VOTE";
        return false;
    }
    const int64_t our_index = m_entries.empty() ? 0 : m_entries.back().index;
    const int64_t our_term = m_entries.empty() ? 0 : m_entries.back().term;
    if (last_term < our_term || (last_term == our_term && last_index < our_index)) {
        err = "STALE_LOG";
        return false;
    }
    if (term < m_term) {
        err = "STALE_TERM";
        return false;
    }
    if (term == m_term && !m_voted_for.empty() && m_voted_for != candidate) {
        err = "VOTE";
        return false;
    }
    m_term = term;
    m_voted_for = candidate;
    return Persist(err);
}

bool SwarmCommandLog::Append(int64_t term, int64_t prev_index, int64_t prev_term, const std::string& command, std::string& err)
{
    if (!m_open || command.empty() || term <= 0) {
        err = "APPEND";
        return false;
    }
    if (term < m_term) {
        err = "STALE_TERM";
        return false;
    }
    const int64_t our_index = m_entries.empty() ? 0 : m_entries.back().index;
    const int64_t our_term = m_entries.empty() ? 0 : m_entries.back().term;
    if (prev_index != our_index || prev_term != our_term) {
        err = "PREDECESSOR";
        return false;
    }
    if (prev_index < m_commit) {
        err = "COMMITTED_PREFIX";
        return false;
    }
    SwarmLogEntry entry;
    entry.index = our_index + 1;
    entry.term = term;
    entry.command = command;
    m_term = term;
    m_entries.push_back(std::move(entry));
    return Persist(err);
}

bool SwarmCommandLog::Commit(int64_t index, std::string& err)
{
    if (!m_open || index <= m_commit) {
        err = "COMMIT";
        return false;
    }
    bool found = false;
    for (const SwarmLogEntry& entry : m_entries) {
        if (entry.index == index) found = true;
    }
    if (!found || index > (m_entries.empty() ? 0 : m_entries.back().index)) {
        err = "COMMIT";
        return false;
    }
    m_commit = index;
    return Persist(err);
}

bool SwarmCommandLog::Truncate(int64_t index, std::string& err)
{
    if (!m_open) {
        err = "TRUNCATE";
        return false;
    }
    if (index <= m_commit) {
        err = "COMMITTED_PREFIX";
        return false;
    }
    std::vector<SwarmLogEntry> kept;
    for (const SwarmLogEntry& entry : m_entries) {
        if (entry.index < index) kept.push_back(entry);
    }
    m_entries.swap(kept);
    return Persist(err);
}

bool SwarmCommandLog::Load(const fs::path& modeldir, std::string& err)
{
    m_dir = modeldir;
    const fs::path path = m_dir / "swarm" / "raft-log.json";
    std::string raw;
    UniValue root;
    if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject()) {
        err = "RAFT_READ";
        return false;
    }
    m_term = root["term"].getInt<int64_t>();
    m_commit = root["commit"].getInt<int64_t>();
    m_voters = root["voters"].getInt<int>();
    m_voted_for = root["voted_for"].get_str();
    m_entries.clear();
    for (const UniValue& item : root["entries"].getValues()) {
        SwarmLogEntry entry;
        entry.index = item["index"].getInt<int64_t>();
        entry.term = item["term"].getInt<int64_t>();
        entry.command = item["command"].get_str();
        m_entries.push_back(std::move(entry));
    }
    m_open = true;
    err.clear();
    return true;
}

} // namespace modelnet
