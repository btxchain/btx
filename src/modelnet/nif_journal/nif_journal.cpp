// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_journal/nif_journal.h>

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <fstream>
#include <string>
#include <system_error>

namespace modelnet {
namespace {

std::string Encode(const NifRequestRecord& record, const std::string& outbox)
{
    std::string body;
    body += record.principal;
    body += '\n';
    body += record.receiver;
    body += '\n';
    body += record.generation;
    body += '\n';
    body += record.attempt;
    body += '\n';
    body += outbox;
    body += '\n';
    return body;
}

/** Attempt line of an existing journal, or empty when the file is absent. */
std::string ReadAttempt(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::string();
    }
    std::string line;
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(in, line)) {
            return std::string();
        }
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

bool WriteJournal(const fs::path& final_path, const std::string& body, std::string& err)
{
    try {
        fs::create_directories(final_path.parent_path());
    } catch (const std::filesystem::filesystem_error&) {
        err = NIF_JOURNAL_JOURNAL;
        return false;
    }
    const fs::path tmp = fs::u8path(final_path.utf8string() + ".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = NIF_JOURNAL_JOURNAL;
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.close();
        if (!out) {
            err = NIF_JOURNAL_JOURNAL;
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = NIF_JOURNAL_JOURNAL;
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    err.clear();
    return true;
}

} // namespace

bool NifJournal::Accept(const fs::path& dir, const NifRequestRecord& record, const std::string& outbox, bool journal_ok, std::string& err)
{
    if (dir.utf8string().empty()) {
        err = NIF_JOURNAL_DIR;
        return false;
    }
    if (record.principal.empty() || record.receiver.empty() || record.generation.empty() || record.attempt.empty()) {
        err = NIF_JOURNAL_REQUEST;
        return false;
    }
    if (outbox.empty()) {
        err = NIF_JOURNAL_OUTBOX;
        return false;
    }
    if (!journal_ok) {
        err = NIF_JOURNAL_JOURNAL;
        return false;
    }
    if (m_have && m_attempt == record.attempt) {
        err = NIFDT_REPLAY;
        return false;
    }
    const fs::path root = fs::u8path(dir.utf8string());
    const fs::path final_path = root / NIF_JOURNAL_FILE;
    const std::string stored = ReadAttempt(final_path);
    if (!stored.empty() && stored == record.attempt) {
        m_have = true;
        m_attempt = record.attempt;
        err = NIFDT_REPLAY;
        return false;
    }
    if (!WriteJournal(final_path, Encode(record, outbox), err)) {
        return false;
    }
    m_have = true;
    m_attempt = record.attempt;
    err.clear();
    return true;
}

} // namespace modelnet
