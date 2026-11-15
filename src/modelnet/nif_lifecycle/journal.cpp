// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_lifecycle/journal.h>

#include <modelnet/nif_lifecycle/codes.h>
#include <modelnet/nifdt_contract/contract.h>

#include <util/fs.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

constexpr char kHex[] = "0123456789abcdef";

bool ParseU64(const std::string& text, std::uint64_t& out)
{
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (const char ch : text) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

class Cursor {
public:
    explicit Cursor(const std::string& raw) : m_raw(raw) {}

    bool TakeLine(std::string& line)
    {
        if (m_pos > m_raw.size()) {
            return false;
        }
        const std::size_t end = m_raw.find('\n', m_pos);
        if (end == std::string::npos) {
            return false;
        }
        line.assign(m_raw, m_pos, end - m_pos);
        m_pos = end + 1;
        return true;
    }

    bool TakeBytes(std::size_t n, std::string& out)
    {
        if (m_pos > m_raw.size() || n > m_raw.size() - m_pos) {
            return false;
        }
        out.assign(m_raw, m_pos, n);
        m_pos += n;
        if (m_pos >= m_raw.size() || m_raw[m_pos] != '\n') {
            return false;
        }
        ++m_pos;
        return true;
    }

    bool Done() const { return m_pos == m_raw.size(); }

private:
    const std::string& m_raw;
    std::size_t m_pos{0};
};

bool TakeString(Cursor& cursor, const char* name, std::string& out)
{
    std::string line;
    if (!cursor.TakeLine(line)) {
        return false;
    }
    const std::string prefix = std::string(name) + " ";
    if (line.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    std::uint64_t len = 0;
    if (!ParseU64(line.substr(prefix.size()), len)) {
        return false;
    }
    if (len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }
    return cursor.TakeBytes(static_cast<std::size_t>(len), out);
}

bool TakeU64(Cursor& cursor, const char* name, std::uint64_t& out)
{
    std::string line;
    if (!cursor.TakeLine(line)) {
        return false;
    }
    const std::string prefix = std::string(name) + " ";
    if (line.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return ParseU64(line.substr(prefix.size()), out);
}

bool TakeBool(Cursor& cursor, const char* name, bool& out)
{
    std::string line;
    if (!cursor.TakeLine(line)) {
        return false;
    }
    const std::string prefix = std::string(name) + " ";
    if (line == prefix + "0") {
        out = false;
        return true;
    }
    if (line == prefix + "1") {
        out = true;
        return true;
    }
    return false;
}

void PutString(std::string& out, const char* name, const std::string& value)
{
    out += name;
    out += ' ';
    out += std::to_string(value.size());
    out += '\n';
    out += value;
    out += '\n';
}

void PutU64(std::string& out, const char* name, std::uint64_t value)
{
    out += name;
    out += ' ';
    out += std::to_string(value);
    out += '\n';
}

void PutBool(std::string& out, const char* name, bool value)
{
    out += name;
    out += ' ';
    out += value ? '1' : '0';
    out += '\n';
}

std::string Encode(const NifRequestRecord& record)
{
    std::string out;
    out += kNifLifecycleJournalMagic;
    out += '\n';
    PutString(out, "principal", record.principal);
    PutString(out, "receiver", record.receiver);
    PutString(out, "realm", record.realm);
    PutString(out, "generation", record.generation);
    PutString(out, "runtime_image", record.runtime_image);
    PutString(out, "commitment", record.commitment);
    PutString(out, "attempt", record.attempt);
    PutU64(out, "epoch", record.epoch);
    PutU64(out, "ceiling_bytes", record.ceiling_bytes);
    PutU64(out, "lease_until_ms", record.lease_until_ms);
    PutBool(out, "cancelled", record.cancelled);
    PutU64(out, "output_ceiling", record.output_ceiling);
    PutString(out, "accepted_output", record.accepted_output);
    PutString(out, "economic_contract", record.economic_contract);
    return out;
}

bool Decode(const std::string& raw, NifRequestRecord& record)
{
    Cursor cursor(raw);
    std::string magic;
    if (!cursor.TakeLine(magic) || magic != kNifLifecycleJournalMagic) {
        return false;
    }
    NifRequestRecord parsed;
    if (!TakeString(cursor, "principal", parsed.principal) ||
        !TakeString(cursor, "receiver", parsed.receiver) ||
        !TakeString(cursor, "realm", parsed.realm) ||
        !TakeString(cursor, "generation", parsed.generation) ||
        !TakeString(cursor, "runtime_image", parsed.runtime_image) ||
        !TakeString(cursor, "commitment", parsed.commitment) ||
        !TakeString(cursor, "attempt", parsed.attempt) ||
        !TakeU64(cursor, "epoch", parsed.epoch) ||
        !TakeU64(cursor, "ceiling_bytes", parsed.ceiling_bytes) ||
        !TakeU64(cursor, "lease_until_ms", parsed.lease_until_ms) ||
        !TakeBool(cursor, "cancelled", parsed.cancelled) ||
        !TakeU64(cursor, "output_ceiling", parsed.output_ceiling) ||
        !TakeString(cursor, "accepted_output", parsed.accepted_output) ||
        !TakeString(cursor, "economic_contract", parsed.economic_contract) ||
        !cursor.Done()) {
        return false;
    }
    record = std::move(parsed);
    return true;
}

bool IsSymlink(const fs::path& path)
{
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    return !ec && fs::is_symlink(status);
}

} // namespace

fs::path NifLifecycleJournalPath(const fs::path& journal_dir, const std::string& attempt)
{
    std::string name;
    name.reserve(attempt.size() * 2 + 4);
    for (const char ch : attempt) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        name.push_back(kHex[byte >> 4]);
        name.push_back(kHex[byte & 0x0f]);
    }
    name += ".nif";
    return journal_dir / fs::u8path(name);
}

bool NifLifecycleJournalWrite(const fs::path& path, const NifRequestRecord& record, std::string& err)
{
    if (IsSymlink(path)) {
        err = kNifLifecycleSymlink;
        return false;
    }
    try {
        fs::create_directories(path.parent_path());
    } catch (const std::filesystem::filesystem_error&) {
        err = kNifLifecycleWrite;
        return false;
    }
    const std::string body = Encode(record);
    const fs::path tmp = fs::u8path(path.utf8string() + ".tmp");
    if (IsSymlink(tmp)) {
        err = kNifLifecycleSymlink;
        return false;
    }
    {
        std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = kNifLifecycleWrite;
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.close();
        if (!out) {
            err = kNifLifecycleWrite;
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = kNifLifecycleRename;
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    err.clear();
    return true;
}

bool NifLifecycleJournalRead(const fs::path& path, NifRequestRecord& record, std::string& err)
{
    if (IsSymlink(path)) {
        err = kNifLifecycleSymlink;
        return false;
    }
    if (!fs::exists(path)) {
        err = kNifLifecycleJournal;
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = kNifLifecycleJournal;
        return false;
    }
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (!in && !in.eof()) {
        err = kNifLifecycleJournal;
        return false;
    }
    NifRequestRecord parsed;
    if (!Decode(raw, parsed)) {
        err = kNifLifecycleJournal;
        return false;
    }
    record = std::move(parsed);
    err.clear();
    return true;
}

} // namespace modelnet
