// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_lineage/dt_lineage.h>

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

constexpr char kMagic[] = "dt-lineage-v1";

struct Row {
    std::string generation;
    int64_t weight{0};
};

bool ParseI64(const std::string& text, int64_t& out)
{
    if (text.empty()) return false;
    std::size_t i = 0;
    bool neg = false;
    if (text[0] == '-') {
        neg = true;
        i = 1;
        if (i == text.size()) return false;
    }
    std::uint64_t mag = 0;
    for (; i < text.size(); ++i) {
        const char ch = text[i];
        if (ch < '0' || ch > '9') return false;
        const unsigned digit = static_cast<unsigned>(ch - '0');
        if (mag > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
        mag = mag * 10 + digit;
    }
    const std::uint64_t max_pos = static_cast<std::uint64_t>(std::numeric_limits<int64_t>::max());
    if (neg) {
        if (mag > max_pos + 1) return false;
        if (mag == max_pos + 1) {
            out = std::numeric_limits<int64_t>::min();
            return true;
        }
        out = -static_cast<int64_t>(mag);
        return true;
    }
    if (mag > max_pos) return false;
    out = static_cast<int64_t>(mag);
    return true;
}

class Cursor {
public:
    explicit Cursor(const std::string& raw) : m_raw(raw) {}

    bool TakeLine(std::string& line)
    {
        if (m_pos > m_raw.size()) return false;
        const std::size_t end = m_raw.find('\n', m_pos);
        if (end == std::string::npos) return false;
        line.assign(m_raw, m_pos, end - m_pos);
        m_pos = end + 1;
        return true;
    }

    bool TakeBytes(std::size_t n, std::string& out)
    {
        if (m_pos > m_raw.size() || n > m_raw.size() - m_pos) return false;
        out.assign(m_raw, m_pos, n);
        m_pos += n;
        if (m_pos >= m_raw.size() || m_raw[m_pos] != '\n') return false;
        ++m_pos;
        return true;
    }

    bool Done() const { return m_pos == m_raw.size(); }

private:
    const std::string& m_raw;
    std::size_t m_pos{0};
};

bool TakePrefixed(Cursor& cursor, const char* name, std::string& out)
{
    std::string line;
    if (!cursor.TakeLine(line)) return false;
    const std::string prefix = std::string(name) + " ";
    if (line.compare(0, prefix.size(), prefix) != 0) return false;
    std::uint64_t len = 0;
    int64_t parsed = 0;
    if (!ParseI64(line.substr(prefix.size()), parsed) || parsed < 0) return false;
    len = static_cast<std::uint64_t>(parsed);
    if (len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
    return cursor.TakeBytes(static_cast<std::size_t>(len), out);
}

std::string Encode(const std::vector<Row>& records)
{
    std::string out;
    out += kMagic;
    out += '\n';
    for (const Row& rec : records) {
        out += "generation ";
        out += std::to_string(rec.generation.size());
        out += '\n';
        out += rec.generation;
        out += '\n';
        out += "weight ";
        out += std::to_string(rec.weight);
        out += '\n';
    }
    return out;
}

bool Decode(const std::string& raw, std::vector<Row>& records)
{
    Cursor cursor(raw);
    std::string magic;
    if (!cursor.TakeLine(magic) || magic != kMagic) return false;
    std::vector<Row> parsed;
    while (!cursor.Done()) {
        Row rec;
        std::string weight_line;
        if (!TakePrefixed(cursor, "generation", rec.generation)) return false;
        if (rec.generation.empty()) return false;
        if (!cursor.TakeLine(weight_line)) return false;
        const std::string prefix = "weight ";
        if (weight_line.compare(0, prefix.size(), prefix) != 0) return false;
        if (!ParseI64(weight_line.substr(prefix.size()), rec.weight)) return false;
        parsed.push_back(std::move(rec));
    }
    if (parsed.empty()) return false;
    records = std::move(parsed);
    return true;
}

bool Contains(const std::vector<Row>& records, const std::string& generation)
{
    for (const Row& rec : records) {
        if (rec.generation == generation) return true;
    }
    return false;
}

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in && !in.eof()) return false;
    return true;
}

bool ReadRecords(const fs::path& path, std::vector<Row>& records, std::string& err)
{
    std::string raw;
    if (!ReadRaw(path, raw)) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    if (!Decode(raw, records)) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    err.clear();
    return true;
}

bool WriteRecords(const fs::path& path, const std::vector<Row>& records, std::string& err)
{
    const std::string body = Encode(records);
    const fs::path tmp = fs::u8path(path.utf8string() + ".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
        if (!out) {
            err = DT_LINEAGE_JOURNAL;
            return false;
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.close();
        if (!out) {
            err = DT_LINEAGE_JOURNAL;
            std::error_code ignore;
            fs::remove(tmp, ignore);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = DT_LINEAGE_JOURNAL;
        std::error_code ignore;
        fs::remove(tmp, ignore);
        return false;
    }
    err.clear();
    return true;
}

} // namespace

void DtLineage::ClearLive()
{
    m_records.clear();
    m_generation.clear();
    m_weight = static_cast<int64_t>(1);
}

void DtLineage::Apply(std::vector<Record> records)
{
    m_generation = records.back().generation;
    m_weight = records.back().weight;
    m_records = std::move(records);
}

fs::path DtLineage::JournalPath() const
{
    return m_dir / DT_LINEAGE_JOURNAL_NAME;
}

bool DtLineage::Open(const fs::path& dir, std::string& err)
{
    const std::string utf8 = dir.utf8string();
    if (utf8.empty()) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    const fs::path rebuilt = fs::u8path(utf8);
    try {
        fs::create_directories(rebuilt);
    } catch (const std::filesystem::filesystem_error&) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    if (!fs::exists(rebuilt)) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    m_dir = rebuilt;
    m_open = true;
    err.clear();
    return true;
}

bool DtLineage::Commit(const std::string& generation, int64_t weight, bool journal_ok, std::string& err)
{
    if (generation.empty()) {
        err = DT_LINEAGE_GENERATION;
        return false;
    }
    if (!journal_ok) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    if (!m_open) {
        err = DT_LINEAGE_JOURNAL;
        return false;
    }

    for (const Record& rec : m_records) {
        if (rec.generation == generation) {
            err = NIFDT_REPLAY;
            return false;
        }
    }

    std::vector<Row> records;
    records.reserve(m_records.size() + 1);
    for (const Record& rec : m_records) {
        Row row;
        row.generation = rec.generation;
        row.weight = rec.weight;
        records.push_back(std::move(row));
    }
    const fs::path journal = JournalPath();
    if (fs::exists(journal)) {
        std::vector<Row> stored;
        if (!ReadRecords(journal, stored, err)) return false;
        if (Contains(stored, generation)) {
            err = NIFDT_REPLAY;
            return false;
        }
        records = std::move(stored);
    }

    Row added;
    added.generation = generation;
    added.weight = weight;
    records.push_back(std::move(added));
    if (!WriteRecords(journal, records, err)) return false;

    std::vector<Record> applied;
    applied.reserve(records.size());
    for (Row& row : records) {
        Record rec;
        rec.generation = std::move(row.generation);
        rec.weight = row.weight;
        applied.push_back(std::move(rec));
    }
    Apply(std::move(applied));
    err.clear();
    return true;
}

bool DtLineage::Reload(std::string& err)
{
    if (!m_open) {
        ClearLive();
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    const fs::path journal = JournalPath();
    if (!fs::exists(journal)) {
        ClearLive();
        err = DT_LINEAGE_JOURNAL;
        return false;
    }
    std::vector<Row> stored;
    if (!ReadRecords(journal, stored, err)) return false;
    std::vector<Record> applied;
    applied.reserve(stored.size());
    for (Row& row : stored) {
        Record rec;
        rec.generation = std::move(row.generation);
        rec.weight = row.weight;
        applied.push_back(std::move(rec));
    }
    Apply(std::move(applied));
    err.clear();
    return true;
}

bool DtLineage::StepFailed(std::string& err)
{
    err = DT_LINEAGE_STEP;
    return false;
}

} // namespace modelnet
