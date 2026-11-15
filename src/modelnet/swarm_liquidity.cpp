// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_liquidity.h>

#include <univalue.h>

#include <charconv>
#include <fstream>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

bool EnsureDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = "SWARM_DIR";
        return false;
    }
    return true;
}

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
        if (!file) {
            err = "WRITE";
            return false;
        }
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

bool ParseInt(const UniValue& value, int64_t& out)
{
    if (!value.isNum()) return false;
    const std::string& text = value.getValStr();
    if (text.empty()) return false;
    int64_t parsed = 0;
    const char* const first = text.data();
    const char* const last = text.data() + text.size();
    const std::from_chars_result result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last) return false;
    out = parsed;
    return true;
}

bool HasForbiddenSpend(const UniValue& obj, std::string& err)
{
    if (obj.exists("spend")) {
        err = "SPEND";
        return true;
    }
    for (const char* key : {"automatic_spend", "automatic_spend_atoms"}) {
        if (!obj.exists(key)) continue;
        const UniValue& value = obj[key];
        if (value.isStr()) {
            if (value.get_str() == "0") continue;
            err = "SPEND";
            return true;
        }
        int64_t atoms = 0;
        if (!value.isNum() || !ParseInt(value, atoms) || atoms != 0) {
            err = "SPEND";
            return true;
        }
    }
    return false;
}

} // namespace

bool SwarmLiquidityBook::Open(int64_t capacity, std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    if (capacity <= 0) {
        err = "CAPACITY";
        return false;
    }
    m_open = true;
    m_frozen = false;
    m_capacity = capacity;
    m_rows.clear();
    err.clear();
    return true;
}

bool SwarmLiquidityBook::Reserve(const std::string& reservation_id, const std::string& pool_id, int64_t atoms,
                                 std::string& err)
{
    if (reservation_id.empty() || pool_id.empty() || atoms <= 0) {
        err = "RESERVE";
        return false;
    }
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (m_frozen) {
        err = "FROZEN";
        return false;
    }
    const auto it = m_rows.find(reservation_id);
    if (it != m_rows.end()) {
        if (it->second.pool_id == pool_id && it->second.atoms == atoms) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    const int64_t reserved = Reserved();
    if (reserved > m_capacity || atoms > m_capacity - reserved) {
        err = "DOUBLE_RESERVE";
        return false;
    }
    SwarmReservation row;
    row.reservation_id = reservation_id;
    row.pool_id = pool_id;
    row.atoms = atoms;
    row.frozen = false;
    m_rows.emplace(reservation_id, std::move(row));
    err.clear();
    return true;
}

bool SwarmLiquidityBook::Release(const std::string& reservation_id, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_rows.find(reservation_id);
    if (it == m_rows.end()) {
        err = "RESERVE_MISSING";
        return false;
    }
    m_rows.erase(it);
    err.clear();
    return true;
}

bool SwarmLiquidityBook::Freeze(std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    m_frozen = true;
    for (auto& item : m_rows) item.second.frozen = true;
    err.clear();
    return true;
}

int64_t SwarmLiquidityBook::Reserved() const
{
    int64_t sum = 0;
    for (const auto& item : m_rows) sum += item.second.atoms;
    return sum;
}

int64_t SwarmLiquidityBook::Available() const
{
    if (!m_open) return 0;
    const int64_t reserved = Reserved();
    if (reserved > m_capacity) return 0;
    return m_capacity - reserved;
}

bool SwarmLiquidityBook::Persist(const fs::path& modeldir, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue reservations(UniValue::VARR);
    for (const auto& item : m_rows) {
        const SwarmReservation& row = item.second;
        UniValue encoded(UniValue::VOBJ);
        encoded.pushKV("atoms", row.atoms);
        encoded.pushKV("frozen", row.frozen);
        encoded.pushKV("pool_id", row.pool_id);
        encoded.pushKV("reservation_id", row.reservation_id);
        reservations.push_back(std::move(encoded));
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("capacity", m_capacity);
    out.pushKV("frozen", m_frozen);
    out.pushKV("reservations", reservations);
    const fs::path final_path = swarm_dir / "liquidity.json";
    // Closed temp file, then rename. Success is only after the new file is in place.
    return WriteAtomic(final_path, out.write(0, 0) + "\n", err);
}

bool SwarmLiquidityBook::Load(const fs::path& modeldir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    const fs::path path = modeldir / "swarm" / "liquidity.json";
    std::string raw;
    UniValue root;
    if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject()) {
        err = "LOAD";
        return false;
    }
    if (HasForbiddenSpend(root, err)) return false;
    if (!root.exists("capacity") || !root.exists("frozen") || !root.exists("reservations") || !root["frozen"].isBool() ||
        !root["reservations"].isArray()) {
        err = "LOAD";
        return false;
    }
    int64_t capacity = 0;
    if (!ParseInt(root["capacity"], capacity) || capacity <= 0) {
        err = "LOAD";
        return false;
    }
    const bool frozen = root["frozen"].get_bool();
    std::map<std::string, SwarmReservation> rows;
    int64_t sum = 0;
    for (const UniValue& item : root["reservations"].getValues()) {
        if (!item.isObject() || HasForbiddenSpend(item, err)) {
            if (err != "SPEND") err = "LOAD";
            return false;
        }
        if (!item.exists("reservation_id") || !item.exists("pool_id") || !item.exists("atoms") ||
            !item["reservation_id"].isStr() || !item["pool_id"].isStr()) {
            err = "LOAD";
            return false;
        }
        SwarmReservation row;
        row.reservation_id = item["reservation_id"].get_str();
        row.pool_id = item["pool_id"].get_str();
        if (row.reservation_id.empty() || row.pool_id.empty() || !ParseInt(item["atoms"], row.atoms) || row.atoms <= 0) {
            err = "LOAD";
            return false;
        }
        if (item.exists("frozen")) {
            if (!item["frozen"].isBool()) {
                err = "LOAD";
                return false;
            }
            row.frozen = item["frozen"].get_bool();
        }
        if (row.atoms > capacity - sum) {
            err = "LOAD";
            return false;
        }
        sum += row.atoms;
        if (!rows.emplace(row.reservation_id, row).second) {
            err = "LOAD";
            return false;
        }
    }
    m_open = true;
    m_frozen = frozen;
    m_capacity = capacity;
    m_rows = std::move(rows);
    err.clear();
    return true;
}

} // namespace modelnet
