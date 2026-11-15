// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clearing.h>

#include <univalue.h>
#include <util/fs.h>

#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <system_error>
#include <vector>

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

bool AddDelta(__int128& slot, int64_t change)
{
    const __int128 next = slot + static_cast<__int128>(change);
    if (next > static_cast<__int128>(std::numeric_limits<int64_t>::max()) ||
        next < static_cast<__int128>(std::numeric_limits<int64_t>::min())) {
        return false;
    }
    slot = next;
    return true;
}

bool ParseClearing(const std::string& raw, int64_t& capacity, int64_t& sequence,
                   std::map<std::string, int64_t>& balances, std::set<std::string>& seen, std::string& err)
{
    try {
        UniValue root;
        if (!root.read(raw) || !root.isObject() || !root.exists("automatic_spend_atoms") ||
            !root["automatic_spend_atoms"].isStr() || root["automatic_spend_atoms"].get_str() != "0" ||
            !root.exists("broadcast") || !root["broadcast"].isFalse() || !root.exists("capacity") ||
            !root["capacity"].isNum() || !root.exists("sequence") || !root["sequence"].isNum() ||
            !root.exists("balances") || !root["balances"].isArray() || !root.exists("seen") ||
            !root["seen"].isArray()) {
            err = "CLEARING_JSON";
            return false;
        }
        capacity = root["capacity"].getInt<int64_t>();
        sequence = root["sequence"].getInt<int64_t>();
        if (capacity <= 0 || sequence < 0) {
            err = "CLEARING_JSON";
            return false;
        }
        __int128 sum = 0;
        for (const UniValue& row : root["balances"].getValues()) {
            if (!row.isObject() || !row.exists("pool_id") || !row["pool_id"].isStr() || !row.exists("atoms") ||
                !row["atoms"].isNum()) {
                err = "CLEARING_JSON";
                return false;
            }
            const std::string pool_id = row["pool_id"].get_str();
            const int64_t atoms = row["atoms"].getInt<int64_t>();
            if (pool_id.empty() || atoms < 0 || !balances.emplace(pool_id, atoms).second) {
                err = "CLEARING_JSON";
                return false;
            }
            sum += static_cast<__int128>(atoms);
        }
        if (balances.empty() || sum != static_cast<__int128>(capacity)) {
            err = "CLEARING_JSON";
            return false;
        }
        for (const UniValue& item : root["seen"].getValues()) {
            if (!item.isStr()) {
                err = "CLEARING_JSON";
                return false;
            }
            seen.insert(item.get_str());
        }
    } catch (const std::exception&) {
        err = "CLEARING_JSON";
        return false;
    }
    return true;
}

} // namespace

bool SwarmClearingBook::Open(int64_t capacity, const std::vector<SwarmPoolSlice>& slices, std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    if (capacity <= 0) {
        err = "CAPACITY";
        return false;
    }
    if (slices.empty()) {
        err = "SLICE";
        return false;
    }
    std::map<std::string, int64_t> balances;
    __int128 sum = 0;
    for (const SwarmPoolSlice& slice : slices) {
        if (slice.pool_id.empty() || slice.reserved <= 0) {
            err = "SLICE";
            return false;
        }
        if (!balances.emplace(slice.pool_id, slice.reserved).second) {
            err = "DUPLICATE_POOL";
            return false;
        }
        sum += static_cast<__int128>(slice.reserved);
    }
    if (sum != static_cast<__int128>(capacity)) {
        err = "CAPACITY";
        return false;
    }
    m_capacity = capacity;
    m_sequence = 0;
    m_balances.swap(balances);
    m_seen.clear();
    m_open = true;
    err.clear();
    return true;
}

bool SwarmClearingBook::Apply(const std::vector<SwarmCoordinatedPayment>& payments, SwarmClearingReceipt& receipt,
                              std::string& err)
{
    if (payments.empty()) {
        err = "EMPTY";
        return false;
    }
    std::set<std::string> batch_ids;
    std::map<std::string, __int128> delta;
    for (const SwarmCoordinatedPayment& payment : payments) {
        if (m_balances.find(payment.from_pool) == m_balances.end() ||
            m_balances.find(payment.to_pool) == m_balances.end()) {
            err = "POOL";
            return false;
        }
        if (payment.atoms <= 0) {
            err = "AMOUNT";
            return false;
        }
        if (payment.from_pool == payment.to_pool) {
            err = "SELF";
            return false;
        }
        if (m_seen.count(payment.payment_id) != 0 || !batch_ids.insert(payment.payment_id).second) {
            err = "REPLAY";
            return false;
        }
        __int128& from_delta = delta[payment.from_pool];
        __int128& to_delta = delta[payment.to_pool];
        if (!AddDelta(from_delta, -payment.atoms) || !AddDelta(to_delta, payment.atoms)) {
            err = "INSUFFICIENT";
            return false;
        }
    }
    std::map<std::string, int64_t> scratch = m_balances;
    for (const auto& entry : delta) {
        auto it = scratch.find(entry.first);
        if (it == scratch.end()) {
            err = "POOL";
            return false;
        }
        const __int128 next = static_cast<__int128>(it->second) + entry.second;
        if (next < 0 || next > static_cast<__int128>(std::numeric_limits<int64_t>::max())) {
            err = "INSUFFICIENT";
            return false;
        }
        it->second = static_cast<int64_t>(next);
    }
    m_balances.swap(scratch);
    m_seen.insert(batch_ids.begin(), batch_ids.end());
    ++m_sequence;
    int close_outputs = 0;
    for (const auto& entry : m_balances) {
        if (entry.second > 0) ++close_outputs;
    }
    receipt.sequence = m_sequence;
    receipt.payments = static_cast<int>(payments.size());
    receipt.l1_transactions = 0;
    receipt.close_outputs = close_outputs;
    receipt.broadcast = false;
    receipt.automatic_spend_atoms = "0";
    err.clear();
    return true;
}

int64_t SwarmClearingBook::Balance(const std::string& pool_id) const
{
    const auto it = m_balances.find(pool_id);
    if (it == m_balances.end()) return 0;
    return it->second;
}

std::vector<std::pair<std::string, int64_t>> SwarmClearingBook::Balances() const
{
    return {m_balances.begin(), m_balances.end()};
}

int64_t SwarmClearingBook::Sequence() const
{
    return m_sequence;
}

bool SwarmClearingBook::Persist(const fs::path& modeldir, std::string& err)
{
    if (!m_open) {
        err = "CLOSED";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue out(UniValue::VOBJ);
    out.pushKV("automatic_spend_atoms", "0");
    UniValue balances(UniValue::VARR);
    for (const auto& entry : m_balances) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("atoms", entry.second);
        row.pushKV("pool_id", entry.first);
        balances.push_back(std::move(row));
    }
    out.pushKV("balances", balances);
    out.pushKV("broadcast", false);
    out.pushKV("capacity", m_capacity);
    UniValue seen(UniValue::VARR);
    for (const std::string& payment_id : m_seen) seen.push_back(payment_id);
    out.pushKV("seen", seen);
    out.pushKV("sequence", m_sequence);
    return WriteAtomic(swarm_dir / "clearing.json", out.write(0, 0) + "\n", err);
}

bool SwarmClearingBook::Load(const fs::path& modeldir, std::string& err)
{
    const fs::path path = modeldir / "swarm" / "clearing.json";
    if (!fs::exists(path)) {
        err = "CLEARING_READ";
        return false;
    }
    std::string raw;
    if (!ReadRaw(path, raw)) {
        err = "CLEARING_READ";
        return false;
    }
    int64_t capacity = 0;
    int64_t sequence = 0;
    std::map<std::string, int64_t> balances;
    std::set<std::string> seen;
    if (!ParseClearing(raw, capacity, sequence, balances, seen, err)) return false;
    m_capacity = capacity;
    m_sequence = sequence;
    m_balances.swap(balances);
    m_seen.swap(seen);
    m_open = true;
    err.clear();
    return true;
}

bool SwarmBuildClearingClose(const SwarmClearingBook& book, const Txid& funding,
                             const std::map<std::string, std::vector<unsigned char>>& scripts,
                             const std::string& worker_pool, int64_t previous_worker_atoms, SwarmClearingClose& out,
                             std::string& err)
{
    out.tx = CMutableTransaction();
    out.templates = 0;
    out.outputs = 0;
    out.broadcast = false;
    const std::vector<std::pair<std::string, int64_t>> balances = book.Balances();
    if (balances.empty()) {
        err = "CLOSED";
        return false;
    }
    const int64_t worker_atoms = book.Balance(worker_pool);
    if (!worker_pool.empty() && worker_atoms < previous_worker_atoms) {
        err = "DECREASING_PAYMENT";
        return false;
    }
    out.tx.vin.emplace_back(COutPoint(funding, 0));
    int64_t sum = 0;
    for (const auto& entry : balances) {
        if (entry.second <= 0) continue;
        const auto script = scripts.find(entry.first);
        if (script == scripts.end() || script->second.empty()) {
            err = "CLOSE_SCRIPT";
            return false;
        }
        out.tx.vout.emplace_back(entry.second, CScript(script->second.begin(), script->second.end()));
        sum += entry.second;
    }
    int64_t expected = 0;
    for (const auto& entry : balances) expected += entry.second;
    if (sum != expected || out.tx.vout.empty() || out.tx.vin.size() != 1) {
        err = "CLOSE_CONSERVATION";
        return false;
    }
    out.templates = 1;
    out.outputs = static_cast<int>(out.tx.vout.size());
    out.broadcast = false;
    err.clear();
    return true;
}

} // namespace modelnet
