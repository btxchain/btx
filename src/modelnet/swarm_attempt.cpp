// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_attempt.h>

#include <univalue.h>
#include <util/fs.h>

#include <exception>
#include <fstream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace modelnet {
namespace {

const char* const AUTOMATIC_SPEND_ATOMS = "0";

bool SameLease(const SwarmAttempt& stored, const SwarmAttempt& incoming)
{
    return stored.worker_id == incoming.worker_id && stored.checkpoint_id == incoming.checkpoint_id &&
           stored.recipe == incoming.recipe && stored.batch_size == incoming.batch_size &&
           stored.expiry_ms == incoming.expiry_ms;
}

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

bool FitInt(int64_t value, int& out)
{
    if (value < 0 || value > static_cast<int64_t>(std::numeric_limits<int>::max())) return false;
    out = static_cast<int>(value);
    return true;
}

bool ParseAttempts(const std::string& raw, std::vector<SwarmAttempt>& rows, std::string& err)
{
    try {
        UniValue root;
        if (!root.read(raw) || !root.isObject() || !root.exists("automatic_spend_atoms") ||
            !root["automatic_spend_atoms"].isStr() || root["automatic_spend_atoms"].get_str() != AUTOMATIC_SPEND_ATOMS ||
            root.exists("spend_key") || !root.exists("attempts") || !root["attempts"].isArray()) {
            err = "READ";
            return false;
        }
        std::vector<SwarmAttempt> parsed;
        for (const UniValue& item : root["attempts"].getValues()) {
            if (!item.isObject() || item.exists("spend_key") || !item.exists("attempt_id") || !item["attempt_id"].isStr() ||
                !item.exists("worker_id") || !item["worker_id"].isStr() || !item.exists("checkpoint_id") ||
                !item["checkpoint_id"].isStr() || !item.exists("recipe") || !item["recipe"].isStr() ||
                !item.exists("expiry_ms") || !item["expiry_ms"].isNum() || !item.exists("batch_size") ||
                !item["batch_size"].isNum() || !item.exists("accepted") || !item["accepted"].isNum() ||
                !item.exists("quiescent") || !item["quiescent"].isBool()) {
                err = "READ";
                return false;
            }
            SwarmAttempt row;
            row.attempt_id = item["attempt_id"].get_str();
            row.worker_id = item["worker_id"].get_str();
            row.checkpoint_id = item["checkpoint_id"].get_str();
            row.recipe = item["recipe"].get_str();
            row.expiry_ms = item["expiry_ms"].getInt<int64_t>();
            int batch_size = 0;
            int accepted = 0;
            if (row.attempt_id.empty() || row.worker_id.empty() || row.checkpoint_id.empty() || row.recipe.empty() ||
                !FitInt(item["batch_size"].getInt<int64_t>(), batch_size) || batch_size <= 0 ||
                !FitInt(item["accepted"].getInt<int64_t>(), accepted) || accepted > batch_size) {
                err = "READ";
                return false;
            }
            row.batch_size = batch_size;
            row.accepted = accepted;
            row.quiescent = item["quiescent"].get_bool();
            for (const SwarmAttempt& prior : parsed) {
                if (prior.attempt_id == row.attempt_id) {
                    err = "READ";
                    return false;
                }
            }
            parsed.push_back(std::move(row));
        }
        rows = std::move(parsed);
    } catch (const std::exception&) {
        err = "READ";
        return false;
    }
    err.clear();
    return true;
}

} // namespace

SwarmAttempt* SwarmAttemptBook::Find(const std::string& attempt_id)
{
    for (SwarmAttempt& row : m_rows) {
        if (row.attempt_id == attempt_id) return &row;
    }
    return nullptr;
}

bool SwarmAttemptBook::Grant(const SwarmAttempt& attempt, int64_t now_ms, std::string& err)
{
    if (attempt.attempt_id.empty() || attempt.worker_id.empty() || attempt.checkpoint_id.empty() ||
        attempt.recipe.empty() || attempt.batch_size <= 0) {
        err = "ATTEMPT";
        return false;
    }
    if (attempt.expiry_ms <= now_ms) {
        err = "EXPIRED";
        return false;
    }
    if (SwarmAttempt* existing = Find(attempt.attempt_id)) {
        if (!SameLease(*existing, attempt)) {
            err = "CONFLICT";
            return false;
        }
        err.clear();
        return true;
    }
    SwarmAttempt row = attempt;
    row.accepted = 0;
    row.quiescent = false;
    m_rows.push_back(std::move(row));
    err.clear();
    return true;
}

bool SwarmAttemptBook::Heartbeat(const std::string& attempt_id, int64_t now_ms, bool quiescent, std::string& err)
{
    SwarmAttempt* row = Find(attempt_id);
    if (row == nullptr) {
        err = "ATTEMPT";
        return false;
    }
    if (now_ms >= row->expiry_ms) {
        err = "EXPIRED";
        return false;
    }
    row->quiescent = quiescent;
    err.clear();
    return true;
}

bool SwarmAttemptBook::AcceptOne(const std::string& attempt_id, int64_t now_ms, std::string& err)
{
    SwarmAttempt* row = Find(attempt_id);
    if (row == nullptr) {
        err = "ATTEMPT";
        return false;
    }
    if (now_ms >= row->expiry_ms) {
        err = "EXPIRED";
        return false;
    }
    if (!row->quiescent) {
        err = "QUIESCENT";
        return false;
    }
    if (row->accepted >= row->batch_size) {
        err = "BATCH_FULL";
        return false;
    }
    row->accepted += 1;
    err.clear();
    return true;
}

int SwarmAttemptBook::Active(int64_t now_ms) const
{
    int count = 0;
    for (const SwarmAttempt& row : m_rows) {
        if (row.expiry_ms > now_ms) ++count;
    }
    return count;
}

bool SwarmAttemptBook::Persist(const fs::path& modeldir, std::string& err)
{
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue attempts(UniValue::VARR);
    for (const SwarmAttempt& row : m_rows) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("accepted", row.accepted);
        item.pushKV("attempt_id", row.attempt_id);
        item.pushKV("batch_size", row.batch_size);
        item.pushKV("checkpoint_id", row.checkpoint_id);
        item.pushKV("expiry_ms", row.expiry_ms);
        item.pushKV("quiescent", row.quiescent);
        item.pushKV("recipe", row.recipe);
        item.pushKV("worker_id", row.worker_id);
        attempts.push_back(std::move(item));
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("attempts", std::move(attempts));
    root.pushKV("automatic_spend_atoms", AUTOMATIC_SPEND_ATOMS);
    return WriteAtomic(swarm_dir / "attempts.json", root.write(0, 0) + "\n", err);
}

bool SwarmAttemptBook::Load(const fs::path& modeldir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    std::string raw;
    if (!ReadRaw(modeldir / "swarm" / "attempts.json", raw)) {
        err = "READ";
        return false;
    }
    std::vector<SwarmAttempt> rows;
    if (!ParseAttempts(raw, rows, err)) return false;
    m_rows = std::move(rows);
    err.clear();
    return true;
}

} // namespace modelnet
