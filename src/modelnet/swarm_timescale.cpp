// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_timescale.h>

#include <univalue.h>

#include <fstream>
#include <iterator>

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

bool ScaleOf(const std::string& scale, const std::string& kind, std::string& err)
{
    if (kind == "prompt" || kind == "repository" || kind == "credential") {
        err = "PRIVATE_DATA";
        return false;
    }
    if (scale == "immediate" && (kind == "finding" || kind == "kv_page")) return true;
    if (scale == "short" && (kind == "strategy" || kind == "tool" || kind == "benchmark" || kind == "evaluation")) return true;
    if (scale == "medium" && (kind == "adapter" || kind == "finetune")) return true;
    if (scale == "long" && (kind == "generation" || kind == "candidate")) return true;
    err = "TIMESCALE";
    return false;
}

UniValue ArrayOrEmpty(const UniValue& root, const char* key, std::string& err)
{
    if (!root.exists(key)) return UniValue(UniValue::VARR);
    if (!root[key].isArray()) {
        err = "TIMESCALE_JSON";
        return UniValue(UniValue::VARR);
    }
    return root[key];
}

} // namespace

bool SwarmRecordTimescale(const fs::path& modeldir, const std::string& scale, const std::string& kind,
                          const std::string& body, const std::string& checkpoint_id, const std::string& recipe,
                          std::string& err)
{
    if (!ScaleOf(scale, kind, err)) return false;
    if ((scale == "medium" || scale == "long") && (checkpoint_id.empty() || (scale == "medium" && recipe.empty()))) {
        err = "TIMESCALE_COMPAT";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    const fs::path path = swarm_dir / "timescales.json";
    UniValue root(UniValue::VOBJ);
    if (fs::exists(path)) {
        std::string raw;
        if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject()) {
            err = "TIMESCALE_JSON";
            return false;
        }
    }
    UniValue immediate = ArrayOrEmpty(root, "immediate", err);
    if (err == "TIMESCALE_JSON") return false;
    UniValue short_term = ArrayOrEmpty(root, "short", err);
    if (err == "TIMESCALE_JSON") return false;
    UniValue medium = ArrayOrEmpty(root, "medium", err);
    if (err == "TIMESCALE_JSON") return false;
    UniValue long_term = ArrayOrEmpty(root, "long", err);
    if (err == "TIMESCALE_JSON") return false;
    UniValue row(UniValue::VOBJ);
    row.pushKV("body", body);
    row.pushKV("checkpoint_id", checkpoint_id);
    row.pushKV("kind", kind);
    row.pushKV("recipe", recipe);
    if (scale == "immediate") immediate.push_back(std::move(row));
    else if (scale == "short") short_term.push_back(std::move(row));
    else if (scale == "medium") medium.push_back(std::move(row));
    else long_term.push_back(std::move(row));
    UniValue out(UniValue::VOBJ);
    out.pushKV("automatic_spend_atoms", "0");
    out.pushKV("general_stable", "unchanged");
    out.pushKV("immediate", immediate);
    out.pushKV("long", long_term);
    out.pushKV("medium", medium);
    out.pushKV("short", short_term);
    return WriteAtomic(path, out.write(0, 0) + "\n", err);
}

bool SwarmReuseFinding(const fs::path& modeldir, const std::string& query, std::string& found, std::string& err)
{
    found.clear();
    if (query.empty()) {
        err = "NOT_FOUND";
        return false;
    }
    const fs::path path = modeldir / "swarm" / "timescales.json";
    std::string raw;
    UniValue root;
    if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject() || !root.exists("immediate") || !root["immediate"].isArray()) {
        err = "NOT_FOUND";
        return false;
    }
    for (const UniValue& item : root["immediate"].getValues()) {
        if (!item.isObject() || !item.exists("kind") || item["kind"].get_str() != "finding") continue;
        if (!item.exists("body") || !item["body"].isStr()) continue;
        const std::string body = item["body"].get_str();
        if (body.find(query) != std::string::npos) {
            found = body;
            err.clear();
            return true;
        }
    }
    err = "NOT_FOUND";
    return false;
}

bool SwarmWithinMemory(int64_t used_bytes, int64_t cap_bytes, std::string& err)
{
    if (cap_bytes <= 0 || used_bytes < 0 || used_bytes > cap_bytes) {
        err = "MEMORY_CAP";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
