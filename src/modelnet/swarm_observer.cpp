// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/plane.h>
#include <modelnet/swarm_form/atomic.h>
#include <modelnet/guard_supervisor.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_live.h>
#include <modelnet/swarm_node.h>
#include <modelnet/swarm_observer.h>

#include <crypto/sha384.h>
#include <logging.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>
#include <utility>

namespace modelnet {
namespace {

constexpr uint64_t kCatalogLimit = 32ull * 1024ull * 1024ull;

using Row = SwarmCatalogEntry;

std::atomic<bool> g_stop{false};
std::thread g_thread;
std::mutex g_mu;

bool IsSwarmId(std::string_view s)
{
    if (s.size() != 96) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool RejectSymlink(const fs::path& path, std::string& err)
{
    std::error_code ec;
    const fs::file_status st = fs::symlink_status(path, ec);
    if (ec) return true;
    if (fs::is_symlink(st)) {
        err = "CATALOG_SYMLINK";
        return false;
    }
    return true;
}

bool ReadBounded(const fs::path& path, std::string& raw, std::string& err)
{
    if (!RejectSymlink(path, err)) return false;
    if (!fs::exists(path)) return true;
    std::error_code ec;
    const auto sz = fs::file_size(path, ec);
    if (ec || sz > kCatalogLimit) {
        err = "CATALOG_LIMIT";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "CATALOG_READ";
        return false;
    }
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

UniValue RowJson(const Row& row)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("artifact_id", row.artifact_id);
    o.pushKV("automatic_activation", "FOLLOW_LOCAL_POLICY");
    o.pushKV("channel", "general/stable");
    o.pushKV("discovery", true);
    o.pushKV("idle_compute_authorized", false);
    o.pushKV("lineage_assurance", row.lineage_assurance);
    o.pushKV("lineage_id", row.lineage_id);
    o.pushKV("model_id", row.model_id);
    o.pushKV("private_data_training", false);
    o.pushKV("role", "observer");
    o.pushKV("visibility", row.visibility);
    return o;
}

bool LoadStored(const fs::path& path, std::map<std::string, Row>& rows, std::string& err)
{
    std::string raw;
    if (!ReadBounded(path, raw, err)) return false;
    if (raw.empty()) return true;
    UniValue root;
    if (!root.read(raw) || !root.isObject() || !root.exists("subscriptions") || !root["subscriptions"].isArray()) {
        err = "OBSERVER_SCHEMA";
        return false;
    }
    for (const UniValue& item : root["subscriptions"].getValues()) {
        if (!item.isObject()) {
            err = "OBSERVER_SCHEMA";
            return false;
        }
        for (const char* field : {"artifact_id", "model_id", "lineage_id", "lineage_assurance", "visibility"}) {
            if (!item[field].isStr()) {
                err = "OBSERVER_SCHEMA";
                return false;
            }
        }
        Row row;
        row.artifact_id = item["artifact_id"].get_str();
        row.model_id = item["model_id"].get_str();
        row.lineage_id = item["lineage_id"].get_str();
        row.lineage_assurance = item["lineage_assurance"].get_str();
        row.visibility = item["visibility"].get_str();
        if (!IsSwarmId(row.artifact_id) || !IsSwarmId(row.model_id) || !IsSwarmId(row.lineage_id)) {
            err = "ID";
            return false;
        }
        rows.insert_or_assign(row.artifact_id, std::move(row));
    }
    return true;
}

bool WriteStored(const fs::path& dir, const std::map<std::string, Row>& rows, std::string& err)
{
    fs::create_directories(dir);
    if (!fs::exists(dir)) {
        err = "OBSERVER_DIR";
        return false;
    }
    UniValue subs(UniValue::VARR);
    for (const auto& [id, row] : rows) {
        (void)id;
        subs.push_back(RowJson(row));
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("automatic_spend_atoms", "0");
    root.pushKV("payment_authority", false);
    root.pushKV("subscriptions", subs);
    const fs::path final_path = dir / "observers.json";
    const fs::path tmp = dir / "observers.json.tmp";
    if (!RejectSymlink(final_path, err) || !RejectSymlink(tmp, err)) return false;
    if (!SwarmFormWrite(final_path, root.write(0, 0) + "\n", err)) {
        err = err == "RENAME" ? "OBSERVER_RENAME" : "OBSERVER_WRITE";
        return false;
    }
    return true;
}

std::string DigestBytes(const std::string& raw)
{
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(raw.data()), raw.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

bool Fingerprint(const fs::path& path, std::string& out, std::string& err)
{
    out.clear();
    if (!fs::exists(path)) {
        out = "missing";
        return true;
    }
    std::error_code kind;
    // A fifo or directory must not be read. stat is enough; a read would block.
    if (!fs::is_regular_file(path, kind) || kind) {
        out = "skipped";
        return true;
    }
    std::error_code ec;
    const auto sz = fs::file_size(path, ec);
    if (ec) {
        err = "CATALOG_READ";
        return false;
    }
    if (sz > kCatalogLimit) {
        out = "limit";
        return true;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "CATALOG_READ";
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    out = DigestBytes(raw);
    return true;
}

struct InputGeneration {
    bool seen{false};
    std::string catalog;
    std::string mappings;
    std::string device;
    std::string peers;
    std::string native;
};

} // namespace

std::string SwarmProvisionalLineage(const std::string& model_id)
{
    const std::string body = "{\"model_id\":\"" + model_id + "\"}";
    static constexpr char domain[] = "BTX/ProvisionalModelTopic/1";
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(domain), sizeof(domain) - 1);
    const unsigned char sep = 0;
    hasher.Write(&sep, 1);
    hasher.Write(reinterpret_cast<const unsigned char*>(body.data()), body.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

bool SwarmReadCatalog(const fs::path& modeldir, SwarmCatalog& entries, std::string& err)
{
    entries.clear();
    err.clear();
    const fs::path catalog = modeldir / "catalog.json";
    const fs::path mappings = modeldir / "swarm" / "lineage-mappings.json";
    if (!RejectSymlink(catalog, err)) return false;
    if (!fs::exists(catalog)) return true;
    std::string raw;
    if (!ReadBounded(catalog, raw, err)) return false;
    UniValue root;
    if (!root.read(raw) || !root.isObject() || !root.exists("models") || !root["models"].isArray()) {
        err = "CATALOG_SCHEMA";
        return false;
    }
    UniValue map_root(UniValue::VOBJ);
    if (!RejectSymlink(mappings, err)) return false;
    if (fs::exists(mappings)) {
        std::string map_raw;
        if (!ReadBounded(mappings, map_raw, err)) return false;
        if (!map_raw.empty()) {
            if (!map_root.read(map_raw) || !map_root.isObject()) {
                err = "MAPPING_SCHEMA";
                return false;
            }
        }
    }
    // Index the mapping keys once; map_root.exists() and map_root[] are linear
    // scans, which made the loop below O(catalog rows x mapping keys).
    std::map<std::string_view, size_t> mapped;
    for (size_t i = 0; i < map_root.getKeys().size(); ++i) mapped.emplace(map_root.getKeys()[i], i);
    std::map<std::string, Row> fresh;
    for (const UniValue& item : root["models"].getValues()) {
        if (!item.isObject()) {
            err = "CATALOG_SCHEMA";
            return false;
        }
        const bool verified = item.exists("bytes_verified") && item["bytes_verified"].isBool() && item["bytes_verified"].get_bool();
        const bool complete = item.exists("incomplete") && item["incomplete"].isBool() && !item["incomplete"].get_bool();
        if (!verified || !complete) continue;
        if (!item.exists("artifact_id") || !item.exists("model_id") || !item["artifact_id"].isStr() || !item["model_id"].isStr()) {
            err = "ID";
            return false;
        }
        Row row;
        row.artifact_id = item["artifact_id"].get_str();
        row.model_id = item["model_id"].get_str();
        if (!IsSwarmId(row.artifact_id) || !IsSwarmId(row.model_id)) {
            err = "ID";
            return false;
        }
        if (const auto hit = mapped.find(row.artifact_id); hit != mapped.end()) {
            const UniValue& mapping = map_root.getValues()[hit->second];
            if (!mapping.isObject() || !mapping.exists("lineage_id") || !mapping["lineage_id"].isStr()) {
                err = "MAPPING_SCHEMA";
                return false;
            }
            row.lineage_id = mapping["lineage_id"].get_str();
            if (mapping.exists("visibility") && !mapping["visibility"].isStr()) {
                err = "VISIBILITY";
                return false;
            }
            row.visibility = mapping.exists("visibility") ? mapping["visibility"].get_str() : "private";
            if (!IsSwarmId(row.lineage_id) || (row.visibility != "private" && row.visibility != "public")) {
                err = "VISIBILITY";
                return false;
            }
            row.lineage_assurance = "VERIFIED_MAPPING";
        } else {
            row.lineage_id = SwarmProvisionalLineage(row.model_id);
            row.lineage_assurance = "PROVISIONAL_NOT_AUTHORITATIVE";
            row.visibility = "private";
        }
        for (const char* field : {"quantization", "checkpoint_id", "recipe"}) {
            if (item.exists(field) && !item[field].isStr()) {
                err = "CATALOG_SCHEMA";
                return false;
            }
        }
        if (item.exists("quantization")) row.quantization = item["quantization"].get_str();
        if (item.exists("checkpoint_id")) row.checkpoint = item["checkpoint_id"].get_str();
        if (item.exists("recipe")) row.recipe = item["recipe"].get_str();
        if (!fresh.emplace(row.artifact_id, row).second) {
            err = "CATALOG_DUPLICATE";
            return false;
        }
    }
    entries = std::move(fresh);
    return true;
}

bool SwarmObserveCatalog(const fs::path& modeldir, std::string& err)
{
    SwarmCatalog fresh;
    if (!SwarmReadCatalog(modeldir, fresh, err)) return false;
    const fs::path swarm_dir = modeldir / "swarm";
    const fs::path stored_path = swarm_dir / "observers.json";
    std::map<std::string, Row> rows;
    if (fs::exists(stored_path) && !LoadStored(stored_path, rows, err)) {
        // observers.json is derived from the catalog. Set a damaged copy aside
        // and write it again, instead of failing on every observer pass.
        if (err != "OBSERVER_SCHEMA" && err != "ID") return false;
        std::error_code ec;
        fs::rename(stored_path, fs::u8path(stored_path.utf8string() + ".bad"), ec);
        if (ec) {
            err = "OBSERVER_RENAME";
            return false;
        }
        rows.clear();
        err.clear();
    }
    bool changed = rows.size() != fresh.size();
    for (const auto& [id, row] : fresh) {
        const auto it = rows.find(id);
        if (it == rows.end() || it->second.model_id != row.model_id || it->second.lineage_id != row.lineage_id ||
            it->second.lineage_assurance != row.lineage_assurance || it->second.visibility != row.visibility) {
            changed = true;
        }
    }
    if (!changed && fs::exists(stored_path)) return true;
    if (fresh.empty() && rows.empty()) return true;
    return WriteStored(swarm_dir, fresh, err);
}

void StartSwarmObserver(const fs::path& modeldir)
{
    StopSwarmObserver();
    if (modeldir.empty()) return;
    g_stop.store(false);
    try {
    g_thread = std::thread([modeldir] {
        InputGeneration generation;
        GuardSupervisor guard;
        std::string guard_error;
        if (!guard.Start(FindPackagedGuardd(), guard_error)) {
            LogPrintf("swarm guard: %s (monetary node continues)\n", guard_error);
        }
        uint64_t guard_heartbeat = 0;
        std::string guard_stable;
        int64_t guard_written_at = 0;
        std::string last_observer_err;
        int observer_failures = 0;
        // A step that keeps failing is logged on its 1st, 8th and every 64th
        // pass, as a failed pass is below, instead of on every poll.
        std::map<std::string, std::pair<std::string, int>> step_failures;
        const auto report = [&](const std::string& step, bool step_ok, const std::string& error) {
            if (step_ok) {
                step_failures.erase(step);
                return;
            }
            auto& [last, count] = step_failures[step];
            if (error != last) {
                last = error;
                count = 0;
            }
            ++count;
            if (count == 1 || count == 8 || count % 64 == 0) {
                LogPrintf("%s: %s (monetary node continues, repeated %d)\n", step, error, count);
            }
        };
        auto publish_guard_status = [&](std::string& error) {
            const auto status = guard.Snapshot();
            const std::string phase = !status.enabled ? "STOPPED" : status.ready ? "READY" : "RESTARTING";
            const std::string stable = phase + "\n" + std::to_string(status.pid) + "\n" +
                                       std::to_string(status.restart_count) + "\n" + status.error + "\n" +
                                       (status.enabled ? "1" : "0") + (status.ready ? "1" : "0");
            const int64_t observed_at = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            // Refresh the lease before it expires. An unchanged guard does not
            // rewrite the file on every poll.
            if (stable == guard_stable && observed_at < guard_written_at + 20000) return true;
            UniValue state(UniValue::VOBJ);
            state.pushKV("schema", "BTX/GuardProcess/1");
            state.pushKV("enabled", status.enabled);
            state.pushKV("ready", status.ready);
            state.pushKV("state", phase);
            state.pushKV("pid", status.pid);
            state.pushKV("restart_count", status.restart_count);
            state.pushKV("error", status.error);
            state.pushKV("transport", "PRIVATE_INHERITED_STDIO");
            state.pushKV("automatic_spend_atoms", "0");
            state.pushKV("execution_authorized", false);
            state.pushKV("observed_at_ms", observed_at);
            // Readiness is a sampled observation. An abrupt parent exit
            // cannot leave an indefinitely current ready=true file.
            state.pushKV("valid_until_ms", status.enabled ? observed_at + 30000 : observed_at);
            state.pushKV("heartbeat_sequence", ++guard_heartbeat);
            const fs::path directory = modeldir / "swarm";
            if (!RejectSymlink(directory, error)) return false;
            fs::create_directories(directory);
            if (!SwarmFormWrite(directory / "guard-process.json", state.write() + "\n", error)) return false;
            guard_stable = stable;
            guard_written_at = observed_at;
            return true;
        };
        while (!g_stop.load()) {
            std::string err;
            bool ok = true;
            try {
                guard.Tick();
                const bool guard_ok = publish_guard_status(err);
                report("swarm guard status", guard_ok, err);
                if (!guard_ok) ok = false;
                std::lock_guard<std::mutex> lock(g_mu);
                InputGeneration now;
                if (!Fingerprint(modeldir / "catalog.json", now.catalog, err) ||
                    !Fingerprint(modeldir / "swarm" / "lineage-mappings.json", now.mappings, err) ||
                    !Fingerprint(modeldir / "swarm" / "device.json", now.device, err) ||
                    !Fingerprint(modeldir / "swarm" / "peers.json", now.peers, err) ||
                    !Fingerprint(modeldir / "swarm" / "native-participation.json", now.native, err)) {
                    ok = false;
                } else {
                    const bool catalog_changed = !generation.seen || now.catalog != generation.catalog ||
                                                 now.mappings != generation.mappings;
                    // Device, peer, and native fingerprints drive offers and publication.
                    // An existing native snapshot is not itself a change: its digest stays
                    // put while wall-clock peer expiry still has to run.
                    const bool mesh_files_changed = !generation.seen || now.device != generation.device ||
                                                    now.peers != generation.peers || now.native != generation.native;
                    const bool peer_clock = generation.seen && !mesh_files_changed && now.native != "missing" &&
                                            now.native != "skipped" && now.native != "limit";
                    bool retain = true;
                    if (catalog_changed) {
                        ok = SwarmObserveCatalog(modeldir, err);
                        if (!ok) retain = false;
                    }
                    if (ok && (catalog_changed || mesh_files_changed)) {
                        std::string mesh_err;
                        const bool mesh_ok = SwarmRefreshLocalMesh(modeldir, mesh_err);
                        report("swarm mesh", mesh_ok, mesh_err);
                        if (!mesh_ok) retain = false;
                        std::string join_err;
                        const bool join_ok = SwarmIntegrateCatalog(modeldir, join_err);
                        report("swarm join", join_ok, join_err);
                        if (!join_ok) {
                            retain = false;
                        } else {
                            const fs::path membership = modeldir / "swarm" / kMembershipFile;
                            if (catalog_changed || !fs::exists(membership)) {
                                std::string form_err;
                                const bool form_ok = SwarmFormPlane(modeldir, form_err);
                                report("swarm form", form_ok, form_err);
                                if (!form_ok) retain = false;
                            }
                            std::string live_err;
                            const bool live_ok = SwarmPublishLive(modeldir, live_err);
                            report("swarm live", live_ok, live_err);
                            if (!live_ok) retain = false;
                        }
                    } else if (ok && peer_clock) {
                        // Expiry is computed from observed_at_ms, so the mesh document can
                        // change without any input file changing. Do not republish the catalog.
                        std::string mesh_err;
                        const bool mesh_ok = SwarmRefreshLocalMesh(modeldir, mesh_err);
                        report("swarm mesh", mesh_ok, mesh_err);
                        if (!mesh_ok) retain = false;
                    }
                    if (ok && retain) {
                        now.seen = true;
                        generation = std::move(now);
                    }
                }
                // Qualification suites run explicitly against real processes;
                // production startup no longer runs/latches self-test records.
            } catch (const std::exception& e) {
                ok = false;
                err = e.what();
            }
            if (!ok) {
                if (err != last_observer_err) {
                    last_observer_err = err;
                    observer_failures = 0;
                }
                ++observer_failures;
                if (observer_failures == 1 || observer_failures == 8 || observer_failures % 64 == 0) {
                    LogPrintf("swarm observer: %s (monetary node continues, repeated %d)\n", err, observer_failures);
                }
            } else {
                last_observer_err.clear();
                observer_failures = 0;
            }
            for (int i = 0; i < 20 && !g_stop.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        guard.Stop();
        try {
            std::string error;
            if (!publish_guard_status(error)) {
                LogPrintf("swarm guard shutdown status: %s\n", error);
            }
        } catch (const std::exception& e) {
            LogPrintf("swarm guard shutdown status: %s\n", e.what());
        }
    });
    } catch (const std::exception& e) {
        LogPrintf("swarm observer: thread not started: %s (monetary node continues)\n", e.what());
    }
}

void StopSwarmObserver() noexcept
{
    g_stop.store(true);
    if (g_thread.joinable()) g_thread.join();
}

} // namespace modelnet
