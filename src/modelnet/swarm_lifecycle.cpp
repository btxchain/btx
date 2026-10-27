// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lifecycle.h>

#include <modelnet/swarm_codec.h>
#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_observer.h>

#include <univalue.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <thread>

namespace modelnet {
namespace {

bool Blocked(const SwarmDevice& device)
{
    return device.battery || device.thermal_hot || device.metered;
}

// device.json, peers.json and mesh-state.json are a few hundred bytes to a few
// kB. The observer reads them on every failing pass, so bound the read.
constexpr uint64_t kSwarmFileLimit = 1024ull * 1024ull;

bool ReadFile(const fs::path& path, std::string& raw)
{
    if (!fs::exists(path)) return true;
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec || size > kSwarmFileLimit) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

int HardwareThreads()
{
    unsigned threads = std::thread::hardware_concurrency();
    if (threads == 0) threads = 1;
    if (threads > 64) threads = 64;
    return static_cast<int>(threads);
}

UniValue SortedJson(const UniValue& value)
{
    if (value.isObject()) {
        // Sort positions, not keys: value[key] and pushKV are linear scans, so
        // the old loop was quadratic in the key count of the file on disk.
        const std::vector<std::string>& keys = value.getKeys();
        const std::vector<UniValue>& values = value.getValues();
        std::vector<size_t> order(keys.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return keys[a] < keys[b]; });
        UniValue out(UniValue::VOBJ);
        for (size_t n = 0; n < order.size(); ++n) {
            // A repeated key keeps its first value, as value[key] did.
            if (n > 0 && keys[order[n]] == keys[order[n - 1]]) continue;
            out.pushKVEnd(keys[order[n]], SortedJson(values[order[n]]));
        }
        return out;
    }
    if (value.isArray()) {
        UniValue out(UniValue::VARR);
        for (const UniValue& item : value.getValues()) out.push_back(SortedJson(item));
        return out;
    }
    return value;
}

bool SameDocument(const std::string& existing, const std::string& body)
{
    UniValue left;
    UniValue right;
    if (!left.read(existing) || !right.read(body)) return false;
    return SortedJson(left).write(0, 0) == SortedJson(right).write(0, 0);
}

SwarmDevice StockDevice()
{
    SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 1;
    device.cpu_threads = 0;
    device.vram_bytes = 0;
    device.max_steps = 0;
    device.license_allows_training = false;
    return device;
}

bool ReadDeviceFile(const fs::path& path, SwarmDevice& device, std::string& err)
{
    std::string raw;
    if (!ReadFile(path, raw)) {
        err = "DEVICE_READ";
        return false;
    }
    UniValue root;
    if (!root.read(raw) || !root.isObject()) {
        err = "DEVICE_JSON";
        return false;
    }
    device = SwarmDevice{};
    device.idle_contribution = root.exists("idle_contribution") && root["idle_contribution"].isTrue();
    device.slots = root.exists("slots") ? root["slots"].getInt<int>() : 0;
    device.cpu_threads = root.exists("cpu_threads") ? root["cpu_threads"].getInt<int>() : 0;
    device.vram_bytes = root.exists("vram_bytes") ? root["vram_bytes"].getInt<int64_t>() : 0;
    device.max_steps = root.exists("max_steps") ? root["max_steps"].getInt<int>() : 0;
    device.battery = root.exists("battery") && root["battery"].isTrue();
    device.thermal_hot = root.exists("thermal_hot") && root["thermal_hot"].isTrue();
    device.metered = root.exists("metered") && root["metered"].isTrue();
    device.license_allows_training =
        root.exists("license_allows_training") && root["license_allows_training"].isTrue();
    err.clear();
    return true;
}

} // namespace

bool SwarmLoadGoverned(const fs::path& modeldir, SwarmGovernSnapshot& out, std::string& err)
{
    out = SwarmGovernSnapshot{};
    SwarmDevice device = StockDevice();
    if (!modeldir.empty()) {
        const fs::path device_path = modeldir / "swarm" / "device.json";
        if (fs::exists(device_path)) {
            if (!ReadDeviceFile(device_path, device, err)) return false;
        }
    }
    out.device = device;
    out.hardware_threads = HardwareThreads();
    out.roles = SwarmEligibleRoles(device);
    out.budget = SwarmGovern(device, device.slots);
    out.roles.automatic_spend_atoms = "0";
    err.clear();
    return true;
}

std::vector<SwarmPeer> SwarmNeighbors(const std::vector<SwarmPeer>& peers, int near, int remote)
{
    std::vector<SwarmPeer> eligible;
    for (const SwarmPeer& peer : peers) {
        if (peer.authorized && peer.available) eligible.push_back(peer);
    }
    std::sort(eligible.begin(), eligible.end(), [](const SwarmPeer& a, const SwarmPeer& b) {
        if (a.rtt_us != b.rtt_us) return a.rtt_us < b.rtt_us;
        if (a.bandwidth_bps != b.bandwidth_bps) return a.bandwidth_bps > b.bandwidth_bps;
        return a.id < b.id;
    });
    if (near < 0) near = 0;
    if (remote < 0) remote = 0;
    std::vector<SwarmPeer> chosen;
    chosen.reserve(static_cast<size_t>(near + remote));
    std::set<std::string> used;
    std::set<std::string> domains;
    for (const SwarmPeer& peer : eligible) {
        if (static_cast<int>(chosen.size()) >= near) break;
        chosen.push_back(peer);
        used.insert(peer.id);
        domains.insert(peer.domain);
    }
    std::vector<SwarmPeer> remaining;
    for (const SwarmPeer& peer : eligible) {
        if (!used.count(peer.id)) remaining.push_back(peer);
    }
    std::sort(remaining.begin(), remaining.end(), [&](const SwarmPeer& a, const SwarmPeer& b) {
        const bool a_known = domains.count(a.domain) != 0;
        const bool b_known = domains.count(b.domain) != 0;
        if (a_known != b_known) return !a_known;
        if (a.rtt_us != b.rtt_us) return a.rtt_us < b.rtt_us;
        return a.id < b.id;
    });
    for (const SwarmPeer& peer : remaining) {
        if (static_cast<int>(chosen.size()) >= near + remote) break;
        chosen.push_back(peer);
    }
    return chosen;
}

SwarmRoles SwarmEligibleRoles(const SwarmDevice& device)
{
    SwarmRoles roles;
    const bool idle = device.idle_contribution && !Blocked(device);
    roles.seeder = idle && device.slots > 0;
    roles.evaluator = idle && device.cpu_threads > 0;
    roles.trainer = idle && device.vram_bytes > 0 && device.license_allows_training;
    roles.private_prompts = device.private_prompt_grant;
    roles.private_data = device.private_data_grant;
    roles.automatic_spend_atoms = "0";
    return roles;
}

SwarmBudget SwarmGovern(const SwarmDevice& device, int requested_workers)
{
    SwarmBudget budget;
    if (!device.idle_contribution) {
        budget.code = "IDLE_OFF";
        return budget;
    }
    if (Blocked(device)) {
        budget.code = "RESOURCE_BLOCKED";
        return budget;
    }
    if (requested_workers < 0) requested_workers = 0;
    budget.active_workers = std::min(requested_workers, std::max(device.slots, 0));
    budget.cpu_threads = std::max(device.cpu_threads, 0);
    budget.vram_bytes = std::max<int64_t>(device.vram_bytes, 0);
    budget.max_steps = std::max(device.max_steps, 0);
    budget.drained = budget.active_workers == 0;
    budget.code = budget.drained ? "NO_SLOTS" : "ADMITTED";
    return budget;
}

SwarmJoin SwarmJoinLineage(const std::string& artifact_id, const std::string& model_id,
                           const std::string& checkpoint_id, const std::string& mapped_lineage,
                           const std::string& mapped_visibility)
{
    SwarmJoin join;
    if (!SwarmFixedId(artifact_id) || !SwarmFixedId(model_id) || !SwarmFixedId(checkpoint_id)) {
        join.code = "ID";
        return join;
    }
    join.artifact_id = artifact_id;
    join.model_id = model_id;
    join.checkpoint_id = checkpoint_id;
    if (!mapped_lineage.empty()) {
        if (!SwarmFixedId(mapped_lineage) || (mapped_visibility != "private" && mapped_visibility != "public")) {
            join.code = "VISIBILITY";
            return join;
        }
        join.lineage_id = mapped_lineage;
        join.assurance = "VERIFIED_MAPPING";
        join.visibility = mapped_visibility;
    } else {
        join.lineage_id = SwarmProvisionalLineage(model_id);
        join.assurance = "PROVISIONAL_NOT_AUTHORITATIVE";
        join.visibility = "private";
    }
    if (join.lineage_id == checkpoint_id || join.lineage_id == artifact_id) {
        join.code = "LINEAGE_COLLISION";
        join.ok = false;
        return join;
    }
    join.ok = !join.lineage_id.empty();
    join.code = join.ok ? "JOINED" : "LINEAGE";
    return join;
}

bool SwarmOriginIsLineage(const std::string& origin_url)
{
    (void)origin_url;
    return false;
}

SwarmTimescale SwarmClassifyTimescale(const std::string& kind)
{
    if (kind == "finding" || kind == "kv") return SwarmTimescale::Immediate;
    if (kind == "strategy" || kind == "evaluation") return SwarmTimescale::Short;
    if (kind == "adapter" || kind == "finetune") return SwarmTimescale::Medium;
    return SwarmTimescale::Long;
}

bool SwarmRefreshLocalMesh(const fs::path& modeldir, std::string& err)
{
    const fs::path swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = "MESH_DIR";
        return false;
    }
    std::vector<SwarmPeer> peers;
    const fs::path peers_path = swarm_dir / "peers.json";
    std::string peers_raw;
    if (fs::exists(peers_path)) {
        if (!ReadFile(peers_path, peers_raw)) {
            err = "PEERS_READ";
            return false;
        }
        UniValue root;
        if (!root.read(peers_raw) || !root.isObject() || !root.exists("peers") || !root["peers"].isArray()) {
            err = "PEERS_JSON";
            return false;
        }
        for (const UniValue& item : root["peers"].getValues()) {
            if (!item.isObject() || !item.exists("id") || !item.exists("domain")) {
                err = "PEERS_JSON";
                return false;
            }
            SwarmPeer peer;
            peer.id = item["id"].get_str();
            peer.domain = item["domain"].get_str();
            peer.authorized = item.exists("authorized") && item["authorized"].isTrue();
            peer.available = item.exists("available") && item["available"].isTrue();
            peer.rtt_us = item.exists("rtt_us") ? item["rtt_us"].getInt<int64_t>() : 0;
            peer.bandwidth_bps = item.exists("bandwidth_bps") ? item["bandwidth_bps"].getInt<int64_t>() : 0;
            peers.push_back(std::move(peer));
        }
    }
    SwarmGovernSnapshot governed;
    if (!SwarmLoadGoverned(modeldir, governed, err)) return false;
    const SwarmRoles& roles = governed.roles;
    const SwarmBudget& budget = governed.budget;
    const std::vector<SwarmPeer> neighborhood = SwarmNeighbors(peers);
    UniValue out(UniValue::VOBJ);
    UniValue ids(UniValue::VARR);
    for (const SwarmPeer& peer : neighborhood) ids.push_back(peer.id);
    out.pushKV("automatic_spend_atoms", "0");
    out.pushKV("drained", budget.drained);
    out.pushKV("evaluator", roles.evaluator);
    out.pushKV("governor", budget.code);
    out.pushKV("hardware_threads", governed.hardware_threads);
    out.pushKV("neighbors", ids);
    // The helper supplies live, authenticated transport observations. These
    // enable observer participation only; they are not training or data grants.
    UniValue observed(UniValue::VARR), shared(UniValue::VARR);
    const fs::path native_path = swarm_dir / "native-participation.json";
    std::error_code native_ec;
    if (fs::is_regular_file(fs::symlink_status(native_path, native_ec)) &&
        fs::file_size(native_path, native_ec) <= 512 * 1024 && !native_ec) {
        std::string raw;
        UniValue native;
        if (ReadFile(native_path, raw) && native.read(raw) && native.isObject() &&
            native["schema"].isStr() && native["schema"].get_str() == "BTX/NativeParticipation/1" &&
            native["peer_observations"].isArray() && native["peer_observations"].size() <= 128) {
            const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            std::set<std::string> fresh;
            for (const auto& peer : native["peer_observations"].getValues()) {
                if (!peer.isObject() || !peer["transport_pin"].isStr() ||
                    !peer["observed_at_ms"].isNum() || !peer["expires_at_ms"].isNum()) continue;
                const std::string pin = peer["transport_pin"].get_str();
                if (!SwarmFixedId(pin)) continue;
                const int64_t seen = peer["observed_at_ms"].getInt<int64_t>();
                const int64_t expiry = peer["expires_at_ms"].getInt<int64_t>();
                if (seen < 0 || seen > now || now - seen >= 90000 || expiry <= now || expiry - seen > 90000) continue;
                if (fresh.insert(pin).second) observed.push_back(pin);
            }
            SwarmCatalog local;
            std::string local_err;
            std::set<std::string> local_models;
            if (SwarmReadCatalog(modeldir, local, local_err))
                for (const auto& [id, entry] : local) local_models.insert(entry.model_id);
            if (native["shared_model_families"].isArray() && native["shared_model_families"].size() <= 128) {
                for (const auto& family : native["shared_model_families"].getValues()) {
                    if (!family.isObject() || !family["model_id"].isStr() || !family["peer_transport_pins"].isArray()) continue;
                    const std::string model = family["model_id"].get_str();
                    if (!local_models.count(model)) continue;
                    UniValue members(UniValue::VARR);
                    for (const auto& p : family["peer_transport_pins"].getValues())
                        if (p.isStr() && fresh.count(p.get_str())) members.push_back(p);
                    if (members.empty()) continue;
                    UniValue admitted(UniValue::VOBJ);
                    admitted.pushKV("model_id", model);
                    admitted.pushKV("peer_transport_pins", members);
                    admitted.pushKV("role", "observer");
                    admitted.pushKV("compute_authorized", false);
                    shared.push_back(admitted);
                }
            }
        }
    }
    out.pushKV("observer_neighbors", observed);
    out.pushKV("shared_model_families", shared);
    out.pushKV("observer", roles.observer);
    out.pushKV("private_data_training", roles.private_data);
    out.pushKV("private_prompts", roles.private_prompts);
    out.pushKV("seeder", roles.seeder);
    out.pushKV("trainer", roles.trainer);
    const std::string body = out.write(0, 0) + "\n";
    const fs::path final_path = swarm_dir / "mesh-state.json";
    std::string existing;
    if (ReadFile(final_path, existing) && SameDocument(existing, body)) {
        err.clear();
        return true;
    }
    if (!SwarmFormWrite(final_path, body, err)) {
        if (err == "WRITE") err = "MESH_WRITE";
        if (err == "RENAME") err = "MESH_RENAME";
        return false;
    }
    return true;
}

} // namespace modelnet
