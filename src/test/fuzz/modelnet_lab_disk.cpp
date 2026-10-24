// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>
#include <modelnet/lab_api.h>
#include <modelnet/lab_disk.h>
#include <modelnet/lab_exchange.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/time.h>

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

// BTX035_LAB_DIR holds lab.json, the piece store and admission-registry.json.
// btxd loads them on the first lab035 call or /btx-model/3/ route after a
// start, and the live model paths reload the registry on every call.

namespace modelnet {
// Defined in lab_exchange.cpp; lab_lifecycle_tests declares it the same way.
bool ReadLoopbackBounded(int fd, std::string& out, size_t max_bytes, int timeout_ms, std::string& err);
} // namespace modelnet

namespace {

const std::vector<std::string> LAB_METHODS{
    "lab.info", "lab.record_get", "lab.record_import", "lab.record_verify", "lab.identity_inspect",
    "lab.identity_create", "lab.identity_sign", "lab.identity_transition", "lab.identity_revoke",
    "lab.grant_evaluate", "lab.git_register", "lab.git_snapshot", "lab.git_attest", "lab.git_publish_ref",
    "lab.git_refs", "lab.git_fetch_ticket", "lab.workspace_create", "lab.workspace_snapshot",
    "lab.workspace_restore", "lab.workspace_operation", "lab.workspace_reconcile", "lab.workspace_hydrate",
    "lab.source_query", "lab.research_query", "lab.research_context", "lab.research_frontier",
    "lab.research_subscribe", "lab.research_unsubscribe", "lab.research_publish", "lab.research_events",
    "lab.capsule_resolve", "lab.artifact_acquire", "lab.operation_get", "lab.operation_cancel",
    "lab.audit_coverage", "lab.admission_evaluate", "lab.model_host", "lab.model_unhost", "lab.agent_lineage",
    "lab.agent_adopt", "lab.runtime_bind", "lab.action_prepare", "lab.action_execute", "lab.runtime_pause",
    "lab.runtime_resume", "lab.journal_checkpoint", "lab.journal_proof", "lab.journal_witness",
    "lab.incident_publish", "lab.realm_create", "lab.realm_policy_apply", "lab.realm_status",
    "lab.promotion_prepare", "lab.promotion_attest", "lab.promotion_verify", "lab.channel_publish",
    "lab.channel_get", "lab.rollout_start", "lab.rollout_status", "lab.rollout_pause", "lab.rollout_rollback",
    "lab.deployment_observe", "lab.migration_plan", "lab.migration_apply", "lab.migration_verify",
    "lab.economy_refs", "lab.state_get", "lab.rollout_endpoints", "lab.repository_create",
    "lab.git_push_authorize", "lab.identity_refresh", "lab.research_execute", "lab.trust_reconcile",
    "lab.snapshot_export", "lab.snapshot_import",
};

const std::vector<std::string> PEER_ROUTES{
    "hello", "auth", "records/get", "records/announce", "research/query", "subscriptions/poll",
    "git/tunnel", "artifacts/manifest", "artifacts/piece", "trust/state", "channels/get",
};

fs::path LabDir()
{
    static const fs::path dir = fs::path{fs::temp_directory_path()} /
                                fs::u8path(strprintf("btx-fuzz-labdisk-%08x", std::random_device{}()));
    return dir;
}

fs::path FreshLabDir()
{
    const fs::path dir = LabDir();
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    return dir;
}

void PutFile(const fs::path& path, const std::string& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string GetFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void initialize_lab_disk()
{
    // No loopback peers, no guard daemon, no bundle directory. The lab
    // directory is a private temp directory.
    for (const char* name : {"BTX035_LAB_PEER", "BTX035_LAB_PEERS", "BTX_GUARD_PORT", "BTX035_BUNDLE_DIR"}) {
        unsetenv(name);
    }
    setenv("BTX035_LAB_DIR", fs::PathToString(LabDir()).c_str(), 1);
}

void ResetLab()
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    SetMockTime(1700000000);
    modelnet::ResetLabApi();
    modelnet::ClearAdmissionMemory();
}

/** lab035 RPC: the RPC server turns a thrown std::exception into an error reply. */
std::string LabCall(const std::string& method, const std::string& request)
{
    std::string response;
    std::string err;
    try {
        if (modelnet::DispatchLabApi(method, request, response, err)) {
            UniValue parsed;
            Assert(parsed.read(response));
        } else {
            Assert(response.empty());
            Assert(!err.empty());
        }
    } catch (const std::exception&) {
    }
    return response;
}

/** `/btx-model/3/`: no RPC credentials and no catch around the handler. */
void PeerCall(const std::string& route, const std::string& request)
{
    std::string response;
    std::string err;
    if (modelnet::ServeLabPeer(route, request, response, err)) {
        Assert(err.empty());
        UniValue parsed;
        Assert(parsed.read(response));
    } else {
        Assert(response.empty());
    }
}

void FuzzedCalls(FuzzedDataProvider& fdp, unsigned max_calls)
{
    LIMITED_WHILE(fdp.remaining_bytes() > 0, max_calls)
    {
        if (fdp.ConsumeBool()) {
            const std::string& method = LAB_METHODS[fdp.ConsumeIntegralInRange<size_t>(0, LAB_METHODS.size() - 1)];
            LabCall(method, fdp.ConsumeRandomLengthString(4096));
        } else {
            const std::string& route = PEER_ROUTES[fdp.ConsumeIntegralInRange<size_t>(0, PEER_ROUTES.size() - 1)];
            PeerCall(route, fdp.ConsumeRandomLengthString(4096));
        }
    }
}

bool InRecovery()
{
    return LabCall("lab.info", "{}").find("BTX035_RECOVERY_REQUIRED") != std::string::npos;
}

/** True when `text` survives a JSON string round trip, as an id that arrived over JSON-RPC does. */
bool JsonText(const std::string& text)
{
    UniValue parsed;
    return parsed.read(UniValue(text).write()) && parsed.isStr() && parsed.get_str() == text;
}

} // namespace

// lab.json as found at start: refused files put the lab in recovery, accepted
// files save and load back byte for byte, and the loaded store serves.
FUZZ_TARGET(modelnet_lab_image, .init = initialize_lab_disk)
{
    ResetLab();
    const fs::path dir = FreshLabDir();
    const fs::path file = dir / "lab.json";
    PutFile(file, std::string(buffer.begin(), buffer.end()));

    modelnet::LabDiskImage image;
    std::string err;
    const bool loaded = modelnet::LoadLabDisk(image, err);
    if (!loaded) {
        Assert(err == "BTX035_RECOVERY_REQUIRED");
    } else {
        Assert(err.empty());
        Assert(modelnet::SaveLabDisk(image, err));
        const std::string first = GetFile(file);
        modelnet::LabDiskImage again;
        Assert(modelnet::LoadLabDisk(again, err));
        Assert(modelnet::SaveLabDisk(again, err));
        Assert(GetFile(file) == first);
    }

    // What a restarted node does with the same file.
    modelnet::ReloadLabFromDisk();
    if (!loaded) Assert(InRecovery());
    for (const char* route : {"hello", "trust/state", "channels/get", "subscriptions/poll"}) PeerCall(route, "{}");
    LabCall("lab.state_get", "{}");
    LabCall("lab.research_query", "{}");
}

// Any sequence of lab calls with the lab directory on. Whatever the lab
// persisted, a restart loads without BTX035_RECOVERY_REQUIRED, and the
// admission registry it wrote reloads.
FUZZ_TARGET(modelnet_lab_persist, .init = initialize_lab_disk)
{
    FreshLabDir();
    ResetLab();
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    FuzzedCalls(fdp, 16);
    if (InRecovery()) return;

    modelnet::ReloadLabFromDisk();
    Assert(!InRecovery());
    std::string code;
    modelnet::LivePathAllowed("fuzz-probe-model", false, code);
    Assert(code != "BTX035_RECOVERY_REQUIRED");
}

// admission-registry.json as found under the lab directory.
FUZZ_TARGET(modelnet_admission_registry, .init = initialize_lab_disk)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshLabDir();
    ResetLab();
    const std::string registry = fdp.ConsumeRandomLengthString(1 << 16);
    PutFile(dir / "admission-registry.json", registry);

    // Probe the ids the file names, plus fuzzed ones.
    std::vector<std::string> ids;
    UniValue root;
    if (root.read(registry) && root.isObject()) {
        for (const char* key : {"strict", "admissions"}) {
            if (!root.exists(key) || !root[key].isArray()) continue;
            for (const UniValue& row : root[key].getValues()) {
                if (row.isObject() && row.exists("model_id") && row["model_id"].isStr()) ids.push_back(row["model_id"].get_str());
            }
        }
        for (const char* key : {"legacy", "quarantine", "revoked"}) {
            if (!root.exists(key) || !root[key].isArray()) continue;
            for (const UniValue& item : root[key].getValues()) {
                if (item.isStr()) ids.push_back(item.get_str());
            }
        }
    }
    LIMITED_WHILE(fdp.ConsumeBool(), 4) ids.push_back(fdp.ConsumeRandomLengthString(128));
    if (ids.size() > 64) ids.resize(64);

    bool corrupt{false};
    for (const std::string& id : ids) {
        std::string code;
        const bool allowed = modelnet::LivePathAllowed(id, fdp.ConsumeBool(), code);
        Assert(allowed == code.empty());
        if (!allowed) Assert(code.rfind("BTX035_", 0) == 0);
        if (code == "BTX035_RECOVERY_REQUIRED") corrupt = true;
    }
    std::string probe;
    if (!modelnet::LivePathAllowed("fuzz-probe-model", false, probe) && probe == "BTX035_RECOVERY_REQUIRED") corrupt = true;
    if (corrupt) return;

    // A durable admission recorded over a readable registry is read back.
    const std::string model_id = fdp.ConsumeRandomLengthString(128);
    const std::string digest = fdp.ConsumeRandomLengthString(128);
    const std::string decision = fdp.ConsumeBool() ? "ADMITTED" : fdp.ConsumeRandomLengthString(32);
    if (!JsonText(model_id) || !JsonText(digest) || !JsonText(decision)) return;
    std::string err;
    if (!modelnet::RecordModelAdmission(model_id, digest, decision, err)) return;
    std::string code;
    modelnet::LivePathAllowed(model_id, false, code);
    Assert(code != "BTX035_RECOVERY_REQUIRED");
    modelnet::ClearAdmissionMemory();
    modelnet::LivePathAllowed(model_id, false, code);
    Assert(code != "BTX035_RECOVERY_REQUIRED");
}

#ifndef WIN32
// The bounded loopback reader: what the lab reads from a peer socket, and the
// BTX035_LAB_PEERS list it dials.
FUZZ_TARGET(modelnet_lab_loopback_read, .init = initialize_lab_disk)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const size_t max_bytes = fdp.ConsumeIntegralInRange<size_t>(1, 1 << 16);
    const std::string peers = fdp.ConsumeRandomLengthString(512);
    const std::string sent = fdp.ConsumeRemainingBytesAsString();

    int pair[2];
    Assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    // Fuzz inputs are far below the socket buffer, so this does not block.
    size_t written{0};
    while (written < sent.size()) {
        const ssize_t n = write(pair[1], sent.data() + written, sent.size() - written);
        if (n <= 0) break;
        written += static_cast<size_t>(n);
    }
    close(pair[1]);
    std::string out;
    std::string err;
    const bool ok = modelnet::ReadLoopbackBounded(pair[0], out, max_bytes, 200, err);
    close(pair[0]);
    if (ok) {
        Assert(out.size() <= max_bytes);
        Assert(out == sent.substr(0, written));
    } else {
        Assert(!err.empty());
    }

    if (peers.find('\0') != std::string::npos) return;
    setenv("BTX035_LAB_PEERS", peers.c_str(), 1);
    setenv("BTX035_LAB_PEER_USER", "fuzz", 1);
    setenv("BTX035_LAB_PEER_PASSWORD", "fuzz", 1);
    std::vector<modelnet::LoopbackPeer> list;
    bool configured{false};
    std::string peer_err;
    if (modelnet::LoopbackPeers(list, configured, peer_err)) {
        for (const modelnet::LoopbackPeer& peer : list) Assert(peer.host == "127.0.0.1");
    }
    for (const char* name : {"BTX035_LAB_PEERS", "BTX035_LAB_PEER_USER", "BTX035_LAB_PEER_PASSWORD"}) unsetenv(name);
}
#endif // WIN32
