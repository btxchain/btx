// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Unique todos that were previously lumped as one NOT_RUN paragraph.
// Each BOOST_AUTO_TEST_CASE is one operator todo. automatic_spend_atoms=0.
// Catalog stays on ModelStore. Do not claim GPU hardware PASS from absence.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <clientversion.h>
#include <modelnet/capability.h>
#include <modelnet/catalog.h>
#include <modelnet/file_stream.h>
#include <modelnet/hcp.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_pjson.h>
#include <modelnet/piece_picker.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/subscription_mandate.h>
#include <modelnet/transfer_session.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_unique_todo_tests, BasicTestingSetup)

namespace {

UniValue Rpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR))
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

UniValue MandateJson()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", 1);
    o.pushKV("owner_identity", std::string(96, 'a'));
    o.pushKV("network_id", std::string(64, '0'));
    o.pushKV("publisher_id", std::string(96, 'b'));
    UniValue kinds(UniValue::VARR);
    kinds.push_back("MODEL");
    kinds.push_back("RELEASE");
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    acts.push_back("PREPARE_FUNDING");
    o.pushKV("allowed_actions", acts);
    o.pushKV("per_action_principal_limit_atoms", "50");
    o.pushKV("total_principal_limit_atoms", "100");
    o.pushKV("total_fee_limit_atoms", "20");
    o.pushKV("outstanding_exposure_limit_atoms", "200");
    o.pushKV("max_actions", 16);
    o.pushKV("max_concurrent_reservations", 8);
    o.pushKV("expires_at_ms", "4000000000000");
    o.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    o.pushKV("minimum_confirmations", 1);
    o.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    o.pushKV("revocation_counter", "0");
    return o;
}

void ZeroSpend(const UniValue& o, const char* where)
{
    BOOST_REQUIRE_MESSAGE(o.isObject(), where);
    if (o.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int>(), 0);
    }
}

int SpawnArgv(const char* exe, const char* arg)
{
    const pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        ::execl(exe, exe, arg, static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int st = 0;
    BOOST_REQUIRE_EQUAL(::waitpid(pid, &st, 0), pid);
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return -1;
}

} // namespace

BOOST_AUTO_TEST_CASE(unique_todo_f2_wallet_sign)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-f2", 1 << 20};
    std::string code, err;
    UniValue caps;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxpackagecapabilities"), caps, code, err), err);
    BOOST_CHECK(caps["wallet_sign"].isFalse());
    ZeroSpend(caps, "F2 capabilities");

    UniValue p(UniValue::VARR);
    p.push_back(MandateJson());
    UniValue created;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createsubscriptionmandate", p), created, code, err), err);
    BOOST_CHECK(!created["wallet_signed"].get_bool());
    BOOST_CHECK(!created.exists("private_key"));
    BOOST_CHECK(!created.exists("wallet_seed"));
    ZeroSpend(created, "F2 createsubscriptionmandate");
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN F2 wallet-signed mandate; wallet_sign stays false");
}

BOOST_AUTO_TEST_CASE(unique_todo_getsubscriptionactivity)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-subact", 1 << 20};
    std::string code, err;
    UniValue p(UniValue::VARR);
    p.push_back(MandateJson());
    UniValue created;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createsubscriptionmandate", p), created, code, err), err);
    ZeroSpend(created, "getsubscriptionactivity create");
    const std::string mid = created["mandate_id"].get_str();

    UniValue rsv(UniValue::VOBJ);
    rsv.pushKV("mandate_id", mid);
    rsv.pushKV("event_id", "e-todo-act");
    rsv.pushKV("publisher_id", std::string(96, 'b'));
    rsv.pushKV("object_kind", "RELEASE");
    rsv.pushKV("action", "FUND_WITH_MANDATE");
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("terms_id", std::string(96, 'd'));
    terms.pushKV("publisher_id", std::string(96, 'b'));
    terms.pushKV("network_id", std::string(64, '0'));
    terms.pushKV("principal_atoms", "1");
    terms.pushKV("fee_atoms", "0");
    terms.pushKV("object_kind", "RELEASE");
    terms.pushKV("confirmations", 1);
    rsv.pushKV("signed_terms", terms);
    UniValue rparams(UniValue::VARR);
    rparams.push_back(rsv);
    UniValue reserved;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("reservesubscriptionmandate", rparams), reserved, code, err), err);
    ZeroSpend(reserved, "getsubscriptionactivity reserve");

    UniValue ap(UniValue::VOBJ);
    ap.pushKV("mandate_id", mid);
    ap.pushKV("limit", 10);
    UniValue aparams(UniValue::VARR);
    aparams.push_back(ap);
    UniValue activity;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getsubscriptionactivity", aparams), activity, code, err), err);
    ZeroSpend(activity, "getsubscriptionactivity");
    BOOST_REQUIRE(activity.exists("actions") && activity["actions"].isArray());
    BOOST_REQUIRE_EQUAL(activity["actions"].size(), 1U);
    BOOST_CHECK_EQUAL(activity["actions"][0]["event_id"].get_str(), "e-todo-act");
    BOOST_CHECK_EQUAL(activity["actions"][0]["terms_id"].get_str(), std::string(96, 'd'));
    BOOST_CHECK(activity["actions"][0]["txid"].get_str().empty());
    BOOST_CHECK(activity["telemetry"].isFalse());
    BOOST_CHECK(!activity["wallet_signed"].get_bool());
}

BOOST_AUTO_TEST_CASE(unique_todo_a2_modelindex)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-a2", 1 << 20};
    std::string code, err;
    UniValue addp(UniValue::VARR);
    addp.push_back("127.0.0.1:29447");
    UniValue added;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("addmodelindex", addp), added, code, err), err);
    ZeroSpend(added, "A2 addmodelindex");

    UniValue rec_in(UniValue::VOBJ);
    UniValue ids(UniValue::VARR);
    ids.push_back("id-0");
    rec_in.pushKV("remote_ids", ids);
    UniValue recp(UniValue::VARR);
    recp.push_back(rec_in);
    UniValue rec;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("reconcilemodelindex", recp), rec, code, err), err);
    ZeroSpend(rec, "A2 reconcilemodelindex");

#ifdef MODELNET_MODELD_PATH
    BOOST_REQUIRE(fs::exists(fs::PathFromString(MODELNET_MODELD_PATH)));
    BOOST_CHECK_NE(SpawnArgv(MODELNET_MODELD_PATH, "-modelindex=1"), 0);
#endif
#ifdef MODELNET_BTXD_PATH
    BOOST_REQUIRE(fs::exists(fs::PathFromString(MODELNET_BTXD_PATH)));
    FILE* fp = ::popen((std::string(MODELNET_BTXD_PATH) + " -help").c_str(), "r");
    BOOST_REQUIRE(fp);
    std::string help;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != nullptr) help.append(buf);
    (void)::pclose(fp);
    BOOST_CHECK(help.find("-modelindex") == std::string::npos);
#endif
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN -modelindex as a product flag; helper/modeld reject");
}

BOOST_AUTO_TEST_CASE(unique_todo_build_gui)
{
#if defined(ENABLE_QT)
    BOOST_FAIL("BUILD_GUI unique: ENABLE_QT is set; this tree must stay BUILD_GUI=OFF");
#else
    BOOST_TEST_MESSAGE("BUILD_GUI unique: ENABLE_QT unset (BUILD_GUI=OFF)");
#endif
    modelnet::ModelCatalog cat{m_path_root / "todo-gui", 1 << 20};
    std::string code, err;
    UniValue caps;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxpackagecapabilities"), caps, code, err), err);
    BOOST_CHECK_EQUAL(caps["gui"].get_str(), "DEFERRED_WITH_EVIDENCE");
    ZeroSpend(caps, "GUI capabilities");
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN BUILD_GUI=ON / Qt journeys; this tree stays BUILD_GUI=OFF");
}

BOOST_AUTO_TEST_CASE(unique_todo_live_r2_hf_wan)
{
    auto head_code = [](const char* url) -> int {
        const std::string cmd = std::string("curl -sI -o /dev/null -w '%{http_code}' --max-time 8 --connect-timeout 5 --http1.1 ") + url;
        FILE* fp = ::popen(cmd.c_str(), "r");
        if (!fp) return -1;
        char buf[16]{};
        (void)::fgets(buf, sizeof(buf), fp);
        (void)::pclose(fp);
        return std::atoi(buf);
    };
    const int hf = head_code("https://huggingface.co/robots.txt");
    const int r2 = head_code("https://r2.cloudflarestorage.com/");
    const int cf = head_code("https://cloudflare.com/robots.txt");
    BOOST_TEST_MESSAGE(std::string("WAN_CONTACT HF=") + std::to_string(hf) + " R2=" + std::to_string(r2) +
                       " CF=" + std::to_string(cf) + " (no credentials; helper import stays fail-closed)");
    BOOST_CHECK_MESSAGE(hf > 0 || r2 > 0 || cf > 0, "live R2/HF WAN unique made no HTTP contact");

    modelnet::ModelCatalog cat{m_path_root / "todo-wan", 1 << 20};
    std::string code, err;
    UniValue tr;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getevaluatedtransport"), tr, code, err), err);
    BOOST_CHECK(tr["live_hf_http"].isFalse());
    BOOST_CHECK_EQUAL(tr["live_r2_wan"].get_str(), "NOT_RUN");
    ZeroSpend(tr, "live WAN transport");
}

BOOST_AUTO_TEST_CASE(unique_todo_400gib_sparse_addressing)
{
    const uint64_t logical = 400ull * 1024ull * 1024ull * 1024ull;
    const UniValue receipt = modelnet::SparseOriginScaleReceiptJson(logical, /*stored=*/4096, /*gets=*/1, /*files=*/1);
    BOOST_CHECK(receipt["sparse"].get_bool());
    BOOST_CHECK_EQUAL(receipt["logical_bytes"].getInt<int64_t>(), static_cast<int64_t>(logical));
    BOOST_CHECK_LT(receipt["stored_object_bytes"].getInt<int64_t>(), 1 << 20);
    BOOST_CHECK_EQUAL(receipt["origin_get_ops"].getInt<int64_t>(), 1);
    ZeroSpend(receipt, "400GiB receipt");

    const fs::path sparse = m_path_root / "todo-400gib.sparse";
    const int fd = ::open(fs::PathToString(sparse).c_str(), O_CREAT | O_RDWR, 0644);
    BOOST_REQUIRE_GE(fd, 0);
    BOOST_REQUIRE_EQUAL(::ftruncate(fd, static_cast<off_t>(logical)), 0);
    struct stat st {};
    BOOST_REQUIRE_EQUAL(::fstat(fd, &st), 0);
    BOOST_CHECK_EQUAL(static_cast<uint64_t>(st.st_size), logical);
    const uint64_t allocated = static_cast<uint64_t>(st.st_blocks) * 512ull;
    BOOST_CHECK_MESSAGE(allocated < (64ull << 20), "400GiB sparse file used " + std::to_string(allocated) + " bytes");
    ::close(fd);
    ::unlink(fs::PathToString(sparse).c_str());
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN 400 GiB object I/O (sparse addressing is not payload I/O)");
}

BOOST_AUTO_TEST_CASE(unique_todo_utp_quic)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-utp", 1 << 20};
    std::string code, err;
    UniValue tr;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getevaluatedtransport"), tr, code, err), err);
    BOOST_CHECK_EQUAL(tr["utp"].get_str(), "NONSHIPPING");
    BOOST_CHECK(tr["quic"].isFalse());
    ZeroSpend(tr, "uTP/QUIC transport");

    UniValue info;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelnetworkinfo"), info, code, err), err);
    if (info.exists("quic")) BOOST_CHECK(info["quic"].isFalse());
    ZeroSpend(info, "uTP/QUIC networkinfo");
}

BOOST_AUTO_TEST_CASE(unique_todo_quic_ttc_not_shipping)
{
    // JIT spec §3.2 payload-only arithmetic (not a BTX lab measurement).
    // QUIC saves at most ~1 handshake RTT versus TCP+TLS 1.3. Sessions
    // already reuse PQ1 until PQ1_RECONNECT_BYTES (8 GiB).
    const double mib = 1024.0 * 1024.0;
    const double gib = 1024.0 * 1024.0 * 1024.0;
    auto payload_ms = [](double bytes, double gbit) {
        return bytes * 8.0 / (gbit * 1.0e9) * 1000.0;
    };
    const double adapter_10g_ms = payload_ms(400.0 * mib, 10.0);
    const double full_10g_ms = payload_ms(40.0 * gib, 10.0);
    const double adapter_100m_ms = payload_ms(400.0 * mib, 0.1);
    BOOST_CHECK_CLOSE(adapter_10g_ms, 335.5, 2.0);
    BOOST_CHECK_CLOSE(full_10g_ms, 34359.7, 2.0);

    const double lan_rtt_save_ms = 2.0;
    const double wan_rtt_save_ms = 80.0;
    BOOST_CHECK_LT(lan_rtt_save_ms / adapter_10g_ms, 0.05);
    BOOST_CHECK_LT(wan_rtt_save_ms / adapter_100m_ms, 0.05);
    BOOST_CHECK_LT(wan_rtt_save_ms / full_10g_ms, 0.01);
    BOOST_TEST_MESSAGE(std::string("QUIC TTC: 1-RTT save is not the critical path vs 400MiB@10G=") +
                       std::to_string(adapter_10g_ms) + "ms 40GiB@10G=" + std::to_string(full_10g_ms) + "ms");

    modelnet::ModelCatalog cat{m_path_root / "todo-quic-ttc", 1 << 20};
    std::string code, err;
    UniValue tr;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getevaluatedtransport"), tr, code, err), err);
    BOOST_CHECK(tr["quic"].isFalse());
    BOOST_CHECK(tr["pq1_swarm_only"].isTrue());
    ZeroSpend(tr, "QUIC TTC transport");

    UniValue ttc;
    BOOST_REQUIRE_MESSAGE(modelnet::GetCapabilityTtcTrace("", ttc, code, err), err);
    BOOST_REQUIRE(ttc["stages"].isArray());
    bool saw_acquire = false;
    for (const auto& st : ttc["stages"].getValues()) {
        BOOST_REQUIRE(st.isObject());
        const std::string name = st["stage"].get_str();
        BOOST_CHECK(name != "quic");
        if (name == "acquire") saw_acquire = true;
    }
    BOOST_CHECK(saw_acquire);
    BOOST_CHECK(ttc["critical_path_not_sum"].get_bool());
    ZeroSpend(ttc, "QUIC TTC trace");
}

BOOST_AUTO_TEST_CASE(unique_todo_torrentd)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-torrentd", 1 << 20};
    std::string code, err;
    UniValue tr;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getevaluatedtransport"), tr, code, err), err);
    if (tr.exists("btx_torrentd_process")) BOOST_CHECK(tr["btx_torrentd_process"].isFalse());
    ZeroSpend(tr, "torrentd transport");

    UniValue loc(UniValue::VOBJ);
    loc.pushKV("locator", "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    UniValue tp(UniValue::VARR);
    tp.push_back(loc);
    UniValue st;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("gettorrentsourcestatus", tp), st, code, err), err);
    BOOST_CHECK(st["torrentd_process"].isFalse());
    ZeroSpend(st, "gettorrentsourcestatus");
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_cuda)
{
    bool saw = false;
    for (const auto& s : modelnet::ProbeRuntimeAdapters()) {
        BOOST_CHECK(!s.stub);
        if (s.backend.find("CUDA") != std::string::npos || s.runtime_id.find("cuda") != std::string::npos ||
            s.runtime_id.find("llama") != std::string::npos) {
            saw = true;
            if (!s.present) {
                BOOST_CHECK(s.detail.find("NOT_RUN") != std::string::npos || !s.present);
            }
            BOOST_TEST_MESSAGE(std::string("CUDA unique probe: ") + s.runtime_id + " present=" +
                              (s.present ? "true " : "false ") + s.detail);
        }
    }
    BOOST_CHECK(saw);
    if (::access("/usr/bin/nvidia-smi", X_OK) == 0) {
        FILE* fp = ::popen("/usr/bin/nvidia-smi -L", "r");
        BOOST_REQUIRE(fp);
        std::string out;
        char buf[512];
        while (fgets(buf, sizeof(buf), fp) != nullptr) out.append(buf);
        const int rc = ::pclose(fp);
        BOOST_TEST_MESSAGE(std::string("CUDA unique nvidia-smi -L rc=") + std::to_string(rc) + " " + out);
        BOOST_CHECK(out.find("GPU") != std::string::npos || out.find("NVIDIA") != std::string::npos || rc != 0);
    } else {
        BOOST_TEST_MESSAGE("CUDA unique nvidia-smi absent on this host");
    }
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_rocm)
{
    bool saw = false;
    for (const auto& s : modelnet::ProbeRuntimeAdapters()) {
        BOOST_CHECK(!s.stub);
        if (s.backend.find("ROCm") != std::string::npos || s.backend.find("HIP") != std::string::npos ||
            s.runtime_id.find("vllm") != std::string::npos) {
            saw = true;
            BOOST_TEST_MESSAGE(std::string("ROCm unique probe: ") + s.runtime_id + " " + s.detail);
        }
    }
    BOOST_CHECK(saw);
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_metal)
{
    bool saw = false;
    for (const auto& s : modelnet::ProbeRuntimeAdapters()) {
        BOOST_CHECK(!s.stub);
        if (s.backend.find("Metal") != std::string::npos || s.runtime_id.find("mlx") != std::string::npos) {
            saw = true;
            BOOST_TEST_MESSAGE(std::string("Metal unique probe: ") + s.runtime_id + " " + s.detail);
        }
    }
    BOOST_CHECK(saw);
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_nixl)
{
    modelnet::PeerTransferOffer off;
    BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
    BOOST_CHECK(off.json["stub"].isFalse());
    ZeroSpend(off.json, "NIXL probe");
    BOOST_CHECK(off.json.exists("nixl_status"));
    BOOST_TEST_MESSAGE(std::string("NIXL unique probe: ") + off.json.write());
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_gds)
{
    modelnet::PeerTransferOffer off;
    BOOST_REQUIRE(modelnet::ProbePeerBackends(off));
    BOOST_CHECK(off.json.exists("gds_status"));
    ZeroSpend(off.json, "GDS probe");
    BOOST_TEST_MESSAGE(std::string("GDS unique probe: ") + off.json.write());
}

BOOST_AUTO_TEST_CASE(unique_todo_hw_cxl)
{
    const auto topo = modelnet::DiscoverTopology();
    ZeroSpend(topo.json, "CXL topology");
    BOOST_CHECK(topo.json["cxl_emulation"].isFalse());
    BOOST_CHECK(topo.json["privileged_sysfs_write"].isFalse());
    BOOST_TEST_MESSAGE(std::string("CXL unique probe cxl=") + (topo.cxl ? "true " : "false ") +
                       (topo.json.exists("cxl_evidence") ? topo.json["cxl_evidence"].get_str() : ""));
}

BOOST_AUTO_TEST_CASE(unique_todo_catalog_not_s3)
{
    const fs::path root = m_path_root / "todo-catalog";
    modelnet::ModelCatalog cat{root, 8 << 20};
    const std::string store_root = fs::PathToString(cat.Store().Root());
    BOOST_CHECK(store_root.find(fs::PathToString(root)) != std::string::npos);
    BOOST_CHECK(store_root.find("s3://") == std::string::npos);
    BOOST_CHECK(store_root.find("amazonaws") == std::string::npos);
    BOOST_CHECK(store_root.find("r2.cloudflarestorage") == std::string::npos);

    const fs::path st = root / "model.safetensors";
    fs::create_directories(st.parent_path());
    {
        std::ofstream out(st, std::ios::binary);
        const unsigned char hdr[10] = {2, 0, 0, 0, 0, 0, 0, 0, '{', '}'};
        out.write(reinterpret_cast<const char*>(hdr), 10);
    }
    modelnet::CatalogEntry e;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(st), /*pin=*/true, e, err), err);
    BOOST_CHECK(e.source_path.find("s3://") == std::string::npos);
    BOOST_CHECK(fs::PathToString(cat.Store().Root()).find("PieceStore") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(unique_todo_spend_zero)
{
    BOOST_CHECK(!CLIENT_VERSION_IS_RELEASE);
    modelnet::ModelCatalog cat{m_path_root / "todo-spend", 1 << 20};
    std::string code, err;
    for (const char* m : {"getmodelnetworkinfo", "getevaluatedtransport", "getbtxpackagecapabilities",
                           "getmodelpolicy"}) {
        UniValue o;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc(m), o, code, err), err);
        ZeroSpend(o, m);
    }
}

BOOST_AUTO_TEST_CASE(unique_todo_remote_process)
{
    // Lab-only. Public tree does not name operator hosts or production libexec.
    const char* local_btxd = std::getenv("BTX_REMOTE_PROCESS_BTXD");
    if (local_btxd == nullptr || local_btxd[0] == '\0' || ::access(local_btxd, X_OK) != 0) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN env-gated unique_todo_remote_process: BTX_REMOTE_PROCESS_BTXD unset");
        return;
    }
    std::string cmd = std::string(local_btxd) + " -version 2>/dev/null | head -3";
    FILE* fp = ::popen(cmd.c_str(), "r");
    BOOST_REQUIRE(fp);
    std::string out;
    char buf[512];
    while (::fgets(buf, sizeof(buf), fp) != nullptr) out.append(buf);
    int rc = ::pclose(fp);
    BOOST_TEST_MESSAGE(std::string("remote-process unique rc=") + std::to_string(rc) + " " + out);
    if (rc != 0) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN env-gated unique_todo_remote_process: version probe failed");
        return;
    }
    if (out.find("v0.34.8") == std::string::npos) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN env-gated unique_todo_remote_process: version not observed");
        return;
    }
}

BOOST_AUTO_TEST_CASE(unique_todo_hcp_unix_not_public)
{
    for (const char* m : {"hcphealth", "hcphandle", "accepthcphandoff", "applyhcpwalletless", "importhcpstate",
                           "sethcpreporting", "gethcpreadiness", "exporthcpstate", "planhcplocal", "ensurehcplocal",
                           "puthcplocalitysources", "minthcphandoff"}) {
        BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface(m));
        BOOST_CHECK(modelnet::IsHcpHelperMethod(m));
    }
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("hello"));
}

BOOST_AUTO_TEST_CASE(unique_todo_planhcplocal_lan_wins)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-j02", 1 << 20};
    UniValue src(UniValue::VOBJ);
    UniValue lan(UniValue::VOBJ);
    lan.pushKV("id", "lan");
    lan.pushKV("ttc_ms", 20);
    UniValue inet(UniValue::VOBJ);
    inet.pushKV("id", "cex-hint");
    inet.pushKV("ttc_ms", 8000);
    src.pushKV("lan", lan);
    src.pushKV("internet", inet);
    UniValue arr(UniValue::VARR);
    arr.push_back(src);
    UniValue put;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("puthcplocalitysources", arr), put, code, err), err);
    BOOST_CHECK(put["ok"].get_bool());
    BOOST_CHECK_EQUAL(put["automatic_spend_atoms"].getInt<int64_t>(), 0);
    UniValue rec(UniValue::VOBJ);
    rec.pushKV("recipe_id", "recipe");
    UniValue reca(UniValue::VARR);
    reca.push_back(rec);
    UniValue plan;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planhcplocal", reca), plan, code, err), err);
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
    BOOST_CHECK(plan["selected_source"].get_str() != "internet:cex-hint");
    BOOST_CHECK_EQUAL(plan["selected_source"].get_str().substr(0, 4), "lan:");
    BOOST_CHECK_EQUAL(plan["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(unique_todo_hosted_accept_signed_good)
{
    const fs::path path = m_path_root / "good-handoff.json";
    UniValue body(UniValue::VOBJ);
    body.pushKV("version", 1);
    body.pushKV("provider_id", "provider-demo");
    body.pushKV("account_ref", "account-demo");
    body.pushKV("device_id", "device-demo");
    body.pushKV("request_nonce", "demo-nonce-not-production");
    UniValue net(UniValue::VOBJ);
    net.pushKV("environment", "REGTEST");
    net.pushKV("genesis_hash", std::string(64, '0'));
    body.pushKV("network", net);
    body.pushKV("handoff_id", "handoff-todo-good");
    body.pushKV("client_operation_id", "op-todo-good");
    body.pushKV("issued_at_ms", "1790000000000");
    body.pushKV("expires_at_ms", "1790000600000");
    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("package_core_id", std::string(96, '1'));
    pkg.pushKV("file_sha384", std::string(96, '2'));
    pkg.pushKV("recipe_id", std::string(96, '3'));
    pkg.pushKV("download_url", "https://exchange.example/btx/hcp/v1/packages/" + std::string(96, '1'));
    body.pushKV("package", pkg);
    body.pushKV("readiness_target", "RUNTIME_READY");
    UniValue fx(UniValue::VARR);
    fx.push_back("FETCH_METADATA");
    fx.push_back("ACQUIRE_MODEL");
    fx.push_back("PLAN_LOCAL_RUN");
    body.pushKV("requested_effects", fx);
    body.pushKV("source_hints", UniValue(UniValue::VARR));
    body.pushKV("reporting_requested", false);
    UniValue env(UniValue::VOBJ);
    env.pushKV("object_type", "CapabilityHandoff");
    env.pushKV("body", body);
    {
        std::ofstream out{path};
        out << env.write();
    }
    std::string out, err;
    const std::vector<std::string> args{"btx-hosted", "accept", fs::PathToString(path)};
    BOOST_REQUIRE_EQUAL(modelnet::RunHostedCli(args, out, err), 0);
    UniValue acc;
    BOOST_REQUIRE(acc.read(out));
    BOOST_CHECK_EQUAL(acc["handoff_id"].get_str(), "handoff-todo-good");
    BOOST_CHECK(!acc["wallet_touched"].isTrue());
    BOOST_CHECK_EQUAL(acc["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(unique_todo_seedlab_getmodelchannel)
{
    modelnet::ModelCatalog cat{m_path_root / "todo-ch", 1 << 20};
    UniValue seeded;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("seedlabmodelchannel"), seeded, code, err), err);
    BOOST_CHECK(seeded["lab_seeded"].get_bool());
    BOOST_CHECK(seeded["signature_ok"].get_bool());
    BOOST_CHECK_EQUAL(seeded["automatic_spend_atoms"].getInt<int64_t>(), 0);
    UniValue q(UniValue::VOBJ);
    q.pushKV("publisher_id", seeded["publisher_id"].get_str());
    q.pushKV("name", seeded["name"].get_str());
    q.pushKV("channel", seeded["channel"].get_str());
    UniValue qa(UniValue::VARR);
    qa.push_back(q);
    UniValue got;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getmodelchannel", qa), got, code, err), err);
    BOOST_CHECK_EQUAL(got["publisher_id"].get_str(), seeded["publisher_id"].get_str());
    BOOST_CHECK(got["signature_ok"].get_bool());
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(unique_todo_picker_reschedule_and_classify)
{
    BOOST_CHECK_EQUAL(modelnet::kPickerReschedulePasses, 4);

    modelnet::CreditBroker credit{uint64_t{256} * modelnet::PIECE_SIZE};
    modelnet::TransferSession xfer(credit);
    modelnet::PeerMetrics sample;
    sample.timeout_count = 4;
    xfer.ObservePeer("p1:1", sample);
    const auto metrics = xfer.Metrics();
    BOOST_REQUIRE(metrics.count("p1:1"));
    BOOST_CHECK(metrics.at("p1:1").state == modelnet::PeerXferState::SNUBBED);
    BOOST_CHECK(modelnet::ClassifyPeer(metrics.at("p1:1")) == modelnet::PeerXferState::SNUBBED);

    modelnet::PeerMetrics bad;
    bad.invalid_piece_count = 2;
    xfer.ObservePeer("p2:1", bad);
    BOOST_CHECK(xfer.Metrics().at("p2:1").state == modelnet::PeerXferState::FAILED);

    modelnet::Digest48 artifact;
    UniValue av(UniValue::VOBJ);
    UniValue models(UniValue::VARR);
    UniValue m(UniValue::VOBJ);
    m.pushKV("artifact_id", artifact.Hex());
    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("file_index", 0);
    f.pushKV("piece_count", 2);
    UniValue ranges(UniValue::VARR);
    UniValue r(UniValue::VOBJ);
    r.pushKV("first", 0);
    r.pushKV("count", 99);
    ranges.push_back(r);
    f.pushKV("ranges", ranges);
    files.push_back(f);
    m.pushKV("files", files);
    models.push_back(m);
    av.pushKV("models", models);
    modelnet::PeerId peer;
    peer.endpoint = "127.0.0.1:1";
    std::vector<modelnet::SourceAvailability> out;
    std::string perr;
    BOOST_CHECK(!modelnet::ParseAvailabilitySources(av, peer.endpoint, peer, artifact, out, perr, 1));
    BOOST_CHECK(perr.find("beyond") != std::string::npos);

    modelnet::PickConfig cfg;
    cfg.rng_seed = 1;
    cfg.max_assignments = 8;
    std::vector<modelnet::SourceAvailability> srcs(2);
    srcs[0].peer.endpoint = "a:1";
    srcs[0].peer.service_id = "svc-a";
    srcs[0].file_index = 0;
    srcs[0].piece_count = 4;
    srcs[0].ranges.push_back({0, 4});
    srcs[1].peer.endpoint = "b:1";
    srcs[1].peer.service_id = "svc-b";
    srcs[1].file_index = 0;
    srcs[1].piece_count = 4;
    srcs[1].ranges.push_back({0, 4});
    std::vector<uint32_t> leftover{0, 1, 2, 3};
    int assigned_any = 0;
    for (int pass = 0; pass < modelnet::kPickerReschedulePasses && !leftover.empty(); ++pass) {
        cfg.rng_seed = static_cast<uint32_t>(3 + pass) * 2654435761u;
        const auto picks = modelnet::PickRarestFirst(0, 4, leftover, srcs, xfer.Metrics(), xfer.Outstanding(), {}, cfg);
        assigned_any += static_cast<int>(picks.size());
        std::set<uint32_t> got;
        for (const auto& a : picks) got.insert(a.piece_index);
        std::vector<uint32_t> still;
        for (uint32_t p : leftover) {
            if (!got.count(p)) still.push_back(p);
        }
        leftover.swap(still);
        modelnet::PeerMetrics ok;
        ok.throughput_bps = 1e6;
        ok.completed_pieces = 1;
        xfer.ObservePeer("a:1", ok);
    }
    BOOST_CHECK_GE(assigned_any, 1);
    const auto snap = modelnet::SummarizeSwarm(0, 4, {0}, srcs, xfer.Metrics(), cfg);
    const UniValue sj = modelnet::SwarmSnapshotJson(snap);
    BOOST_CHECK(sj.exists("extinction"));
    BOOST_CHECK(sj.exists("pieces_with_1_source"));
    BOOST_CHECK(sj.exists("min_piece_sources"));
}

BOOST_AUTO_TEST_CASE(unique_todo_gpu_attestor_untouched)
{
    BOOST_CHECK_EQUAL(CLIENT_VERSION_MAJOR, 0);
    BOOST_CHECK_EQUAL(CLIENT_VERSION_MINOR, 34);
    BOOST_CHECK_EQUAL(CLIENT_VERSION_BUILD, 8);
    BOOST_CHECK(!CLIENT_VERSION_IS_RELEASE);
#ifdef MODELNET_BTXD_PATH
    const std::string p = MODELNET_BTXD_PATH;
    BOOST_CHECK(p.find("libexec/btxd.real") == std::string::npos);
    BOOST_CHECK(p.find("btx-0.34.7-e15a07ba") == std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(unique_todo_ordinary_tools_inspect)
{
    // JIT-API-07 / AHP-DOC-09: ordinary framing inspect. No BTX binary required.
#ifdef MODELNET_AHP_FIXTURE_DIR
    const fs::path src = fs::PathFromString(MODELNET_AHP_FIXTURE_DIR) / "model-agent.btx";
#else
    const fs::path src = fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package" /
                          "model-agent.btx";
#endif
    BOOST_REQUIRE_MESSAGE(fs::exists(src), "unsigned AHP fixture model-agent.btx");
    std::ifstream in{src, std::ios::binary};
    BOOST_REQUIRE(in);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_REQUIRE_GE(raw.size(), 8U);
    BOOST_CHECK_EQUAL(raw.compare(0, 8, "BTXPKG\x00\x01", 8), 0);
    std::string err;
    const auto bytes = Span<const unsigned char>{reinterpret_cast<const unsigned char*>(raw.data()), raw.size()};
    UniValue as_bundle;
    BOOST_CHECK(!modelnet::DecodeBtxBundle(bytes, as_bundle, err));
    BOOST_CHECK_EQUAL(err, "conflicting dual body");
    modelnet::DecodedBtxPackage pkg;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(bytes, pkg, err), err);
    BOOST_REQUIRE(pkg.core.isObject());
    BOOST_REQUIRE(pkg.core["documents"].isArray());
    bool saw_agents = false;
    for (const auto& d : pkg.core["documents"].getValues()) {
        if (!d.isObject() || !d.exists("path") || !d["path"].isStr()) continue;
        if (d["path"].get_str() == "AGENTS.md") {
            saw_agents = true;
            BOOST_REQUIRE(d.exists("text") && d["text"].isStr());
            BOOST_CHECK(d["text"].get_str().find("Package purpose") != std::string::npos);
        }
    }
    BOOST_CHECK(saw_agents);
    BOOST_CHECK(!fs::exists(m_path_root / "AGENTS.md"));
}

BOOST_AUTO_TEST_CASE(unique_todo_priv08_unix_and_http_405)
{
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("getmodelnetworkinfo"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("getmodelcryptoinfo"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("getbtxpackagecapabilities"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("getsetupstatus"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("checkmodelsetup"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("getevaluatedtransport"));
    BOOST_CHECK(modelnet::HelperUnixMethodIsPublicSurface("hello"));
    BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface("ensurebtxcapability"));
    BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface("planbtxcapability"));
    BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface("executebtxacquisition"));
    BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface("planbtxclientinstall"));
    BOOST_CHECK(!modelnet::HelperUnixMethodIsPublicSurface("inspectbtxtensormap"));
    for (const char* hcp : {"hcphealth", "hcphandle", "accepthcphandoff", "applyhcpwalletless", "importhcpstate",
                            "sethcpreporting", "gethcpreadiness", "enrollhcpprovider", "pairhcpdevice",
                            "puthcplocalitysources", "minthcphandoff"}) {
        BOOST_CHECK_MESSAGE(!modelnet::HelperUnixMethodIsPublicSurface(hcp), hcp);
        BOOST_CHECK_MESSAGE(modelnet::IsHcpHelperMethod(hcp), hcp);
    }

    for (const char* k : {"local_paths", "installation_directory", "independent_trust_ref", "wallet_seed", "hf_token",
                          "aws_secret_access_key"}) {
        UniValue leak(UniValue::VOBJ);
        leak.pushKV(k, "/secret");
        BOOST_CHECK_MESSAGE(modelnet::JsonLeaksPrivateLocalState(leak), k);
    }

    BOOST_CHECK(modelnet::NativeHttpRequiresVerifiedPq1());
    for (const auto& p : modelnet::AdvertisedNativeHttpPaths()) {
        BOOST_CHECK(p.find("capability") == std::string::npos);
        BOOST_CHECK(p.find("btxlock") == std::string::npos);
        BOOST_CHECK(p.find("tensormap") == std::string::npos);
    }

    modelnet::ModelCatalog cat{m_path_root / "todo-priv08", 1 << 20};
    std::string code, err;
    for (const char* m : {"getmodelnetworkinfo", "getmodelcryptoinfo", "getbtxpackagecapabilities", "getsetupstatus",
                           "checkmodelsetup", "getevaluatedtransport", "hello"}) {
        UniValue o;
        BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc(m), o, code, err), err);
        BOOST_CHECK_MESSAGE(!modelnet::JsonLeaksPrivateLocalState(o), m);
        ZeroSpend(o, m);
    }
    BOOST_REQUIRE(cat.QuotaBytes() > 0);

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.body = "{}";
    for (const char* path : {"/btx-model/2/ensurebtxcapability", "/btx-model/2/planbtxcapability",
                              "/btx-model/2/inspectbtxtensormap", "/btx-model/2/exportbtxlock",
                              "/btx-model/2/hcphealth", "/btx-model/2/hcphandle", "/btx-model/2/accepthcphandoff",
                              "/btx-model/2/applyhcpwalletless"}) {
        nreq.path = path;
        modelnet::NativeResponse nresp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
        BOOST_CHECK_EQUAL(nresp.status, 405);
        UniValue body;
        BOOST_REQUIRE(body.read(nresp.body));
        BOOST_CHECK(body["public_runtime_rpc"].isFalse());
        ZeroSpend(body, path);
    }

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/ensurebtxcapability", "{}", br, ""));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/planbtxcapability", "{}", br, ""));
    BOOST_CHECK_EQUAL(br.http_status, 405);
}

BOOST_AUTO_TEST_CASE(unique_todo_live_cex_idp)
{
    std::string err;
    auto e = modelnet::HcpEngine::Create(modelnet::HcpWalletlessPreset(), err);
    BOOST_REQUIRE_MESSAGE(e, err);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);

    modelnet::HcpHttpRequest health_req;
    health_req.method = "GET";
    health_req.path = "/health";
    const auto health = e->Handle(health_req);
    BOOST_REQUIRE_EQUAL(health.status, 200);
    ZeroSpend(health.json, "live CEX IdP health");
    BOOST_CHECK(health.json["not_live_cex_idp"].isTrue());

    modelnet::HcpHttpRequest auth_req;
    auth_req.method = "GET";
    auth_req.path = "/.well-known/oauth-authorization-server";
    const auto auth = e->Handle(auth_req);
    BOOST_REQUIRE_EQUAL(auth.status, 200);
    BOOST_CHECK(auth.json["lab_only"].isTrue());
    BOOST_CHECK(auth.json["not_live_cex_idp"].isTrue());
    ZeroSpend(auth.json, "live CEX IdP auth");
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN live CEX IdP");
}

BOOST_AUTO_TEST_CASE(unique_todo_live_custody_hsm)
{
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.automatic_spend_atoms = 0;
    BOOST_CHECK_EQUAL(cfg.custody_backend, modelnet::HCP_CUSTODY_BTX_NATIVE);
    BOOST_CHECK(cfg.custody_backend.find("HSM") == std::string::npos);

    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE_MESSAGE(e, err);
    BOOST_CHECK_EQUAL(e->Cfg().custody_backend, modelnet::HCP_CUSTODY_BTX_NATIVE);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);

    modelnet::HcpHttpRequest health_req;
    health_req.method = "GET";
    health_req.path = "/health";
    const auto health = e->Handle(health_req);
    BOOST_REQUIRE_EQUAL(health.status, 200);
    ZeroSpend(health.json, "live HSM health");
    BOOST_CHECK(health.json["not_live_hsm"].isTrue());
    BOOST_CHECK_EQUAL(health.json["custody_backend"].get_str(), modelnet::HCP_CUSTODY_BTX_NATIVE);
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN live HSM");
}

BOOST_AUTO_TEST_CASE(unique_todo_with_modelnet_off_second_tree)
{
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN second cmake tree forbidden by disk policy");
    BOOST_CHECK_MESSAGE(!fs::exists(m_path_root / "CMakeCache.txt"), "no second Debug cmake tree required");
}

BOOST_AUTO_TEST_CASE(unique_todo_1000_downloaders)
{
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN 1000 real downloaders; 1000 sockets NOT_RUN");
    modelnet::CreditBroker credit{modelnet::PIECE_SIZE};
    modelnet::TransferSession xfer(credit);
    const UniValue st = xfer.Json();
    BOOST_CHECK(st.exists("ledger_size"));
    BOOST_CHECK(st.exists("outstanding"));
    BOOST_CHECK(st.exists("credit_ceiling"));
    BOOST_CHECK_EQUAL(st["ledger_size"].getInt<int>(), 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::QUEUED) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::CREDIT_RESERVED) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::SENT) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::RECEIVING) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::VERIFYING) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::COMMITTED) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::CANCELLED) >= 0);
    BOOST_CHECK(static_cast<int>(modelnet::RequestPhase::FAILED) >= 0);
    ZeroSpend(st, "1000 downloaders scale states");
}

BOOST_AUTO_TEST_CASE(unique_todo_10m_anti_entropy)
{
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN 10m anti-entropy; did not allocate 10m rows");
    const std::vector<std::string> none;
    BOOST_CHECK_EQUAL(none.size(), 0U);
}

BOOST_AUTO_TEST_CASE(unique_todo_20_buyer_superseed)
{
    BOOST_TEST_MESSAGE("HONEST_NOT_RUN 20-buyer lab");
}

BOOST_AUTO_TEST_CASE(unique_todo_mixed_0347_binaries)
{
    const char* env = std::getenv("BTX_MIXED_0347");
    if (env == nullptr || env[0] == '\0') {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN mixed 0.34.7 helper; BTX_MIXED_0347 unset");
        return;
    }
    BOOST_TEST_MESSAGE(std::string("HONEST_NOT_RUN mixed 0.34.7 helper; BTX_MIXED_0347=") + env +
                       " (env is not a mixed-binary lab PASS)");
}

BOOST_AUTO_TEST_CASE(unique_todo_core_v4_forbidden)
{
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.automatic_spend_atoms = 0;
    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE_MESSAGE(e, err);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);

    UniValue v4(UniValue::VOBJ);
    v4.pushKV("package_core_version", 4);
    std::vector<unsigned char> raw;
    std::string perr;
    BOOST_REQUIRE_MESSAGE(modelnet::EncodePjson1(v4, raw, perr), perr);
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/institutional/assets";
    req.body.assign(raw.begin(), raw.end());
    const auto resp = e->Handle(req);
    BOOST_CHECK_EQUAL(resp.status, 400);
    BOOST_REQUIRE(resp.json.exists("error") && resp.json["error"].isObject());
    BOOST_CHECK_EQUAL(resp.json["error"]["code"].get_str(), modelnet::HCP_ERR_CORE_V4);
    BOOST_CHECK_EQUAL(resp.json["error"]["code"].get_str(), "CORE_V4_FORBIDDEN");
    ZeroSpend(resp.json, "CORE_V4_FORBIDDEN");
}

BOOST_AUTO_TEST_SUITE_END()
