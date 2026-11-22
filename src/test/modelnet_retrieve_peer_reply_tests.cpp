// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Retrieve reads its swarm sources' replies (availability, ext/free/grant) as
// peer data. A malformed reply must cost that source only: the host below is
// honest, so the retrieve has to finish and the helper has to stay up.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/file_stream.h>
#include <modelnet/helper.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/transport_pq.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_retrieve_peer_reply_tests, BasicTestingSetup)

// The integration cases below require the helper Unix RPC transport.
#ifndef WIN32
namespace {

using Route = std::function<void(const modelnet::NativeRequest&, modelnet::NativeResponse&)>;
/** Writes its own reply on the TLS stream; true means handled, close the connection. */
using RawRoute = std::function<bool(SSL*, int, const modelnet::NativeRequest&, const std::atomic<bool>&)>;

/** A PQ1 listener on 127.0.0.1 that answers native HTTP from a callback. */
class FakePeer
{
public:
    FakePeer(const fs::path& dir, Route route, int refuse_from = 0, RawRoute raw = {})
        : m_route(std::move(route)), m_raw(std::move(raw)), m_refuse_from(refuse_from)
    {
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::LoadPq1Identity(m_pq, dir, err), err);
        m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        BOOST_REQUIRE(m_fd >= 0);
        int one = 1;
        ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        BOOST_REQUIRE(::bind(m_fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
        BOOST_REQUIRE(::listen(m_fd, 16) == 0);
        socklen_t len = sizeof(a);
        BOOST_REQUIRE(::getsockname(m_fd, reinterpret_cast<sockaddr*>(&a), &len) == 0);
        m_port = ntohs(a.sin_port);
        m_accept = std::thread([this] { Accept(); });
    }
    ~FakePeer()
    {
        m_stop.store(true);
        if (m_accept.joinable()) m_accept.join();
        std::lock_guard<std::mutex> lock(m_mu);
        for (auto& t : m_conns) {
            if (t.joinable()) t.join();
        }
        ::close(m_fd);
    }
    std::string Endpoint() const { return "127.0.0.1:" + std::to_string(m_port); }

private:
    void Accept()
    {
        while (!m_stop.load()) {
            pollfd p{m_fd, POLLIN, 0};
            if (::poll(&p, 1, 100) <= 0) continue;
            const int c = ::accept(m_fd, nullptr, nullptr);
            if (c < 0) continue;
            if (m_refuse_from > 0 && ++m_accepted >= m_refuse_from) {
                ::close(c); // closed before TLS: that dial fails
                continue;
            }
            std::lock_guard<std::mutex> lock(m_mu);
            m_conns.emplace_back([this, c] { Serve(c); });
        }
    }
    void Serve(int c)
    {
        modelnet::SetPq1SocketOpts(c, true);
        SSL* ssl = SSL_new(static_cast<SSL_CTX*>(m_pq.SslCtx()));
        SSL_set_fd(ssl, c);
        SSL_set_accept_state(ssl);
        std::string err;
        if (modelnet::SslHandshake(ssl, c, /*accept=*/true, 10000, &m_stop, err)) {
            for (;;) {
                const std::string raw = modelnet::SslReadHttp(ssl, c, 1 << 20, 10000, &m_stop);
                if (raw.empty()) break;
                modelnet::NativeRequest req;
                if (!modelnet::ParseHttpRequest(raw, req, err)) break;
                if (m_raw && m_raw(ssl, c, req, m_stop)) break;
                modelnet::NativeResponse resp;
                resp.status = 404;
                resp.content_type = "application/json";
                resp.body = "{}";
                m_route(req, resp);
                if (!modelnet::SslWriteAll(ssl, c, modelnet::FormatHttpResponse(resp), 10000, &m_stop, err)) break;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ::close(c);
    }

    modelnet::Pq1Context m_pq;
    Route m_route;
    RawRoute m_raw;
    int m_refuse_from{0};
    int m_accepted{0};
    int m_fd{-1};
    uint16_t m_port{0};
    std::atomic<bool> m_stop{false};
    std::thread m_accept;
    std::mutex m_mu;
    std::vector<std::thread> m_conns;
};

/** A safetensors file with one U8 tensor of `body` bytes ({} and no data when 0). */
modelnet::CatalogEntry ImportModel(modelnet::ModelCatalog& cat, const fs::path& src, size_t body)
{
    fs::create_directories(src);
    std::string hdr = "{}";
    if (body > 0) {
        hdr = "{\"t\":{\"dtype\":\"U8\",\"shape\":[" + std::to_string(body) + "],\"data_offsets\":[0," +
              std::to_string(body) + "]}}";
        while (hdr.size() % 8) hdr += ' ';
    }
    std::vector<unsigned char> st(8 + hdr.size() + body, 0);
    WriteLE64(st.data(), hdr.size());
    std::copy(hdr.begin(), hdr.end(), st.begin() + 8);
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, imported, err), err);
    return imported;
}

void Json(modelnet::NativeResponse& resp, const std::string& body)
{
    resp.status = 200;
    resp.content_type = "application/json";
    resp.body = body;
}

using SwarmRoute = std::function<void(const modelnet::CatalogEntry&, const modelnet::NativeRequest&, modelnet::NativeResponse&)>;

/**
 * Run the helper in-process with two configured contacts: an honest host that
 * serves the model but lists no availability, and a swarm source answered by
 * `swarm`. Fetch the model with getmodel and return the job's final status.
 * `model_bytes` sizes the model; `host_refuse_from` makes the host refuse its
 * Nth connection and every one after it.
 */
std::string RetrieveWithSwarmSource(const fs::path& root, const SwarmRoute& swarm, size_t model_bytes = 0,
                                    int host_refuse_from = 0)
{
    fs::create_directories(root);
    modelnet::ModelCatalog host_cat{root / "host", 32 << 20};
    const auto model = ImportModel(host_cat, root / "host-src", model_bytes);
    UniValue manifest;
    std::string err;
    BOOST_REQUIRE_MESSAGE(host_cat.GetManifest(model.model_id, manifest, err), err);

    FakePeer host(root / "host-peer", [&](const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
        const std::string r{modelnet::MODEL_HTTP_ROOT};
        if (req.path == r + "hello") return Json(resp, "{\"schema_version\":2,\"protocol\":2}");
        if (req.path == r + "manifests/" + model.model_id.Hex()) return Json(resp, manifest.write());
        if (req.path == r + "ext/pex") return Json(resp, "{\"schema_version\":2}");
        if (req.path == r + "availability") return Json(resp, "{\"local\":{\"models\":[]}}");
        if (req.path == r + "ext/free/grant" || req.path.rfind(r + "transfers/", 0) == 0) {
            (void)modelnet::HandleNativeRequest(host_cat, req, resp);
        }
    }, host_refuse_from);
    FakePeer source(root / "swarm-peer", [&](const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
        swarm(model, req, resp);
    });

    modelnet::HelperConfig cfg;
    cfg.modeldir = root / "victim";
    fs::create_directories(cfg.modeldir);
    cfg.storage_mode = modelnet::StorageMode::FIXED;
    cfg.quota_bytes = 32 << 20;
    cfg.lan_discovery = false;
    cfg.natpmp = false;
    cfg.pwc_chain = "regtest";
    cfg.peers = {host.Endpoint(), source.Endpoint()};
    char sock_dir[] = "/tmp/btx-sock-XXXXXX";
    BOOST_REQUIRE(::mkdtemp(sock_dir) != nullptr);
    cfg.rpc_socket = fs::PathFromString(sock_dir) / "modeld.sock";
    std::atomic<bool> stop{false};
    std::thread daemon([&] { modelnet::RunModelDaemon(cfg, &stop); });
    auto finish = [&] {
        stop.store(true);
        if (daemon.joinable()) daemon.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
        ::rmdir(sock_dir);
    };
    std::string status = "running";
    try {
        const auto t0 = std::chrono::steady_clock::now();
        while (!fs::exists(cfg.rpc_socket) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        BOOST_REQUIRE(fs::exists(cfg.rpc_socket));

        UniValue params(UniValue::VARR);
        params.push_back(model.model_id.Hex());
        UniValue started;
        BOOST_REQUIRE_MESSAGE(modelnet::CallUnixRpc(cfg.rpc_socket, "getmodel", params, started, err), err);
        BOOST_REQUIRE_MESSAGE(started.exists("job_id") && started["job_id"].isStr(), started.write());
        const std::string job_id = started["job_id"].get_str();

        UniValue job;
        const auto t1 = std::chrono::steady_clock::now();
        while ((status == "running" || status == "queued") &&
               std::chrono::steady_clock::now() - t1 < std::chrono::seconds(60)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            UniValue jp(UniValue::VARR);
            jp.push_back(job_id);
            UniValue res;
            if (!modelnet::CallUnixRpc(cfg.rpc_socket, "getmodeljob", jp, res, err)) continue;
            if (!res.exists("jobs") || !res["jobs"].isArray() || res["jobs"].empty()) continue;
            job = res["jobs"][0];
            if (job.exists("status") && job["status"].isStr()) status = job["status"].get_str();
        }
        BOOST_TEST_MESSAGE("retrieve job: " + job.write());
        // The helper is still up.
        UniValue info;
        BOOST_CHECK_MESSAGE(modelnet::CallUnixRpc(cfg.rpc_socket, "getmodelnetworkinfo", UniValue(UniValue::VARR), info, err), err);
    } catch (...) {
        finish();
        throw;
    }
    finish();
    return status;
}

/**
 * One host that offers full_file_stream_v1. Its whole-file GET sends the
 * headers and one piece of junk, then stalls, so the retriever falls back to
 * piece GETs. Every other request is served honestly. Returns the job status
 * and counts the whole-file GETs in `streams`.
 */
std::string RetrieveAfterJunkStream(const fs::path& root, std::atomic<int>& streams)
{
    fs::create_directories(root);
    modelnet::ModelCatalog host_cat{root / "host", 256 << 20};
    // Just under the 64 MiB stream cap: one 4 MiB piece is 1/16 of the file,
    // so the measured rate falls short of PQ1_TRANSFER_MS after about 38 s.
    const auto model = ImportModel(host_cat, root / "host-src", (64u << 20) - 4096);
    UniValue manifest;
    std::string err;
    BOOST_REQUIRE_MESSAGE(host_cat.GetManifest(model.model_id, manifest, err), err);
    const uint64_t file_size = manifest["files"][0]["size"].getInt<uint64_t>();
    BOOST_REQUIRE_LE(file_size, modelnet::FULL_FILE_STREAM_MAX_BYTES);
    const std::string stream_path = std::string(modelnet::MODEL_HTTP_ROOT) + "files/" + model.artifact_id.Hex() + "/0";

    FakePeer host(
        root / "host-peer",
        [&](const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
            const std::string r{modelnet::MODEL_HTTP_ROOT};
            if (req.path == r + "hello") {
                return Json(resp, "{\"schema_version\":2,\"protocol\":2,\"full_file_stream_v1\":true}");
            }
            if (req.path == r + "manifests/" + model.model_id.Hex()) return Json(resp, manifest.write());
            if (req.path == r + "ext/pex") return Json(resp, "{\"schema_version\":2}");
            if (req.path == r + "availability") return Json(resp, "{\"local\":{\"models\":[]}}");
            if (req.path == r + "ext/free/grant" || req.path.rfind(r + "transfers/", 0) == 0) {
                (void)modelnet::HandleNativeRequest(host_cat, req, resp);
            }
        },
        /*refuse_from=*/0,
        [&](SSL* ssl, int c, const modelnet::NativeRequest& req, const std::atomic<bool>& stop) {
            if (req.method != "GET" || req.path != stream_path) return false;
            ++streams;
            const std::string junk(modelnet::PIECE_SIZE, '\xaa');
            const std::string head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                                     std::to_string(file_size) + "\r\n\r\n";
            std::string werr;
            std::atomic<bool> write_stop{false};
            if (!modelnet::SslWriteAll(ssl, c, head + junk, 10000, &write_stop, werr)) return true;
            // Stall until the retriever gives the stream up and closes.
            while (!stop.load()) {
                pollfd p{c, POLLIN, 0};
                if (::poll(&p, 1, 200) <= 0) continue;
                char b;
                const int n = SSL_read(ssl, &b, 1);
                if (n > 0) continue;
                if (SSL_get_error(ssl, n) == SSL_ERROR_WANT_READ) continue;
                break;
            }
            return true;
        });

    modelnet::HelperConfig cfg;
    cfg.modeldir = root / "victim";
    fs::create_directories(cfg.modeldir);
    cfg.storage_mode = modelnet::StorageMode::FIXED;
    cfg.quota_bytes = 256 << 20;
    cfg.lan_discovery = false;
    cfg.natpmp = false;
    cfg.pwc_chain = "regtest";
    cfg.peers = {host.Endpoint()};
    char sock_dir[] = "/tmp/btx-sock-XXXXXX";
    BOOST_REQUIRE(::mkdtemp(sock_dir) != nullptr);
    cfg.rpc_socket = fs::PathFromString(sock_dir) / "modeld.sock";
    std::atomic<bool> stop{false};
    std::thread daemon([&] { modelnet::RunModelDaemon(cfg, &stop); });
    auto finish = [&] {
        stop.store(true);
        if (daemon.joinable()) daemon.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
        ::rmdir(sock_dir);
    };
    std::string status = "running";
    try {
        const auto t0 = std::chrono::steady_clock::now();
        while (!fs::exists(cfg.rpc_socket) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        BOOST_REQUIRE(fs::exists(cfg.rpc_socket));
        UniValue params(UniValue::VARR);
        params.push_back(model.model_id.Hex());
        UniValue started;
        BOOST_REQUIRE_MESSAGE(modelnet::CallUnixRpc(cfg.rpc_socket, "getmodel", params, started, err), err);
        BOOST_REQUIRE_MESSAGE(started.exists("job_id") && started["job_id"].isStr(), started.write());
        const std::string job_id = started["job_id"].get_str();
        UniValue job;
        const auto t1 = std::chrono::steady_clock::now();
        while ((status == "running" || status == "queued") &&
               std::chrono::steady_clock::now() - t1 < std::chrono::seconds(300)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            UniValue jp(UniValue::VARR);
            jp.push_back(job_id);
            UniValue res;
            if (!modelnet::CallUnixRpc(cfg.rpc_socket, "getmodeljob", jp, res, err)) continue;
            if (!res.exists("jobs") || !res["jobs"].isArray() || res["jobs"].empty()) continue;
            job = res["jobs"][0];
            if (job.exists("status") && job["status"].isStr()) status = job["status"].get_str();
        }
        BOOST_TEST_MESSAGE("retrieve job: " + job.write());
    } catch (...) {
        finish();
        throw;
    }
    finish();
    return status;
}

std::string ClaimPieceZero(const modelnet::CatalogEntry& model)
{
    return "{\"local\":{\"models\":[{\"artifact_id\":\"" + model.artifact_id.Hex() +
           "\",\"files\":[{\"file_index\":0,\"piece_count\":1,\"ranges\":[[0,0]]}]}]}}";
}

} // namespace

BOOST_AUTO_TEST_CASE(swarm_grant_reply_with_non_string_fields_does_not_end_the_helper)
{
    // The source claims the piece, so its grant is asked for on a swarm
    // thread. Before the fix the number fields threw there and ended the process.
    std::atomic<int> grants{0};
    const std::string status = RetrieveWithSwarmSource(
        m_args.GetDataDirBase() / "grant",
        [&](const modelnet::CatalogEntry& model, const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
            const std::string r{modelnet::MODEL_HTTP_ROOT};
            if (req.path == r + "availability") return Json(resp, ClaimPieceZero(model));
            if (req.path == r + "ext/free/grant") {
                ++grants;
                return Json(resp, "{\"payload_hex\":1,\"sig_hex\":1,\"pubkey_hex\":1}");
            }
        });
    BOOST_CHECK_GE(grants.load(), 1);
    BOOST_CHECK_EQUAL(status, "done");
}

BOOST_AUTO_TEST_CASE(swarm_availability_with_wrong_types_does_not_fail_the_retrieve)
{
    const std::vector<std::string> replies{
        "{\"local\":{\"models\":[{\"files\":[{\"file_index\":\"x\"}]}]}}",
        "{\"local\":{\"models\":[{\"files\":[{\"file_index\":0,\"ranges\":[[\"x\",0]]}]}]}}",
    };
    for (size_t k = 0; k < replies.size(); ++k) {
        std::atomic<int> asked{0};
        const std::string status = RetrieveWithSwarmSource(
            m_args.GetDataDirBase() / ("availability-" + std::to_string(k)).c_str(),
            [&](const modelnet::CatalogEntry&, const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
                if (req.path == std::string(modelnet::MODEL_HTTP_ROOT) + "availability") {
                    ++asked;
                    Json(resp, replies[k]);
                }
            });
        BOOST_CHECK_GE(asked.load(), 1);
        BOOST_CHECK_MESSAGE(status == "done", "reply " + replies[k] + " left the job " + status);
    }
}

// A host streams one piece of junk and stalls. The retriever falls back to
// piece GETs; that piece was never checked, so it must not stand in the live
// store as if it were: the piece GETs fetch it with its proof and the model
// completes from the same host.
BOOST_AUTO_TEST_CASE(stream_fallback_does_not_keep_unchecked_pieces)
{
    std::atomic<int> streams{0};
    const std::string status = RetrieveAfterJunkStream(m_path_root / "junk-stream", streams);
    BOOST_CHECK_GE(streams.load(), 1);
    BOOST_CHECK_EQUAL(status, "done");
}

// getmodel starts a retrieve job, with its own worker thread, for every model
// it is asked for. The jobs are saved and started again with the helper. Both
// the jobs one helper runs and the saved jobs it starts are bounded.
BOOST_AUTO_TEST_CASE(retrieve_jobs_are_bounded)
{
    const fs::path root = m_path_root / "retrieve-bound";
    modelnet::HelperConfig cfg;
    cfg.modeldir = root / "node";
    fs::create_directories(cfg.modeldir);
    cfg.storage_mode = modelnet::StorageMode::FIXED;
    cfg.quota_bytes = 32 << 20;
    cfg.lan_discovery = false;
    cfg.natpmp = false;
    cfg.pwc_chain = "regtest";
    // Nothing listens there, so every job keeps retrying its only contact.
    cfg.peers = {"127.0.0.1:1"};
    char sock_dir[] = "/tmp/btx-sock-XXXXXX";
    BOOST_REQUIRE(::mkdtemp(sock_dir) != nullptr);
    cfg.rpc_socket = fs::PathFromString(sock_dir) / "modeld.sock";
    const auto with_daemon = [&](const std::function<void()>& body) {
        std::atomic<bool> stop{false};
        std::thread daemon([&] { modelnet::RunModelDaemon(cfg, &stop); });
        const auto t0 = std::chrono::steady_clock::now();
        while (!fs::exists(cfg.rpc_socket) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        try {
            BOOST_REQUIRE(fs::exists(cfg.rpc_socket));
            body();
        } catch (...) {
            stop.store(true);
            daemon.join();
            throw;
        }
        stop.store(true);
        daemon.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    };
    const auto getmodel = [&](int i, std::string& err) {
        UniValue params(UniValue::VARR);
        params.push_back(strprintf("%096x", i + 1));
        UniValue res;
        err.clear();
        return modelnet::CallUnixRpc(cfg.rpc_socket, "getmodel", params, res, err) &&
               res.exists("job_id") && res["job_id"].isStr() && !res["job_id"].get_str().empty();
    };
    const auto job_count = [&] {
        UniValue res;
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::CallUnixRpc(cfg.rpc_socket, "getmodeljob", UniValue(UniValue::VARR), res, err), err);
        return res["job_count"].getInt<int>();
    };

    constexpr int LIMIT{16};
    with_daemon([&] {
        std::string err;
        for (int i = 0; i < LIMIT; ++i) BOOST_REQUIRE_MESSAGE(getmodel(i, err), "job " + std::to_string(i) + ": " + err);
        BOOST_CHECK(!getmodel(LIMIT, err));
        BOOST_CHECK_MESSAGE(err.find("HELPER_BUSY") != std::string::npos, err);
        BOOST_CHECK_EQUAL(job_count(), LIMIT);
    });

    // A saved list longer than the limit, as an older helper could leave it.
    fs::path saved;
    for (const auto& e : fs::recursive_directory_iterator(cfg.modeldir)) {
        if (e.path().filename() == "retrieve_jobs.json") saved = e.path();
    }
    BOOST_REQUIRE(!saved.empty());
    UniValue jobs(UniValue::VARR);
    for (int i = 0; i < LIMIT + 8; ++i) {
        UniValue j(UniValue::VOBJ);
        j.pushKV("job_id", strprintf("%032x", 0x1000 + i));
        j.pushKV("model_id", strprintf("%096x", 0x1000 + i));
        j.pushKV("automatic", false);
        j.pushKV("status", "queued");
        jobs.push_back(j);
    }
    UniValue file(UniValue::VOBJ);
    file.pushKV("schema_version", 1);
    file.pushKV("jobs", jobs);
    {
        std::ofstream out(saved, std::ios::binary | std::ios::trunc);
        out << file.write();
    }
    with_daemon([&] {
        BOOST_CHECK_EQUAL(job_count(), LIMIT);
        // The jobs beyond the limit are dropped from the file at once, so a
        // later RPC cannot load one of them, without a worker, when a place frees.
        {
            std::ifstream in(saved, std::ios::binary);
            const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            UniValue left;
            BOOST_REQUIRE(left.read(raw));
            BOOST_CHECK_EQUAL(left["jobs"].size(), static_cast<size_t>(LIMIT));
        }
        std::string err;
        BOOST_CHECK(!getmodel(LIMIT + 100, err));
        BOOST_CHECK_MESSAGE(err.find("HELPER_BUSY") != std::string::npos, err);
    });
    ::rmdir(sock_dir);
}

BOOST_AUTO_TEST_CASE(early_return_waits_for_swarm_threads_before_their_state_goes)
{
    // Two pieces: the source claims piece 0 and is slow to answer its grant.
    // The host refuses the piece pool's connections, so the attempt returns
    // while the source's thread still runs; that thread then records the
    // failed grant. Before the fix it wrote to state the return had already
    // destroyed: a use after free, which crashes under glibc malloc perturbation.
    std::atomic<int> grants{0};
    const std::string status = RetrieveWithSwarmSource(
        m_args.GetDataDirBase() / "early-return",
        [&](const modelnet::CatalogEntry& model, const modelnet::NativeRequest& req, modelnet::NativeResponse& resp) {
            const std::string r{modelnet::MODEL_HTTP_ROOT};
            if (req.path == r + "availability") {
                return Json(resp, "{\"local\":{\"models\":[{\"artifact_id\":\"" + model.artifact_id.Hex() +
                                      "\",\"files\":[{\"file_index\":0,\"piece_count\":2,\"ranges\":[[0,0]]}]}]}}");
            }
            if (req.path == r + "ext/free/grant") {
                ++grants;
                std::this_thread::sleep_for(std::chrono::seconds(3));
                resp.status = 404;
            }
        },
        /*model_bytes=*/(4u << 20) + 4096, /*host_refuse_from=*/3);
    BOOST_CHECK_GE(grants.load(), 1);
    // Neither contact can serve the model; the job ends without taking the helper down.
    BOOST_CHECK_EQUAL(status, "failed");
}

#else
BOOST_AUTO_TEST_CASE(windows_helper_unix_rpc_is_explicitly_unsupported)
{
    const fs::path socket = m_path_root / "unsupported-helper.sock";
    std::vector<fs::path> before, after;
    for (const auto& entry : fs::directory_iterator(m_path_root)) before.push_back(entry.path());
    UniValue result;
    std::string err;
    BOOST_CHECK(!modelnet::CallUnixRpc(socket, "hello", UniValue(UniValue::VARR), result, err));
    BOOST_CHECK_EQUAL(err, "helper Unix RPC is not supported on this platform");
    for (const auto& entry : fs::directory_iterator(m_path_root)) after.push_back(entry.path());
    std::sort(before.begin(), before.end());
    std::sort(after.begin(), after.end());
    BOOST_CHECK(before == after);
    BOOST_TEST_MESSAGE("Windows helper Unix RPC is unsupported; the three Unix retrieval integration cases are not run");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
