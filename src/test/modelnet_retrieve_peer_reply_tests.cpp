// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Retrieve reads its swarm sources' replies (availability, ext/free/grant) as
// peer data. A malformed reply must cost that source only: the host below is
// honest, so the retrieve has to finish and the helper has to stay up.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/transport_pq.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_retrieve_peer_reply_tests, BasicTestingSetup)

namespace {

using Route = std::function<void(const modelnet::NativeRequest&, modelnet::NativeResponse&)>;

/** A PQ1 listener on 127.0.0.1 that answers native HTTP from a callback. */
class FakePeer
{
public:
    FakePeer(const fs::path& dir, Route route, int refuse_from = 0) : m_route(std::move(route)), m_refuse_from(refuse_from)
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

BOOST_AUTO_TEST_SUITE_END()
