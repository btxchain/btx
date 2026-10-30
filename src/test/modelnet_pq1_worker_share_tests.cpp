// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// R10-03: one peer address must not keep every PQ1 worker of the helper.
//
// The helper runs in-process on loopback. A netgroup is a full IPv4 address,
// so the cases connect from several 127.0.0.x source addresses: all of
// 127.0.0.0/8 is loopback on Linux, while other hosts may only have
// 127.0.0.1, and there the cases that need more addresses say so and return.
// Each case uses its own addresses, because the inbound and unauth maps are
// process-global.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/transport_pq.h>
#include <modelnet/types.h>
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
#include <cstdlib>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_pq1_worker_share_tests, BasicTestingSetup)

namespace {

const std::string HELLO = "POST /btx-model/2/hello HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}";

sockaddr_in Loopback(const char* ip, int port)
{
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

bool HaveSources(std::initializer_list<const char*> ips)
{
    for (const char* ip : ips) {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        const sockaddr_in a = Loopback(ip, 0);
        const bool ok = ::bind(fd, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) == 0;
        ::close(fd);
        if (!ok) {
            BOOST_TEST_MESSAGE("no source address " << ip << " on this host; case not run");
            return false;
        }
    }
    return true;
}

uint32_t Ng(const char* ip)
{
    const sockaddr_in a = Loopback(ip, 0);
    return modelnet::Ipv4Netgroup(reinterpret_cast<const sockaddr*>(&a), sizeof(a));
}

int FreePort()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a = Loopback("127.0.0.1", 0);
    ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    socklen_t len = sizeof(a);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
    const int port = ntohs(a.sin_port);
    ::close(fd);
    return port;
}

int TcpFrom(const char* src, int port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    const sockaddr_in s = Loopback(src, 0);
    const sockaddr_in d = Loopback("127.0.0.1", port);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&s), sizeof(s)) != 0 ||
        ::connect(fd, reinterpret_cast<const sockaddr*>(&d), sizeof(d)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

/** True once the helper has closed its end. */
bool ClosedByPeer(int fd)
{
    pollfd p{};
    p.fd = fd;
    p.events = POLLIN;
    if (::poll(&p, 1, 0) <= 0) return false;
    char b;
    return ::recv(fd, &b, 1, MSG_PEEK) <= 0;
}

struct Conn {
    int fd{-1};
    SSL* ssl{nullptr};
};

void Close(Conn& c)
{
    if (c.ssl) SSL_free(c.ssl);
    if (c.fd >= 0) ::close(c.fd);
    c = {};
}

void CloseAll(std::vector<Conn>& conns)
{
    for (auto& c : conns) Close(c);
    conns.clear();
}

bool Ping(Conn& c, int timeout_ms)
{
    std::string err;
    if (!c.ssl || !modelnet::SslWriteAll(c.ssl, c.fd, HELLO, timeout_ms, nullptr, err)) return false;
    return modelnet::SslReadHttp(c.ssl, c.fd, 1 << 16, timeout_ms, nullptr, &err).find(" 200 ") != std::string::npos;
}

int Alive(std::vector<Conn>& conns)
{
    int n = 0;
    for (auto& c : conns) n += Ping(c, 2000) ? 1 : 0;
    return n;
}

/** A PQ1 session from `src` that has been answered once. */
bool Pq1Hello(modelnet::Pq1Context& ctx, const char* src, int port, int timeout_ms, Conn& out)
{
    out.fd = TcpFrom(src, port);
    if (out.fd < 0) return false;
    modelnet::SetPq1SocketOpts(out.fd, true);
    out.ssl = SSL_new(static_cast<SSL_CTX*>(ctx.SslCtx()));
    SSL_set_fd(out.ssl, out.fd);
    SSL_set_connect_state(out.ssl);
    std::string err;
    return modelnet::SslHandshake(out.ssl, out.fd, /*accept=*/false, timeout_ms, nullptr, err) && Ping(out, timeout_ms);
}

std::string HttpBody(const std::string& raw)
{
    const auto p = raw.find("\r\n\r\n");
    return p == std::string::npos ? std::string{} : raw.substr(p + 4);
}

/** A model whose piece 0 is a full piece, imported into `modeldir` before the helper starts. */
modelnet::CatalogEntry ImportOnePiece(const fs::path& modeldir, uint64_t quota)
{
    const fs::path src = modeldir.parent_path() / "src";
    fs::create_directories(src);
    const std::string n = std::to_string(modelnet::PIECE_SIZE);
    std::string hdr = "{\"w\":{\"dtype\":\"U8\",\"shape\":[" + n + "],\"data_offsets\":[0," + n + "]}}";
    hdr.append((8 - hdr.size() % 8) % 8, ' ');
    unsigned char len[8];
    WriteLE64(len, hdr.size());
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(len), sizeof(len));
        out << hdr << std::string(modelnet::PIECE_SIZE, '\x5a');
    }
    modelnet::ModelCatalog cat{modeldir, quota};
    modelnet::CatalogEntry e;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), true, e, err), err);
    return e;
}

/** Asks on `c` for a free grant for piece 0, then for the piece, and leaves the reply unread. */
bool AskForPiece(Conn& c, const modelnet::CatalogEntry& e)
{
    std::string err;
    const std::string body = "{\"model_id\":\"" + e.model_id.Hex() + "\",\"first_piece\":0,\"piece_count\":1}";
    if (!modelnet::SslWriteAll(c.ssl, c.fd,
                               "POST /btx-model/2/ext/free/grant HTTP/1.1\r\nHost: x\r\nContent-Length: " +
                                   std::to_string(body.size()) + "\r\nConnection: keep-alive\r\n\r\n" + body,
                               5000, nullptr, err)) {
        return false;
    }
    UniValue g;
    if (!g.read(HttpBody(modelnet::SslReadHttp(c.ssl, c.fd, 1 << 16, 5000, nullptr, &err))) || !g.exists("payload_hex")) {
        return false;
    }
    return modelnet::SslWriteAll(c.ssl, c.fd,
                                 "GET /btx-model/2/transfers/" + e.artifact_id.Hex() + "/pieces/0/0 HTTP/1.1\r\nHost: x\r\n"
                                 "X-BTX-Grant-Payload: " + g["payload_hex"].get_str() +
                                     "\r\nX-BTX-Grant-Sig: " + g["sig_hex"].get_str() +
                                     "\r\nX-BTX-Grant-Pubkey: " + g["pubkey_hex"].get_str() +
                                     "\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                                 5000, nullptr, err);
}

/** The helper serving PQ1 on a loopback port, stopped on scope exit. */
struct Helper {
    modelnet::HelperConfig cfg;
    modelnet::Pq1Context client;
    std::atomic<bool> stop{false};
    std::thread thread;
    // A socket under the test datadir does not fit in sun_path.
    std::string sock_dir{"/tmp/btx-sock-XXXXXX"};
    int port{0};

    explicit Helper(const fs::path& root, const std::function<void(modelnet::HelperConfig&)>& prepare = {})
    {
        fs::create_directories(root);
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::LoadPq1Identity(client, root / "client", err), err);
        cfg.modeldir = root / "seeder";
        fs::create_directories(cfg.modeldir);
        cfg.storage_mode = modelnet::StorageMode::FIXED;
        cfg.quota_bytes = 8 << 20;
        cfg.lan_discovery = false;
        cfg.natpmp = false;
        cfg.pwc_chain = "regtest";
        port = FreePort();
        cfg.bind = "127.0.0.1:" + std::to_string(port);
        BOOST_REQUIRE(::mkdtemp(sock_dir.data()) != nullptr);
        cfg.rpc_socket = fs::PathFromString(sock_dir) / "modeld.sock";
        if (prepare) prepare(cfg);
        thread = std::thread([this] { modelnet::RunModelDaemon(cfg, &stop); });
        const auto t0 = std::chrono::steady_clock::now();
        while (!fs::exists(cfg.rpc_socket) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(10)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    ~Helper()
    {
        stop.store(true);
        if (thread.joinable()) thread.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
        ::rmdir(sock_dir.c_str());
    }

    /** Every inbound slot comes back once the peers have closed. */
    bool Drained()
    {
        const auto t0 = std::chrono::steady_clock::now();
        while (modelnet::GlobalConnLimits().Inbound() != 0) {
            if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(15)) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return true;
    }

    /** One address's connections take every worker; another address must still be served. */
    void CheckOtherServed(const char* other)
    {
        Conn c;
        const auto t0 = std::chrono::steady_clock::now();
        const bool served = Pq1Hello(client, other, port, 5000, c);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        BOOST_TEST_MESSAGE("other address served=" << served << " after " << ms << " ms");
        BOOST_CHECK_MESSAGE(served, "a peer from another address must get a worker while one address holds all of them");
        Close(c);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(idle_sessions_of_one_address_hand_a_worker_over)
{
    if (!HaveSources({"127.0.0.21", "127.0.0.22"})) return;
    Helper h(m_args.GetDataDirBase() / "share-idle");
    {
        Conn probe;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.22", h.port, 5000, probe));
        Close(probe);
    }
    // One address opens its 8 connections, one per worker. They finish PQ1 and idle.
    std::vector<Conn> held;
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        Conn c;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.21", h.port, 5000, c));
        held.push_back(c);
    }
    h.CheckOtherServed("127.0.0.22");
    // One worker changed hands, not more.
    BOOST_CHECK_EQUAL(Alive(held), modelnet::PQ1_HTTP_WORKERS - 1);
    CloseAll(held);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(unfinished_requests_of_one_address_hand_a_worker_over)
{
    if (!HaveSources({"127.0.0.31", "127.0.0.32"})) return;
    Helper h(m_args.GetDataDirBase() / "share-unfinished");
    std::vector<Conn> held;
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        Conn c;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.31", h.port, 5000, c));
        held.push_back(c);
    }
    // Each connection keeps a request header arriving, a byte at a time.
    std::atomic<bool> done{false};
    std::thread writer([&] {
        std::string err;
        for (auto& c : held) (void)modelnet::SslWriteAll(c.ssl, c.fd, "POST /btx-model/2/hello HTTP/1.1\r\n", 2000, nullptr, err);
        while (!done.load()) {
            for (auto& c : held) (void)modelnet::SslWriteAll(c.ssl, c.fd, "X", 2000, nullptr, err);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    h.CheckOtherServed("127.0.0.32");
    done.store(true);
    writer.join();
    CloseAll(held);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(unstarted_handshakes_of_one_address_hand_a_worker_over)
{
    if (!HaveSources({"127.0.0.41", "127.0.0.42"})) return;
    Helper h(m_args.GetDataDirBase() / "share-unstarted");
    {
        Conn probe;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.42", h.port, 5000, probe));
        Close(probe);
    }
    // TCP connections that never start TLS: each holds a worker in the handshake.
    std::vector<Conn> held;
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        Conn c;
        c.fd = TcpFrom("127.0.0.41", h.port);
        BOOST_REQUIRE(c.fd >= 0);
        held.push_back(c);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    h.CheckOtherServed("127.0.0.42");
    // A handshake this side cut short is not counted against the address.
    BOOST_CHECK_EQUAL(modelnet::UnauthCount(Ng("127.0.0.41")), 0);
    CloseAll(held);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(two_buyers_split_the_workers_without_churn)
{
    if (!HaveSources({"127.0.0.51", "127.0.0.52"})) return;
    Helper h(m_args.GetDataDirBase() / "share-buyers");
    const int workers = modelnet::PQ1_HTTP_WORKERS;
    // Buyer A pipelines on 8 connections. Alone, it keeps every one of them.
    std::vector<Conn> a;
    for (int i = 0; i < modelnet::PQ1_INFLIGHT_PIECES; ++i) {
        Conn c;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.51", h.port, 5000, c));
        a.push_back(c);
    }
    BOOST_CHECK_EQUAL(Alive(a), workers);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    BOOST_CHECK_EQUAL(Alive(a), workers);

    // Buyer B opens connections one at a time. Each is served until both hold half.
    std::vector<Conn> b;
    for (int i = 0; i < modelnet::PQ1_INFLIGHT_PIECES; ++i) {
        Conn c;
        if (!Pq1Hello(h.client, "127.0.0.52", h.port, 5000, c)) {
            Close(c);
            break;
        }
        b.push_back(c);
    }
    BOOST_TEST_MESSAGE("buyer B was served " << b.size() << " connections");
    BOOST_CHECK_EQUAL(static_cast<int>(b.size()), workers / 2);
    std::vector<Conn> a_live;
    for (auto& c : a) {
        if (Ping(c, 2000)) {
            a_live.push_back(c);
        } else {
            Close(c);
        }
    }
    a.clear();
    BOOST_CHECK_EQUAL(static_cast<int>(a_live.size()), workers / 2);

    // A reconnects. The split is already even, so nobody hands a worker over:
    // A waits, and none of B's or A's sessions is closed for it.
    Conn again;
    BOOST_CHECK(!Pq1Hello(h.client, "127.0.0.51", h.port, 3000, again));
    Close(again);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    BOOST_CHECK_EQUAL(Alive(a_live), workers / 2);
    BOOST_CHECK_EQUAL(Alive(b), workers / 2);

    CloseAll(a_live);
    CloseAll(b);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(a_busy_connection_finishes_its_response_before_handing_over)
{
    if (!HaveSources({"127.0.0.93", "127.0.0.94"})) return;
    // Uploads are paced at one piece a second, so one address asking for a
    // piece on each of its 8 connections keeps every worker busy for 1 to 8 s.
    // The cap stays set until the next helper starts; the cases below start their own.
    modelnet::CatalogEntry model;
    Helper h(m_args.GetDataDirBase() / "share-busy", [&](modelnet::HelperConfig& cfg) {
        model = ImportOnePiece(cfg.modeldir, cfg.quota_bytes);
        cfg.upload_bps = modelnet::PIECE_SIZE;
    });
    std::vector<Conn> a;
    for (int i = 0; i < modelnet::PQ1_HTTP_WORKERS; ++i) {
        Conn c;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.93", h.port, 5000, c));
        BOOST_REQUIRE(AskForPiece(c, model));
        a.push_back(c);
    }
    // Another address arrives while every worker is answering.
    std::atomic<bool> b_served{false};
    std::thread b([&] {
        Conn c;
        b_served.store(Pq1Hello(h.client, "127.0.0.94", h.port, 15000, c));
        Close(c);
    });
    // Every piece arrives whole: the connection that hands its worker over
    // first finishes the response it is sending...
    int whole = 0;
    for (auto& c : a) {
        std::string err;
        const std::string raw = modelnet::SslReadHttp(c.ssl, c.fd, 2 * modelnet::PIECE_SIZE, 15000, nullptr, &err);
        whole += raw.find(" 200 ") != std::string::npos && HttpBody(raw).size() == modelnet::PIECE_SIZE ? 1 : 0;
    }
    b.join();
    BOOST_CHECK_EQUAL(whole, modelnet::PQ1_HTTP_WORKERS);
    BOOST_CHECK_MESSAGE(b_served.load(), "the other address must get a worker once a response is out");
    // ...and then closes: the address keeps the other 7.
    BOOST_CHECK_EQUAL(Alive(a), modelnet::PQ1_HTTP_WORKERS - 1);
    CloseAll(a);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(a_silent_connection_does_not_stall_the_helper)
{
    if (!HaveSources({"127.0.0.91", "127.0.0.92"})) return;
    Helper h(m_args.GetDataDirBase() / "share-silent");
    // A TCP connection that sends nothing, while every worker is free.
    const int quiet = TcpFrom("127.0.0.91", h.port);
    BOOST_REQUIRE(quiet >= 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    Conn c;
    const auto t0 = std::chrono::steady_clock::now();
    const bool served = Pq1Hello(h.client, "127.0.0.92", h.port, 5000, c);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_TEST_MESSAGE("silent: other address served=" << served << " after " << ms << " ms");
    BOOST_CHECK_MESSAGE(served, "a connection that sends nothing must not stop the helper serving others");
    Close(c);
    ::close(quiet);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(a_waiting_peer_that_sent_nothing_takes_no_worker)
{
    if (!HaveSources({"127.0.0.61", "127.0.0.62", "127.0.0.63"})) return;
    Helper h(m_args.GetDataDirBase() / "share-nothing-sent");
    std::vector<Conn> a;
    for (int i = 0; i < modelnet::PQ1_HTTP_WORKERS; ++i) {
        Conn c;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.61", h.port, 5000, c));
        a.push_back(c);
    }
    // While every worker is taken, one address connects and leaves at once,
    // and another connects and sends nothing.
    const int gone = TcpFrom("127.0.0.62", h.port);
    BOOST_REQUIRE(gone >= 0);
    ::close(gone);
    const int quiet = TcpFrom("127.0.0.63", h.port);
    BOOST_REQUIRE(quiet >= 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    BOOST_CHECK_EQUAL(Alive(a), modelnet::PQ1_HTTP_WORKERS);
    ::close(quiet);
    CloseAll(a);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(a_connection_left_waiting_past_the_handshake_timeout_is_not_counted)
{
    if (!HaveSources({"127.0.0.81", "127.0.0.82"})) return;
    Helper h(m_args.GetDataDirBase() / "share-left-waiting");
    // Two addresses hold half the workers each, so neither gives one up.
    std::vector<Conn> held;
    for (const char* ip : {"127.0.0.81", "127.0.0.82"}) {
        for (int i = 0; i < modelnet::PQ1_HTTP_WORKERS / 2; ++i) {
            Conn c;
            BOOST_REQUIRE(Pq1Hello(h.client, ip, h.port, 5000, c));
            held.push_back(c);
        }
    }
    // One more connection starts its handshake and waits longer than a client would.
    Conn late;
    const auto t0 = std::chrono::steady_clock::now();
    BOOST_CHECK(!Pq1Hello(h.client, "127.0.0.81", h.port, modelnet::PQ1_HANDSHAKE_MS + 3000, late));
    const auto waited = std::chrono::steady_clock::now() - t0;
    Close(late);
    // The helper closed it unserved, before the client's own timeout...
    BOOST_CHECK(waited < std::chrono::milliseconds(modelnet::PQ1_HANDSHAKE_MS + 2000));
    // ...and did not count it as a failed handshake.
    BOOST_CHECK_EQUAL(modelnet::UnauthCount(Ng("127.0.0.81")), 0);
    BOOST_CHECK_EQUAL(Alive(held), modelnet::PQ1_HTTP_WORKERS);
    CloseAll(held);
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(two_addresses_cannot_take_every_inbound_slot)
{
    if (!HaveSources({"127.0.0.71", "127.0.0.72", "127.0.0.73"})) return;
    Helper h(m_args.GetDataDirBase() / "share-slots");
    {
        Conn probe;
        BOOST_REQUIRE(Pq1Hello(h.client, "127.0.0.73", h.port, 5000, probe));
        Close(probe);
    }
    // Two addresses keep 8 connections each open, reopening any the helper
    // closes, until every inbound slot is taken.
    std::map<std::string, std::vector<int>> held{{"127.0.0.71", {}}, {"127.0.0.72", {}}};
    int full_for = 0;
    const auto t0 = std::chrono::steady_clock::now();
    while (full_for < 3 && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5)) {
        for (auto& [ip, fds] : held) {
            for (auto it = fds.begin(); it != fds.end();) {
                if (ClosedByPeer(*it)) {
                    ::close(*it);
                    it = fds.erase(it);
                } else {
                    ++it;
                }
            }
            while (static_cast<int>(fds.size()) < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP) {
                const int fd = TcpFrom(ip.c_str(), h.port);
                if (fd < 0) break;
                fds.push_back(fd);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        full_for = modelnet::GlobalConnLimits().Inbound() == modelnet::PQ1_MAX_INBOUND ? full_for + 1 : 0;
    }
    BOOST_REQUIRE_EQUAL(modelnet::GlobalConnLimits().Inbound(), modelnet::PQ1_MAX_INBOUND);
    h.CheckOtherServed("127.0.0.73");
    for (auto& [ip, fds] : held) {
        for (const int fd : fds) ::close(fd);
    }
    BOOST_CHECK(h.Drained());
}

BOOST_AUTO_TEST_CASE(worker_share_policy)
{
    using modelnet::Pq1NextWaiting;
    using modelnet::Pq1WorkerDonor;
    // The next waiting connection is the oldest from the address that holds the fewest.
    BOOST_CHECK_EQUAL(Pq1NextWaiting({1, 2, 3}, {{1, 5}, {2, 1}, {3, 1}}), 1U);
    BOOST_CHECK_EQUAL(Pq1NextWaiting({1, 1, 4}, {{1, 5}}), 2U);
    BOOST_CHECK_EQUAL(Pq1NextWaiting({7}, {}), 0U);

    // Only an address holding at least two more than the waiting one gives a worker up.
    BOOST_CHECK(!Pq1WorkerDonor(2, {}));
    BOOST_CHECK(!Pq1WorkerDonor(2, {{1, 1}}));
    BOOST_CHECK(Pq1WorkerDonor(2, {{1, 2}}) == std::optional<uint32_t>{1});
    BOOST_CHECK(!Pq1WorkerDonor(2, {{1, 5}, {2, 4}}));
    BOOST_CHECK(Pq1WorkerDonor(2, {{1, 6}, {2, 4}}) == std::optional<uint32_t>{1});
    // The waiting address never gives to itself.
    BOOST_CHECK(!Pq1WorkerDonor(1, {{1, 8}}));
    // The address holding the most gives first.
    BOOST_CHECK(Pq1WorkerDonor(9, {{1, 3}, {2, 5}}) == std::optional<uint32_t>{2});

    // Over random splits of the workers: every hand-over lowers the sum of
    // squares of the shares, so a run of them ends, and none is answered by
    // one back.
    uint32_t r = 12345;
    auto rnd = [&](uint32_t n) { r = r * 1103515245u + 12345u; return (r >> 16) % n; };
    for (int round = 0; round < 2000; ++round) {
        std::map<uint32_t, int> held;
        int left = modelnet::PQ1_HTTP_WORKERS;
        while (left > 0) {
            const int n = 1 + static_cast<int>(rnd(static_cast<uint32_t>(left)));
            held[rnd(5)] += n;
            left -= n;
        }
        int handovers = 0;
        for (;;) {
            const uint32_t waiting = rnd(6);
            const auto donor = Pq1WorkerDonor(waiting, held);
            if (!donor) break;
            long before = 0, after = 0;
            for (const auto& [ng, n] : held) before += long{n} * n;
            if (--held[*donor] == 0) held.erase(*donor);
            ++held[waiting];
            for (const auto& [ng, n] : held) after += long{n} * n;
            BOOST_REQUIRE_LT(after, before);
            BOOST_REQUIRE(Pq1WorkerDonor(*donor, held) != std::optional<uint32_t>{waiting});
            BOOST_REQUIRE_LE(++handovers, modelnet::PQ1_HTTP_WORKERS * modelnet::PQ1_HTTP_WORKERS);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
