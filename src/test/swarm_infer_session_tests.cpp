// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/session.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <system_error>

namespace {

struct TempRegularFile {
    explicit TempRegularFile(const fs::path& file) : path(file)
    {
        std::ofstream out(path);
        out << "not-an-engine\n";
        BOOST_REQUIRE(out.good());
    }
    ~TempRegularFile()
    {
        std::error_code ec;
        fs::remove(path, ec);
    }
    TempRegularFile(const TempRegularFile&) = delete;
    TempRegularFile& operator=(const TempRegularFile&) = delete;
    fs::path path;
};

std::string ReadLine(const fs::path& path)
{
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return line;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_infer_session_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_open_stores_nothing)
{
    const TempRegularFile file(m_path_root / "swarm-infer-session-empty.bin");
    modelnet::SwarmInferSession session;
    BOOST_CHECK_EQUAL(session.Open("", file.path), "ENGINE");
    BOOST_CHECK_EQUAL(session.Open("engine", fs::path{}), "ENGINE");
    BOOST_REQUIRE(!session.bound());
    BOOST_REQUIRE(!session.present());
    BOOST_REQUIRE(!session.qualified());
    BOOST_REQUIRE(!session.advertised());
    BOOST_REQUIRE(session.name().empty());
    BOOST_REQUIRE(session.binary().empty());
    BOOST_REQUIRE(session.status().empty());
    BOOST_REQUIRE(session.code().empty());
    BOOST_REQUIRE(!session.has_text());
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_CHECK_EQUAL(session.AcceptText("hello"), "ENGINE");
    BOOST_REQUIRE(!session.has_text());
    BOOST_REQUIRE(fs::is_regular_file(file.path));
}

BOOST_AUTO_TEST_CASE(absent_engine_refuses_text)
{
    const fs::path missing = m_path_root / "swarm-infer-session-missing.bin";
    std::error_code ec;
    fs::remove(missing, ec);
    modelnet::SwarmInferSession session;
    BOOST_CHECK_EQUAL(session.Open("vllm", missing), "ENGINE_ABSENT");
    BOOST_REQUIRE(session.bound());
    BOOST_REQUIRE(!session.present());
    BOOST_REQUIRE(!session.qualified());
    BOOST_REQUIRE(!session.advertised());
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE(!session.runtime_started());
    BOOST_REQUIRE(!session.process_spawned());
    BOOST_CHECK_EQUAL(session.status(), "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(session.code(), "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(session.AcceptText("hello"), "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(session.AcceptText(""), "ENGINE_ABSENT");
    BOOST_REQUIRE(!session.has_text());
    BOOST_REQUIRE(session.text().empty());
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(session.Publish(), "HELD");
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE(!session.rate_stored());
    BOOST_REQUIRE(!session.has_text());
    BOOST_REQUIRE(!fs::exists(missing));
}

BOOST_AUTO_TEST_CASE(installed_file_stays_unqualified_and_holds_one_text)
{
    const TempRegularFile file(m_path_root / "swarm-infer-session-installed.bin");
    modelnet::SwarmInferSession session;
    BOOST_REQUIRE_EQUAL(session.Open("torch", file.path), "UNQUALIFIED");
    BOOST_REQUIRE(session.bound());
    BOOST_REQUIRE(session.present());
    BOOST_REQUIRE(!session.qualified());
    BOOST_REQUIRE(!session.advertised());
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE(!session.rate_stored());
    BOOST_REQUIRE(!session.runtime_started());
    BOOST_REQUIRE(!session.process_spawned());
    BOOST_REQUIRE(!session.closed());
    BOOST_REQUIRE_EQUAL(session.status(), "INSTALLED");
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(session.last_err(), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(session.name(), "torch");
    BOOST_REQUIRE(session.binary() == file.path);
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p50_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p95_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.ttft_ms(), -1.0);

    BOOST_CHECK_EQUAL(session.AcceptText(""), "TEXT");
    BOOST_REQUIRE(!session.has_text());
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");

    const std::string text(1000, 'a');
    BOOST_REQUIRE_EQUAL(session.AcceptText(text), "STORED");
    BOOST_REQUIRE(session.last_err().empty());
    BOOST_REQUIRE(session.has_text());
    BOOST_REQUIRE_EQUAL(session.text(), text);
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");
    BOOST_REQUIRE(!session.qualified());
    BOOST_REQUIRE(!session.advertised());
    BOOST_REQUIRE(!session.published());

    BOOST_REQUIRE_EQUAL(session.AcceptText(text), "REPLAY");
    BOOST_REQUIRE_EQUAL(session.last_err(), "REPLAY");
    BOOST_REQUIRE_EQUAL(session.text(), text);

    BOOST_CHECK_EQUAL(session.AcceptText("other"), "CONFLICT");
    BOOST_CHECK_EQUAL(session.last_err(), "CONFLICT");
    BOOST_REQUIRE_EQUAL(session.text(), text);
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);

    BOOST_REQUIRE_EQUAL(session.Publish(), "HELD");
    BOOST_REQUIRE_EQUAL(session.last_err(), "HELD");
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE(!session.rate_stored());
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p50_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p95_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.ttft_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(session.text(), text);

    BOOST_CHECK_EQUAL(session.Open("", file.path), "ENGINE");
    BOOST_REQUIRE_EQUAL(session.text(), text);
    BOOST_REQUIRE_EQUAL(session.status(), "INSTALLED");
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");
    BOOST_REQUIRE(fs::is_regular_file(file.path));
}

BOOST_AUTO_TEST_CASE(streamed_text_does_not_become_metrics)
{
    const TempRegularFile file(m_path_root / "swarm-infer-session-stream.bin");
    modelnet::SwarmInferSession session;
    BOOST_REQUIRE_EQUAL(session.Open("torch", file.path), "UNQUALIFIED");
    const std::string streamed = "tok/s=80 p50=12 p95=40 ttft=3";
    BOOST_REQUIRE_EQUAL(session.AcceptText(streamed), "STORED");
    BOOST_REQUIRE_EQUAL(session.text(), streamed);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p50_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.p95_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.ttft_ms(), -1.0);
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE_EQUAL(session.Publish(), "HELD");
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE(!session.rate_stored());
    BOOST_REQUIRE_EQUAL(session.text(), streamed);
}

BOOST_AUTO_TEST_CASE(close_keeps_text_and_does_not_delete_the_binary)
{
    const TempRegularFile file(m_path_root / "swarm-infer-session-close.bin");
    modelnet::SwarmInferSession session;
    BOOST_REQUIRE_EQUAL(session.Open("torch", file.path), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(session.AcceptText("kept"), "STORED");
    session.Close();
    BOOST_REQUIRE(session.closed());
    BOOST_REQUIRE_EQUAL(session.text(), "kept");
    BOOST_REQUIRE_EQUAL(session.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(session.tokens_per_sec(), -1.0);
    BOOST_REQUIRE(!session.published());
    BOOST_REQUIRE_EQUAL(ReadLine(file.path), "not-an-engine");
    BOOST_REQUIRE(fs::is_regular_file(file.path));
    BOOST_CHECK_EQUAL(session.AcceptText("next"), "CLOSED");
    BOOST_REQUIRE_EQUAL(session.text(), "kept");
    BOOST_REQUIRE_EQUAL(session.code(), "UNQUALIFIED");
    BOOST_REQUIRE(!session.qualified());
    BOOST_REQUIRE(!session.advertised());
}

BOOST_AUTO_TEST_CASE(two_sessions_keep_their_own_text)
{
    const TempRegularFile file(m_path_root / "swarm-infer-session-two.bin");
    modelnet::SwarmInferSession first;
    modelnet::SwarmInferSession second;
    BOOST_REQUIRE_EQUAL(first.Open("a", file.path), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(second.Open("b", file.path), "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(first.AcceptText("one"), "STORED");
    BOOST_REQUIRE_EQUAL(second.AcceptText("two"), "STORED");
    BOOST_REQUIRE_EQUAL(first.text(), "one");
    BOOST_REQUIRE_EQUAL(second.text(), "two");
    BOOST_REQUIRE_EQUAL(first.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(second.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(first.tokens_per_sec(), -1.0);
    BOOST_REQUIRE_EQUAL(second.tokens_per_sec(), -1.0);
    BOOST_REQUIRE(fs::is_regular_file(file.path));
}

BOOST_AUTO_TEST_SUITE_END()
