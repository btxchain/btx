// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve Layer v1.2 desktop-context cases.

#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

namespace {

fs::path SdkRoot()
{
#ifdef MODELNET_CRL12_PORTAL_PATH
    return fs::PathFromString(MODELNET_CRL12_PORTAL_PATH).parent_path().parent_path() / "crl12-sdk";
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path().parent_path().parent_path() /
           "contrib" / "modelnet" / "crl12-sdk";
#endif
}

std::string ShellQuote(const std::string& s)
{
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    q += "'";
    return q;
}

int Spawn(const std::string& cmd, std::string& combined)
{
    FILE* fp = ::popen(cmd.c_str(), "r");
    if (!fp) return -1;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != nullptr) combined.append(buf);
    const int st = ::pclose(fp);
    if (st == -1) return -1;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 127;
}

std::string Which(const char* name)
{
    std::string out;
    const int rc = Spawn(std::string("command -v ") + name + " 2>/dev/null", out);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    if (rc != 0) return {};
    return out;
}

std::string Python3()
{
    std::string exe = "/usr/bin/python3";
    if (::access(exe.c_str(), X_OK) != 0) exe = Which("python3");
    return exe;
}

std::string ReadFile(const fs::path& p)
{
    std::ifstream in(fs::PathToString(p));
    BOOST_REQUIRE_MESSAGE(in.good(), fs::PathToString(p) + " missing");
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

UniValue LoadJsonFile(const fs::path& p)
{
    UniValue o;
    BOOST_REQUIRE_MESSAGE(o.read(ReadFile(p)), fs::PathToString(p) + " is not JSON");
    return o;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_desktop_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_desktop_01_example_is_inspect)
{
    const UniValue ctx = LoadJsonFile(SdkRoot() / "fixtures" / "desktop-context.example.json");
    BOOST_CHECK_EQUAL(ctx["type"].get_str(), "btx.cognitiveReserve.v1_2");
    BOOST_CHECK_EQUAL(ctx["btx"]["purpose"].get_str(), "INSPECT");
    BOOST_CHECK(ctx["btx"].exists("asset_ref"));
    BOOST_CHECK(ctx["btx"].exists("projection_ref"));
}

BOOST_AUTO_TEST_CASE(cr12_desktop_02_no_localhost_execute)
{
    const fs::path sdk = SdkRoot();
    const fs::path example = sdk / "fixtures" / "desktop-context.example.json";
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    const fs::path apply = sdk / "python" / "apply_desktop_context.py";
    std::string out;
    const std::string cmd = ShellQuote(python) + " " + ShellQuote(fs::PathToString(apply)) + " " +
                            ShellQuote(fs::PathToString(example)) + " 2>&1";
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, "apply_desktop_context.py rc=" + std::to_string(rc) + "\n" + out);
    UniValue plan;
    BOOST_REQUIRE_MESSAGE(plan.read(out), out);
    BOOST_CHECK(plan["ok"].isTrue());
    BOOST_CHECK(plan["http"].isFalse());
    BOOST_CHECK(plan["localhost"].isFalse());
    BOOST_CHECK(plan["execute"].isFalse());
    BOOST_CHECK(out.find("executeAllocation") == std::string::npos);
    BOOST_CHECK(out.find("127.0.0.1") == std::string::npos);
    BOOST_CHECK(out.find("/execute") == std::string::npos);

    const std::string py_src = ReadFile(sdk / "python" / "desktop_context.py");
    BOOST_CHECK(py_src.find("urllib") == std::string::npos);
    BOOST_CHECK(py_src.find("http.client") == std::string::npos);
    BOOST_CHECK(py_src.find("fetch(") == std::string::npos);
    const std::string ts_src = ReadFile(sdk / "typescript" / "src" / "desktop_context.ts");
    BOOST_CHECK(ts_src.find("fetch(") == std::string::npos);
    BOOST_CHECK(ts_src.find("node:http") == std::string::npos);

    const std::string node = Which("node");
    if (node.empty()) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN typescript desktop apply");
    } else {
        std::string ts_out;
        const fs::path ts = sdk / "typescript" / "src" / "apply_desktop_context.ts";
        const std::string ts_cmd = "env NODE_NO_WARNINGS=1 " + ShellQuote(node) + " --experimental-strip-types " +
                                   ShellQuote(fs::PathToString(ts)) + " " + ShellQuote(fs::PathToString(example)) +
                                   " 2>/dev/null";
        const int ts_rc = Spawn(ts_cmd, ts_out);
        BOOST_REQUIRE_MESSAGE(ts_rc == 0, ts_out);
        BOOST_CHECK(ts_out.find("executeAllocation") == std::string::npos);
        BOOST_CHECK(ts_out.find("\"execute\":false") != std::string::npos ||
                    ts_out.find("\"execute\": false") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(cr12_desktop_03_no_secrets_in_payload)
{
    const std::string raw = ReadFile(SdkRoot() / "fixtures" / "desktop-context.example.json");
    BOOST_CHECK(raw.find("access_token") == std::string::npos);
    BOOST_CHECK(raw.find("private_key") == std::string::npos);
    BOOST_CHECK(raw.find("wallet_rpc") == std::string::npos);
    BOOST_CHECK(raw.find("mnemonic") == std::string::npos);
    BOOST_CHECK(raw.find("BEGIN PRIVATE") == std::string::npos);
    const UniValue ctx = LoadJsonFile(SdkRoot() / "fixtures" / "desktop-context.example.json");
    BOOST_CHECK(!ctx.exists("access_token"));
    BOOST_CHECK(!ctx["btx"].exists("access_token"));
}

BOOST_AUTO_TEST_CASE(cr12_desktop_04_draft_maps_to_prepare)
{
    const fs::path tmp = m_path_root / "desktop-draft.json";
    {
        std::ofstream out(fs::PathToString(tmp));
        BOOST_REQUIRE(out.good());
        out << R"({
  "type": "btx.cognitiveReserve.v1_2",
  "id": {"btxAsset": "asset-demo-a"},
  "name": "Synthetic reserve position",
  "btx": {
    "purpose": "DRAFT",
    "provider_ref": "provider-a",
    "projection_ref": "projection-demo-a",
    "asset_ref": "asset-demo-a"
  }
})";
    }
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    const fs::path apply = SdkRoot() / "python" / "apply_desktop_context.py";
    std::string out;
    const std::string cmd = ShellQuote(python) + " " + ShellQuote(fs::PathToString(apply)) + " " +
                            ShellQuote(fs::PathToString(tmp)) + " 2>&1";
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, out);
    UniValue plan;
    BOOST_REQUIRE(plan.read(out));
    BOOST_CHECK_EQUAL(plan["operations"][0]["operation_id"].get_str(), "preparePortfolioInstruction");
    BOOST_CHECK(plan["operations"][0]["body"]["execute"].isFalse());
    BOOST_CHECK(plan["execute"].isFalse());
    BOOST_CHECK(out.find("executeAllocation") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_05_source_has_no_http)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_desktop_context.py TestDesktopContext.test_source_has_no_http_client 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_06_rejects_token)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_desktop_context.py TestDesktopContext.test_rejects_token 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_07_rejects_execute_purpose)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_desktop_context.py TestDesktopContext.test_rejects_execute_purpose "
                            "TestDesktopContext.test_rejects_localhost_execute_url 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_08_engine_instruction_stays_draft)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    body.pushKV("source_projection_ref", "projection-demo-a");
    body.pushKV("client_operation_id", "desktop-draft-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const UniValue b = cr12_test::Body(r);
    BOOST_CHECK_EQUAL(b["status"].get_str(), "DRAFT");
    BOOST_CHECK(b["execute"].isFalse());
    BOOST_CHECK(b["no_reservation"].isTrue());
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_PORTFOLIO_INSTRUCTION);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_09_custom_namespace_not_fdc3_standard)
{
    const UniValue ctx = LoadJsonFile(SdkRoot() / "fixtures" / "desktop-context.example.json");
    BOOST_CHECK_EQUAL(ctx["type"].get_str(), "btx.cognitiveReserve.v1_2");
    BOOST_CHECK(ctx["type"].get_str().find("fdc3.") != 0);
    const std::string ux = ReadFile(SdkRoot() / "python" / "desktop_context.py");
    BOOST_CHECK(ux.find("btx.cognitiveReserve.v1_2") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_desktop_10_no_wallet_path)
{
    const std::string raw = ReadFile(SdkRoot() / "fixtures" / "desktop-context.example.json");
    BOOST_CHECK(raw.find("/home/") == std::string::npos);
    BOOST_CHECK(raw.find("wallet.dat") == std::string::npos);
    BOOST_CHECK(raw.find("local_path") == std::string::npos);
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_desktop_context.py TestDesktopContext.test_draft_maps_to_prepare_not_execute "
                            "TestDesktopContext.test_example_is_inspect_view "
                            "TestDesktopContext.test_compare_is_view_only "
                            "TestDesktopContext.test_rejects_execute_now 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_SUITE_END()
