// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve Layer v1.2 SDK cases.

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

void TrimNl(std::string& s)
{
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_sdk_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_sdk_01_spawn_body_id)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const UniValue env = cr12_test::Json(r);
    BOOST_REQUIRE_EQUAL(env["object_type"].get_str(), modelnet::HCP_TYPE_LAYER_EXTENSION);
    modelnet::Digest48 native;
    std::string err;
    BOOST_REQUIRE(modelnet::HcpBodyId(env["object_type"].get_str(), env["body"], native, err));
    BOOST_CHECK_EQUAL(native.Hex(), env["body_id"].get_str());

    const fs::path sdk = SdkRoot();
    const fs::path py = sdk / "python" / "compute_body_id.py";
    BOOST_REQUIRE_MESSAGE(fs::exists(py), fs::PathToString(py) + " missing");
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty() && ::access(python.c_str(), X_OK) == 0, "python3 required");

    const fs::path envp = m_path_root / "cr12-sdk-envelope.json";
    {
        std::ofstream out(fs::PathToString(envp));
        BOOST_REQUIRE(out.good());
        out << r.body;
    }
    std::string py_out;
    const std::string py_cmd = ShellQuote(python) + " " + ShellQuote(fs::PathToString(py)) + " " +
                               ShellQuote(fs::PathToString(envp)) + " 2>&1";
    const int py_rc = Spawn(py_cmd, py_out);
    TrimNl(py_out);
    BOOST_REQUIRE_MESSAGE(py_rc == 0, "compute_body_id.py rc=" + std::to_string(py_rc) + "\n" + py_out);
    BOOST_CHECK_EQUAL(py_out, env["body_id"].get_str());

    const std::string node = Which("node");
    if (node.empty()) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN typescript SDK body_id");
    } else {
        const fs::path ts = sdk / "typescript" / "src" / "compute_body_id.ts";
        BOOST_REQUIRE_MESSAGE(fs::exists(ts), fs::PathToString(ts) + " missing");
        std::string ts_out;
        const std::string ts_cmd = "env NODE_NO_WARNINGS=1 " + ShellQuote(node) + " --experimental-strip-types " +
                                   ShellQuote(fs::PathToString(ts)) + " " + ShellQuote(fs::PathToString(envp)) +
                                   " 2>/dev/null";
        const int ts_rc = Spawn(ts_cmd, ts_out);
        TrimNl(ts_out);
        BOOST_REQUIRE_MESSAGE(ts_rc == 0, "compute_body_id.ts rc=" + std::to_string(ts_rc) + "\n" + ts_out);
        BOOST_CHECK_EQUAL(ts_out, env["body_id"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(cr12_sdk_02_refuse_export_secrets)
{
    const fs::path sdk = SdkRoot();
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(sdk)) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_refuse_export_secrets 2>&1";
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, "SDK export-secret test rc=" + std::to_string(rc) + "\n" + out);

    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("access_token", "stolen");
    bad.pushKV("format", "JSONL");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &bad));
    if (r.status >= 200 && r.status < 300) {
        const UniValue b = cr12_test::Body(r);
        BOOST_CHECK(!b.exists("access_token") || b["access_token"].isNull());
        BOOST_CHECK(!b.exists("private_key") || b["private_key"].isNull());
        BOOST_CHECK(b.write().find("stolen") == std::string::npos);
    } else {
        BOOST_CHECK_MESSAGE(r.status == 400, r.body);
    }
}

BOOST_AUTO_TEST_CASE(cr12_sdk_03_refuse_execute_from_analytics)
{
    auto e = cr12_test::Lab();
    auto full = cr12_test::Tok(*e);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "cr12-sdk-analytics-exec");
    alloc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", full, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Json(r)["body"]["allocation_id"].get_str();

    auto analytics = cr12_test::Tok(*e, cr12_test::AnalyticsScopes());
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", analytics));
    BOOST_CHECK_EQUAL(r.status, 401);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);

    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_refuse_execute_from_analytics 2>&1";
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, "SDK analytics execute test rc=" + std::to_string(rc) + "\n" + out);
}

BOOST_AUTO_TEST_CASE(cr12_sdk_04_typed_paths_no_rpc)
{
    const fs::path catalog = SdkRoot() / "schemas" / "operations-v1.2.json";
    const std::string json = ReadFile(catalog);
    BOOST_CHECK(json.find("\"new_operations\": 43") != std::string::npos ||
                json.find("\"new_operations\":43") != std::string::npos);
    BOOST_CHECK(json.find("/rpc") == std::string::npos);
    BOOST_CHECK(json.find("\"operation_id\": \"executeAllocation\"") == std::string::npos);
    BOOST_CHECK(json.find("\"operation_id\":\"executeAllocation\"") == std::string::npos);
    BOOST_CHECK(json.find("/btx/hcp/v1/") != std::string::npos);

    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_no_rpc_passthrough 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_CASE(cr12_sdk_05_automatic_spend_atoms_zero)
{
    auto e = cr12_test::Lab();
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(modelnet::HCP_AUTOMATIC_SPEND_ATOMS, 0);
    const std::string py = ReadFile(SdkRoot() / "python" / "btx_crl12.py");
    BOOST_CHECK(py.find("AUTOMATIC_SPEND_ATOMS = 0") != std::string::npos);
    const std::string ts = ReadFile(SdkRoot() / "typescript" / "src" / "client.ts");
    BOOST_CHECK(ts.find("AUTOMATIC_SPEND_ATOMS = 0") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_sdk_06_catalog_forty_three)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_ops_catalog_count "
                            "TestCrl12BodyId.test_forty_three_operation_ids_on_client 2>&1";
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, out);

    const std::string node = Which("node");
    if (node.empty()) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN typescript SDK unit tests");
    } else {
        std::string ts_out;
        const fs::path tdir = SdkRoot() / "typescript";
        const std::string ts_cmd = "cd " + ShellQuote(fs::PathToString(tdir)) +
                                   " && env NODE_NO_WARNINGS=1 " + ShellQuote(node) +
                                   " --experimental-strip-types --test src/body_id.test.ts src/desktop_context.test.ts 2>&1";
        const int ts_rc = Spawn(ts_cmd, ts_out);
        BOOST_REQUIRE_MESSAGE(ts_rc == 0, "typescript SDK tests rc=" + std::to_string(ts_rc) + "\n" + ts_out);
    }
}

BOOST_AUTO_TEST_CASE(cr12_sdk_07_export_manifest_has_no_secrets)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue req(UniValue::VOBJ);
    req.pushKV("format", "JSONL");
    req.pushKV("secret_ref", "os:keyring/export-policy");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &req));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const UniValue b = cr12_test::Body(r);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_EXPORT_MANIFEST);
    BOOST_CHECK(!b.exists("access_token") || b["access_token"].isNull());
    BOOST_CHECK(!b.exists("private_key") || b["private_key"].isNull());
    BOOST_CHECK(!b.exists("secret") || b["secret"].isNull());
    const std::string dump = b.write();
    BOOST_CHECK(dump.find("BEGIN PRIVATE") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr12_sdk_08_https_default)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_https_default_rejects_http 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_CASE(cr12_sdk_09_import_not_custody)
{
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_import_not_custody_credit 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);

    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    v.pushKV("row_count", "0");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string iid = cr12_test::Body(r)["import_id"].get_str();
    UniValue c(UniValue::VOBJ);
    c.pushKV("mapping_digest", cr12_test::Body(r)["mapping_digest"].get_str());
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + iid + "/commit", tok, &c));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(cr12_test::Body(r)["custody_credit"].isFalse());
    BOOST_CHECK(cr12_test::Body(r)["spendable_created"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_sdk_10_no_brand_dispatch)
{
    const std::string py = ReadFile(SdkRoot() / "python" / "btx_crl12.py");
    BOOST_CHECK(py.find("bloomberg") == std::string::npos);
    BOOST_CHECK(py.find("BlackRock") == std::string::npos);
    BOOST_CHECK(py.find("BRAND_DISPATCH") != std::string::npos);
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::string cmd = "cd " + ShellQuote(fs::PathToString(SdkRoot())) + " && " + ShellQuote(python) +
                            " python/test_body_id.py TestCrl12BodyId.test_no_brand_dispatch "
                            "TestCrl12BodyId.test_no_invented_aum_auc 2>&1";
    BOOST_REQUIRE_EQUAL(Spawn(cmd, out), 0);
}

BOOST_AUTO_TEST_SUITE_END()
