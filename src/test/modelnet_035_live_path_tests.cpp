// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// CMakeLists.txt: modelnet_035_live_path_tests.cpp

#include <modelnet/admission_routes.h>
#include <modelnet/helper.h>
#include <crypto/common.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_live_path_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"live_path\":\"btx035-live-path-" +
                             std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

fs::path WriteTinyModel(const fs::path& dir, unsigned char tag)
{
    fs::create_directories(dir);
    const auto st = TinySafeTensors(tag);
    std::ofstream out(dir / "model.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    return dir;
}

UniValue HostParams(const fs::path& dir, bool publish)
{
    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(dir));
    UniValue opt(UniValue::VOBJ);
    opt.pushKV("pin", true);
    opt.pushKV("publish", publish);
    params.push_back(opt);
    return params;
}

bool CallHost(modelnet::ModelCatalog& cat, const fs::path& dir, bool publish, UniValue& result, std::string& code,
              std::string& err)
{
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "hostmodel");
    rpc.pushKV("params", HostParams(dir, publish));
    return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
}

bool CallExport(modelnet::ModelCatalog& cat, const std::string& model_id, UniValue& result, std::string& code,
                std::string& err)
{
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "exportmodelpath");
    UniValue params(UniValue::VARR);
    params.push_back(model_id);
    rpc.pushKV("params", params);
    return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
}

} // namespace

BOOST_AUTO_TEST_CASE(host_and_export_refuse_quarantine_and_research_only)
{
    const fs::path root = m_path_root / "live-path-host";
    modelnet::ModelCatalog cat{root / "cat", 8 << 20};
    const fs::path src = WriteTinyModel(root / "src", 0x21);

    UniValue hosted;
    std::string code;
    std::string err;
    BOOST_REQUIRE_MESSAGE(CallHost(cat, src, false, hosted, code, err), err);
    BOOST_REQUIRE(hosted.exists("model_id") && hosted["model_id"].isStr());
    const std::string model_id = hosted["model_id"].get_str();
    BOOST_CHECK(code.empty());

    UniValue exported;
    BOOST_REQUIRE_MESSAGE(CallExport(cat, model_id, exported, code, err), err);
    BOOST_CHECK(exported.exists("materialized") && exported["materialized"].get_bool());

    modelnet::Quarantine(model_id);
    UniValue denied_export;
    BOOST_CHECK(!CallExport(cat, model_id, denied_export, code, err));
    BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");

    UniValue denied_host;
    BOOST_CHECK(!CallHost(cat, src, false, denied_host, code, err));
    BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");

    const fs::path research_src = WriteTinyModel(root / "research", 0x22);
    modelnet::ModelCatalog research_cat{root / "research-cat", 8 << 20};
    UniValue research_hosted;
    BOOST_REQUIRE_MESSAGE(CallHost(research_cat, research_src, false, research_hosted, code, err), err);
    BOOST_REQUIRE(research_hosted.exists("model_id") && research_hosted["model_id"].isStr());
    modelnet::StrictAdmissionRecord record;
    record.assurance = modelnet::Assurance::RESEARCH_ONLY;
    record.owner_authorized = true;
    modelnet::RegisterStrictModel(research_hosted["model_id"].get_str(), record);

    UniValue research_again;
    BOOST_CHECK(!CallHost(research_cat, research_src, false, research_again, code, err));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");
}

BOOST_AUTO_TEST_SUITE_END()
