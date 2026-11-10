// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h>
#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/release.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <csignal>
#include <fstream>
#include <string>
#include <vector>

#ifndef WIN32
#include <sys/resource.h>
#endif

using namespace modelnet;

BOOST_FIXTURE_TEST_SUITE(modelnet_release_store_tests, BasicTestingSetup)

#ifndef WIN32
// campaigns.json holds the helper's release funding campaigns (pledged and
// funded atoms, funding outpoints, whether the secret was disclosed). SaveCampaigns
// wrote it in place and reported success without checking the write; every caller
// discards its result. A save that fails only at close (a full disk) then cut the
// previous file short and was silent. RLIMIT_FSIZE stands in for the full disk.
BOOST_AUTO_TEST_CASE(savecampaigns_keeps_the_previous_file_when_a_write_is_cut_short)
{
    const fs::path dir = m_path_root / "release-campaigns-write";
    fs::create_directories(dir);
    std::string err;

    ReleaseCampaign a;
    BOOST_REQUIRE(Digest48::FromHex(std::string(96, 'a'), a.release_id, err));
    a.target_atoms = 111;
    const std::vector<ReleaseCampaign> one{a};
    BOOST_REQUIRE(SaveCampaigns(dir, one, err));
    const auto first_size = fs::file_size(dir / "campaigns.json");
    BOOST_REQUIRE_GT(first_size, 0U);

    // Round trip of the normal path.
    std::vector<ReleaseCampaign> back;
    BOOST_REQUIRE(LoadCampaigns(dir, back, err));
    BOOST_REQUIRE_EQUAL(back.size(), 1U);
    BOOST_CHECK(back[0].release_id == a.release_id);
    BOOST_CHECK_EQUAL(back[0].target_atoms, 111);

    // A larger set that does not fit under a limit set to the one-campaign size.
    ReleaseCampaign b;
    BOOST_REQUIRE(Digest48::FromHex(std::string(96, 'b'), b.release_id, err));
    b.target_atoms = 222;
    const std::vector<ReleaseCampaign> two{a, b};

    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = first_size;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    err.clear();
    const bool saved{SaveCampaigns(dir, two, err)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    BOOST_CHECK_MESSAGE(!saved, "SaveCampaigns reported success although campaigns.json was not written in full");
    BOOST_CHECK(!fs::exists(dir / "campaigns.json.tmp"));

    // The file on disk still holds the first campaign.
    std::vector<ReleaseCampaign> reloaded;
    BOOST_REQUIRE(LoadCampaigns(dir, reloaded, err));
    BOOST_CHECK_MESSAGE(reloaded.size() == 1U && !reloaded.empty() && reloaded[0].release_id == a.release_id,
                        "the previous campaign was lost from campaigns.json");
}

namespace {

void WriteTinySafeTensors(const fs::path& dir, const std::string& header)
{
    fs::create_directories(dir);
    std::vector<unsigned char> st(8 + header.size());
    WriteLE64(st.data(), header.size());
    std::copy(header.begin(), header.end(), st.begin() + 8);
    std::ofstream out(dir / "toy.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
}

bool CallHelper(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result, std::string& code)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    result = UniValue{};
    code.clear();
    std::string err;
    return DispatchHelperRpc(cat, req, result, code, err);
}

UniValue OneParam(const UniValue& v)
{
    UniValue params(UniValue::VARR);
    params.push_back(v);
    return params;
}

UniValue CreateParams(const std::string& uri, char secret)
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("uri", uri);
    body.pushKV("secret32_hex", std::string(64, secret));
    body.pushKV("refund_height", 100000);
    body.pushKV("target_atoms", 5'000'000);
    return OneParam(body);
}

} // namespace

// The helper RPCs that change a campaign used to change it in memory, ignore
// the result of SaveCampaigns and report success, so a change that was never
// written was shown until the next restart and then gone. Each now saves first
// and refuses the call when the save fails, leaving memory and the file as they were.
BOOST_AUTO_TEST_CASE(campaign_rpcs_refuse_a_change_they_cannot_save)
{
    const fs::path root = m_path_root / "release-campaigns-rpc";
    WriteTinySafeTensors(root / "a.dir", "{}");
    WriteTinySafeTensors(root / "b.dir", "{\"__metadata__\":{\"name\":\"b\"}}");
    ModelCatalog cat{root, 8 << 20};
    const fs::path helper_dir = cat.Store().Root().parent_path();

    UniValue res;
    std::string code;
    BOOST_REQUIRE(CallHelper(cat, "hostmodel", OneParam(fs::PathToString(root / "a.dir")), res, code));
    const std::string uri_a = res["uri"].get_str();
    BOOST_REQUIRE(CallHelper(cat, "hostmodel", OneParam(fs::PathToString(root / "b.dir")), res, code));
    const std::string uri_b = res["uri"].get_str();
    BOOST_REQUIRE(uri_a != uri_b);
    BOOST_REQUIRE_MESSAGE(CallHelper(cat, "createmodelrelease", CreateParams(uri_a, 'a'), res, code), code);
    const std::string rid = res["release_id"].get_str();

    BOOST_REQUIRE(CallHelper(cat, "getmodelrelease", UniValue(UniValue::VARR), res, code));
    const std::string listed_before = res["campaigns"].write();
    BOOST_REQUIRE_EQUAL(res["campaigns"].size(), 1U);
    const auto file_size = fs::file_size(helper_dir / "campaigns.json");

    UniValue pledge(UniValue::VARR);
    pledge.push_back(rid);
    pledge.push_back(1'234'567);
    UniValue script(UniValue::VOBJ);
    script.pushKV("release_id", rid);
    script.pushKV("output_script", std::string(68, '5'));
    UniValue outpoint(UniValue::VOBJ);
    outpoint.pushKV("release_id", rid);
    outpoint.pushKV("txid", std::string(64, 'c'));
    outpoint.pushKV("vout", 3);
    outpoint.pushKV("output_script", "51");
    outpoint.pushKV("amount_atoms", 2'000'000);

    // Every change below makes campaigns.json larger than it is now.
    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = file_size;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    const bool pledged{CallHelper(cat, "pledgemodelrelease", pledge, res, code)};
    const std::string pledge_code{code};
    const bool script_set{CallHelper(cat, "setreleaseoutputscript", OneParam(script), res, code)};
    const std::string script_code{code};
    const bool outpoint_recorded{CallHelper(cat, "recordmodelfundingoutpoint", OneParam(outpoint), res, code)};
    const std::string outpoint_code{code};
    const bool created{CallHelper(cat, "createmodelrelease", CreateParams(uri_b, 'b'), res, code)};
    const std::string create_code{code};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);

    BOOST_CHECK_MESSAGE(!pledged && pledge_code == "INTERNAL", "pledgemodelrelease reported success without saving");
    BOOST_CHECK_MESSAGE(!script_set && script_code == "INTERNAL", "setreleaseoutputscript reported success without saving");
    BOOST_CHECK_MESSAGE(!outpoint_recorded && outpoint_code == "INTERNAL", "recordmodelfundingoutpoint reported success without saving");
    BOOST_CHECK_MESSAGE(!created && create_code == "INTERNAL", "createmodelrelease reported success without saving");

    // Memory shows what the file holds: none of the four changes.
    BOOST_REQUIRE(CallHelper(cat, "getmodelrelease", UniValue(UniValue::VARR), res, code));
    BOOST_CHECK_EQUAL(res["campaigns"].write(), listed_before);
    std::string err;
    std::vector<ReleaseCampaign> on_disk;
    BOOST_REQUIRE(LoadCampaigns(helper_dir, on_disk, err));
    BOOST_REQUIRE_EQUAL(on_disk.size(), 1U);
    BOOST_CHECK_EQUAL(on_disk[0].pledged_atoms, 0);
    BOOST_CHECK(!fs::exists(helper_dir / "campaigns.json.tmp"));

    // With room again the same pledge is saved and survives a reload.
    BOOST_REQUIRE_MESSAGE(CallHelper(cat, "pledgemodelrelease", pledge, res, code), code);
    BOOST_CHECK_EQUAL(res["pledged_atoms"].getInt<int64_t>(), 1'234'567);
    on_disk.clear();
    BOOST_REQUIRE(LoadCampaigns(helper_dir, on_disk, err));
    BOOST_REQUIRE_EQUAL(on_disk.size(), 1U);
    BOOST_CHECK_EQUAL(on_disk[0].pledged_atoms, 1'234'567);
}
#endif // WIN32

BOOST_AUTO_TEST_SUITE_END()
