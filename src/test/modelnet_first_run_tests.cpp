// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <test/modelnet_n02_idem.h>
#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/event_journal.h>
#include <modelnet/helper.h>
#include <modelnet/profile.h>
#include <modelnet/file_stream.h>
#include <modelnet/protocol.h>
#include <modelnet/search.h>
#include <modelnet/subscription_mandate.h>
#include <rpc/protocol.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_first_run_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

UniValue Rpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR))
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", WithN02Idempotency(method, params));
    return req;
}

UniValue Dispatch(modelnet::ModelCatalog& cat, const UniValue& req)
{
    UniValue result;
    std::string code, err;
    const bool ok = modelnet::DispatchHelperRpc(cat, req, result, code, err);
    BOOST_REQUIRE_MESSAGE(ok, req.write() + " :: " + err + " [" + code + "] result=" + result.write());
    return result;
}

} // namespace

BOOST_AUTO_TEST_CASE(import_auto_publishes_signed_search_card)
{
    const fs::path tmp = m_path_root / "first-run-import";
    fs::create_directories(tmp / "Qwen3-8B-IQ4_XS");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "Qwen3-8B-IQ4_XS" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(tmp / "Qwen3-8B-IQ4_XS"));
    const UniValue imported = Dispatch(cat, Rpc("importmodel", params));
    BOOST_CHECK(imported["signed_metadata"].get_bool());
    BOOST_CHECK(imported["search_published"].get_bool());
    BOOST_CHECK_EQUAL(imported["format"].get_str(), "safetensors");
    BOOST_CHECK_EQUAL(imported["family"].get_str(), "qwen3");
    BOOST_CHECK_EQUAL(imported["quantization"].get_str(), "IQ4_XS");

    UniValue ids = Dispatch(cat, Rpc("listmodelidentities"));
    BOOST_REQUIRE(ids["identities"].isArray());
    BOOST_REQUIRE_GE(ids["identities"].size(), 1U);

    UniValue q(UniValue::VOBJ);
    q.pushKV("text", "qwen3");
    q.pushKV("scope", "LOCAL");
    UniValue sp(UniValue::VARR);
    sp.push_back(q);
    const UniValue hits = Dispatch(cat, Rpc("searchmodels", sp));
    BOOST_REQUIRE(hits["results"].isArray());
    BOOST_REQUIRE_GE(hits["results"].size(), 1U);
    bool found = false;
    for (const auto& h : hits["results"].getValues()) {
        if (h["model_id"].get_str() != imported["model_id"].get_str()) continue;
        found = true;
        BOOST_CHECK_EQUAL(h["format"].get_str(), "safetensors");
        BOOST_CHECK_EQUAL(h["family"].get_str(), "qwen3");
        BOOST_CHECK_EQUAL(h["quantization"].get_str(), "IQ4_XS");
        BOOST_CHECK(h["search"]["metadata_verified"].get_bool());
        BOOST_CHECK(!h["description"].get_str().empty());
        BOOST_REQUIRE(h.exists("share"));
        BOOST_CHECK(h["share"]["copy_text"].get_str().find("btx://") == 0);
        BOOST_CHECK_EQUAL(h["share"]["format"].get_str(), "safetensors");
    }
    BOOST_REQUIRE(found);
}

BOOST_AUTO_TEST_CASE(catalog_ingest_does_not_wipe_authored_metadata)
{
    using namespace modelnet;
    ModelSearchRecord authored;
    authored.model_id.data[0] = 0x42;
    authored.canonical_name = "Qwen3.8-27B-Uncensored-Cyber-IQ4_XS";
    authored.display_name = "Qwen3.8 27B Uncensored Cyber (IQ4_XS GGUF)";
    authored.family = "qwen3";
    authored.format = "gguf";
    authored.quantization = "IQ4_XS";
    authored.tags = {"qwen3", "gguf"};
    authored.short_description = "Apache-2.0 GGUF imported locally.";
    BOOST_CHECK(SearchRecordHasAuthoredMetadata(authored));

    ModelSearchRecord stub;
    authored.signed_ok = false;
    BOOST_CHECK(SearchRecordHasAuthoredMetadata(authored));
    BOOST_CHECK(!SearchRecordHasAuthoredMetadata(stub));
}

BOOST_AUTO_TEST_CASE(publish_without_prior_identity_signs)
{
    const fs::path tmp = m_path_root / "first-run-publish";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    UniValue meta(UniValue::VOBJ);
    meta.pushKV("display_name", "Creator Lab Model");
    meta.pushKV("canonical_name", "Creator Lab Model");
    meta.pushKV("family", "qwen3");
    meta.pushKV("format", "gguf");
    meta.pushKV("short_description", "unix RPC publish path used by the GUI Publish tab");
    UniValue params(UniValue::VARR);
    params.push_back(std::string(96, 'a'));
    params.push_back(meta);
    const UniValue result = Dispatch(cat, Rpc("publishmodelsearchrecord", params));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result["wallet_key"].get_bool());
    BOOST_CHECK(result["signed_metadata"].get_bool());

    UniValue q(UniValue::VOBJ);
    q.pushKV("text", "Creator Lab");
    q.pushKV("scope", "LOCAL");
    UniValue sp(UniValue::VARR);
    sp.push_back(q);
    const UniValue hits = Dispatch(cat, Rpc("searchmodels", sp));
    BOOST_REQUIRE(hits["results"].isArray());
    BOOST_REQUIRE_GE(hits["results"].size(), 1U);
    BOOST_CHECK_EQUAL(hits["results"][0]["family"].get_str(), "qwen3");
    BOOST_CHECK_EQUAL(hits["results"][0]["format"].get_str(), "gguf");
}

BOOST_AUTO_TEST_CASE(doctor_host_preview_share_transfers_alias)
{
    const fs::path tmp = m_path_root / "first-run-doctor";
    fs::create_directories(tmp / "glm-fp8");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "glm-fp8" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(tmp / "glm-fp8" / "README.md");
        card << "glm-fp8 unique sidecar for search-index isolation\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    const UniValue doctor = Dispatch(cat, Rpc("checkmodelsetup"));
    BOOST_CHECK(doctor["identity_ready"].get_bool());
    BOOST_CHECK(doctor["ready_to_host"].get_bool());
    BOOST_CHECK_EQUAL(doctor["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(doctor["next_actions"].isArray());
    BOOST_REQUIRE_GE(doctor["next_actions"].size(), 1U);
    BOOST_CHECK(doctor.exists("quota") || doctor.exists("quota_bytes"));
    BOOST_CHECK(doctor.exists("pq1") || doctor.exists("pq1_ready"));
    BOOST_CHECK(doctor.exists("remaining_bytes"));
    BOOST_CHECK(doctor.exists("one_liner"));
    BOOST_CHECK(!doctor["one_liner"].get_str().empty());
    BOOST_CHECK(doctor.exists("profile"));
    BOOST_CHECK(doctor.exists("cloud_layout_sentence"));
    BOOST_CHECK(doctor.exists("r2_auto_sentence"));
    BOOST_CHECK(doctor["cloud_layout_sentence"].get_str().find("SOURCE_FILES") != std::string::npos);
    BOOST_CHECK(doctor["r2_auto_sentence"].get_str().find("R2 AUTO") != std::string::npos);
    const UniValue watchst = Dispatch(cat, Rpc("getmodelwatchstatus"));
    BOOST_CHECK(watchst.exists("watch_dir"));
    BOOST_CHECK_EQUAL(watchst["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue prevp(UniValue::VARR);
    prevp.push_back(fs::PathToString(tmp / "glm-fp8"));
    const UniValue preview = Dispatch(cat, Rpc("previewmodelimport", prevp));
    BOOST_CHECK(preview["would_fit"].get_bool());
    BOOST_CHECK_EQUAL(preview["family"].get_str(), "glm");
    BOOST_CHECK_EQUAL(preview["format"].get_str(), "safetensors");
    BOOST_CHECK(preview.exists("hashes") && !preview["hashes"].get_bool());
    BOOST_CHECK(preview.exists("remaining_bytes"));
    BOOST_CHECK(preview.exists("one_liner"));
    BOOST_CHECK(!preview.exists("uri") || preview["uri"].isStr());

    UniValue hostp(UniValue::VARR);
    hostp.push_back(fs::PathToString(tmp / "glm-fp8"));
    const UniValue hosted = Dispatch(cat, Rpc("hostmodel", hostp));
    BOOST_CHECK(hosted["search_published"].get_bool());
    BOOST_CHECK(hosted["signed_metadata"].get_bool());
    BOOST_REQUIRE(hosted.exists("share"));
    BOOST_CHECK(hosted["share"]["copy_text"].get_str().find(hosted["uri"].get_str()) == 0);

    UniValue sharep(UniValue::VARR);
    sharep.push_back(hosted["uri"].get_str());
    const UniValue card = Dispatch(cat, Rpc("getmodelsharecard", sharep));
    BOOST_CHECK_EQUAL(card["share"]["uri"].get_str(), hosted["uri"].get_str());

    const UniValue xfer = Dispatch(cat, Rpc("getmodeltransfers"));
    BOOST_REQUIRE(xfer["transfers"].isArray());
    BOOST_REQUIRE_GE(xfer["transfers"].size(), 1U);
    BOOST_CHECK(xfer["transfers"][0].exists("state"));
    BOOST_CHECK(xfer["transfers"][0].exists("share"));

    const UniValue listed = Dispatch(cat, Rpc("listmodels"));
    BOOST_REQUIRE(listed["models"].isArray());
    BOOST_REQUIRE_GE(listed["models"].size(), 1U);
    BOOST_CHECK(listed["models"][0].exists("state"));
    BOOST_CHECK(listed["models"][0].exists("share"));
    BOOST_CHECK(listed["models"][0].exists("name"));
    BOOST_CHECK(listed["models"][0].exists("aliases"));
    BOOST_CHECK(listed["models"][0].exists("imported_at"));
    BOOST_CHECK(listed["models"][0].exists("percent"));
    BOOST_CHECK(listed["models"][0].exists("served"));
    BOOST_CHECK(listed["models"][0].exists("received"));
    BOOST_CHECK(listed["models"][0]["ratio"].isNull());
    BOOST_CHECK(listed["models"][0]["share"].exists("file_count"));

    UniValue pinfilt(UniValue::VOBJ);
    pinfilt.pushKV("pinned", true);
    UniValue pinp(UniValue::VARR);
    pinp.push_back(pinfilt);
    const UniValue pins = Dispatch(cat, Rpc("listmodels", pinp));
    BOOST_REQUIRE_GE(pins["models"].size(), 1U);

    UniValue unpinfilt(UniValue::VOBJ);
    unpinfilt.pushKV("pinned", false);
    UniValue unpinp(UniValue::VARR);
    unpinp.push_back(unpinfilt);
    const UniValue unpins = Dispatch(cat, Rpc("listmodels", unpinp));
    BOOST_CHECK_EQUAL(unpins["models"].size(), 0U);

    UniValue aliasp(UniValue::VARR);
    aliasp.push_back(hosted["uri"].get_str());
    aliasp.push_back("glm:fp8");
    const UniValue aliased = Dispatch(cat, Rpc("setmodelalias", aliasp));
    BOOST_CHECK(aliased["signed_metadata"].get_bool());
    const UniValue aliases = Dispatch(cat, Rpc("getmodelaliases"));
    bool saw = false;
    for (const auto& a : aliases["aliases"].getValues()) {
        if (a["alias"].get_str() == "glm:fp8") saw = true;
    }
    BOOST_CHECK(saw);
}

BOOST_AUTO_TEST_CASE(show_export_open_unhost_empty_search)
{
    const fs::path tmp = m_path_root / "first-run-show";
    fs::create_directories(tmp / "qwen-show");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "qwen-show" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(tmp / "qwen-show" / "README.md");
        card << "r2-show-export unique sidecar for search-index isolation\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue hostp(UniValue::VARR);
    hostp.push_back(fs::PathToString(tmp / "qwen-show"));
    const UniValue hosted = Dispatch(cat, Rpc("hostmodel", hostp));
    BOOST_REQUIRE(hosted.exists("uri"));
    UniValue aliasp(UniValue::VARR);
    aliasp.push_back(hosted["uri"].get_str());
    aliasp.push_back("qwen3-local");
    BOOST_CHECK(Dispatch(cat, Rpc("setmodelalias", aliasp))["signed_metadata"].get_bool());

    UniValue showp(UniValue::VARR);
    showp.push_back("qwen3-local");
    const UniValue shown = Dispatch(cat, Rpc("showmodel", showp));
    BOOST_CHECK_EQUAL(shown["uri"].get_str(), hosted["uri"].get_str());
    BOOST_CHECK(shown["local"].get_bool());
    BOOST_REQUIRE(shown.exists("share"));
    BOOST_CHECK_EQUAL(shown["share"]["uri"].get_str(), hosted["uri"].get_str());
    BOOST_CHECK_EQUAL(shown["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(shown.exists("details"));
    BOOST_CHECK_EQUAL(shown["details"]["format"].get_str(), shown["format"].get_str());
    BOOST_CHECK(shown.exists("files"));
    BOOST_REQUIRE(shown["files"].isArray());
    BOOST_REQUIRE_GE(shown["files"].size(), 1U);

    UniValue copyp(UniValue::VARR);
    copyp.push_back(shown["share"]["copy_text"].get_str());
    const UniValue opened = Dispatch(cat, Rpc("openmodelshare", copyp));
    BOOST_CHECK_EQUAL(opened["kind"].get_str(), "MODEL");
    BOOST_CHECK_EQUAL(opened["automatic_spend_atoms"].getInt<int>(), 0);

    const fs::path link = tmp / "qwen3-local.btx";
    UniValue linkp(UniValue::VARR);
    linkp.push_back("qwen3-local");
    linkp.push_back(fs::PathToString(link));
    const UniValue exported = Dispatch(cat, Rpc("exportmodellink", linkp));
    BOOST_CHECK(exported["written"].get_bool());
    BOOST_CHECK(fs::exists(link));

    UniValue openfile(UniValue::VARR);
    openfile.push_back(fs::PathToString(link));
    const UniValue fromfile = Dispatch(cat, Rpc("openmodelshare", openfile));
    BOOST_CHECK_EQUAL(fromfile["uri"].get_str(), hosted["uri"].get_str());

    UniValue hostcard(UniValue::VARR);
    hostcard.push_back(fs::PathToString(link));
    const UniValue ascard = Dispatch(cat, Rpc("hostmodel", hostcard));
    BOOST_CHECK(!ascard["imported"].get_bool());
    BOOST_CHECK_EQUAL(ascard["reason"].get_str(), "share_card");
    BOOST_REQUIRE(ascard.exists("share"));
    BOOST_CHECK_EQUAL(ascard["automatic_spend_atoms"].getInt<int>(), 0);

    const UniValue empty_search = Dispatch(cat, Rpc("searchmodels"));
    BOOST_REQUIRE(empty_search["results"].isArray());
    BOOST_REQUIRE_GE(empty_search["results"].size(), 1U);
    BOOST_CHECK(empty_search["results"][0].exists("share"));
    BOOST_CHECK(empty_search["results"][0].exists("next_actions"));
    BOOST_CHECK_EQUAL(empty_search["automatic_spend_atoms"].getInt<int>(), 0);

    const fs::path watch = tmp / "inbox";
    fs::create_directories(watch);
    BOOST_REQUIRE(fs::copy_file(link, watch / "qwen3-local.btx", fs::copy_options::none));
    UniValue scanp(UniValue::VARR);
    scanp.push_back(fs::PathToString(watch));
    const UniValue scanned = Dispatch(cat, Rpc("scanmodelwatch", scanp));
    BOOST_CHECK_EQUAL(scanned["imported_count"].getInt<int>(), 0);
    BOOST_REQUIRE_GE(scanned["opened_count"].getInt<int>(), 1);

    UniValue rmp(UniValue::VARR);
    rmp.push_back("qwen3-local");
    rmp.push_back("qwen3-local");
    const UniValue removed = Dispatch(cat, Rpc("removemodelalias", rmp));
    BOOST_CHECK_EQUAL(removed["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue unhostp(UniValue::VARR);
    unhostp.push_back(hosted["uri"].get_str());
    const UniValue unhosted = Dispatch(cat, Rpc("unhostmodel", unhostp));
    BOOST_CHECK(!unhosted["pinned"].get_bool());
    BOOST_CHECK(!unhosted["seeded"].get_bool());
    BOOST_CHECK_EQUAL(unhosted["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(watch_dir_hosts_new_safetensors_once)
{
    const fs::path tmp = m_path_root / "first-run-watch";
    const fs::path watch = tmp / "inbox";
    fs::create_directories(watch / "qwen-watch");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(watch / "qwen-watch" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(watch / "qwen-watch" / "README.md");
        card << "watch-folder unique sidecar\n";
        std::ofstream tmpf(watch / "downloading.safetensors.part", std::ios::binary);
        tmpf << "not a real model\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    (void)Dispatch(cat, Rpc("checkmodelsetup"));

    UniValue scanp(UniValue::VARR);
    scanp.push_back(fs::PathToString(watch));
    const UniValue first = Dispatch(cat, Rpc("scanmodelwatch", scanp));
    BOOST_REQUIRE_GE(first["imported_count"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(first["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(first["imported"].isArray());
    BOOST_CHECK(first["imported"][0]["search_published"].get_bool());
    BOOST_CHECK(first.exists("last_scan_ms"));
    bool skipped_temp = false;
    if (first.exists("skipped") && first["skipped"].isArray()) {
        for (const auto& s : first["skipped"].getValues()) {
            if (s.isObject() && s.exists("reason") && s["reason"].get_str() == "temp suffix") skipped_temp = true;
        }
    }
    BOOST_CHECK(skipped_temp);

    const UniValue second = Dispatch(cat, Rpc("scanmodelwatch", scanp));
    BOOST_CHECK_EQUAL(second["imported_count"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(title_only_bounty_draft_is_incomplete)
{
    const fs::path tmp = m_path_root / "first-run-bounty";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("title", "Japanese coding model");
    UniValue params(UniValue::VARR);
    params.push_back(terms);
    const UniValue draft = Dispatch(cat, Rpc("createbountydraft", params));
    BOOST_CHECK(draft["local_only"].get_bool());
    BOOST_CHECK(!draft["recipe_complete"].get_bool());
    BOOST_CHECK_EQUAL(draft["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(draft["missing_fields"].isArray());
    BOOST_REQUIRE_GE(draft["missing_fields"].size(), 1U);
    BOOST_CHECK(draft.exists("one_liner"));
    BOOST_CHECK(!draft["one_liner"].get_str().empty());
    BOOST_CHECK_EQUAL(draft["one_liner"].get_str(), "fill missing field: description");
    BOOST_CHECK(draft.exists("copy_text"));
    BOOST_CHECK_EQUAL(draft["copy_text"].get_str(), "draft_id=" + draft["draft_id"].get_str());
    BOOST_REQUIRE(draft.exists("checklist"));
    BOOST_CHECK(!draft["checklist"]["description"]["ok"].get_bool());
    BOOST_CHECK(draft["checklist"]["overview"]["ok"].get_bool());
    BOOST_REQUIRE_GE(draft["user_missing_count"].getInt<int>(), 1);
    BOOST_CHECK(draft.exists("terms_id_preview"));
    const UniValue listed = Dispatch(cat, Rpc("listbountydrafts"));
    BOOST_REQUIRE_GE(listed["count"].getInt<int>(), 1);
    BOOST_CHECK(listed.exists("one_liner"));
    BOOST_CHECK(listed.exists("next_actions"));

    UniValue valp(UniValue::VARR);
    valp.push_back(terms);
    const UniValue validated = Dispatch(cat, Rpc("validatebountyterms", valp));
    BOOST_CHECK(!validated["ok"].get_bool());
    BOOST_CHECK_EQUAL(validated["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(validated.exists("checklist"));
    BOOST_CHECK(!validated["recipe_complete"].get_bool());

    UniValue patch(UniValue::VOBJ);
    patch.pushKV("summary", "local Gitcoin-style save-in-place");
    UniValue up(UniValue::VARR);
    up.push_back(draft["draft_id"].get_str());
    up.push_back(patch);
    const UniValue updated = Dispatch(cat, Rpc("updatebountydraft", up));
    BOOST_CHECK_EQUAL(updated["draft_id"].get_str(), draft["draft_id"].get_str());
    BOOST_CHECK(!updated["recipe_complete"].get_bool());
    BOOST_CHECK_EQUAL(updated["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(updated["unknown_fields"].isArray());
    bool saw_summary = false;
    for (const auto& f : updated["unknown_fields"].getValues()) {
        if (f.isStr() && f.get_str() == "summary") saw_summary = true;
    }
    BOOST_CHECK(saw_summary);

    UniValue delp(UniValue::VARR);
    delp.push_back(draft["draft_id"].get_str());
    const UniValue deleted = Dispatch(cat, Rpc("deletebountydraft", delp));
    BOOST_CHECK(deleted["deleted"].get_bool());
    BOOST_CHECK_EQUAL(deleted["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(deleted.exists("one_liner"));
    BOOST_CHECK(deleted.exists("next_actions"));
}

BOOST_AUTO_TEST_CASE(mirror_policy_and_native_file_stream_hello)
{
    const fs::path tmp = m_path_root / "first-run-mirror";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const UniValue empty = Dispatch(cat, Rpc("getmodelmirror"));
    BOOST_CHECK_EQUAL(empty["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(empty["mirror_privilege"].get_bool(), false);
    BOOST_CHECK(empty["selectors"].isArray());

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("publisher_id", "pub-mirror");
    payload.pushKV("keep_latest", 3);
    payload.pushKV("automatic_spend_atoms", 0);
    UniValue p(UniValue::VARR);
    p.push_back(payload);
    const UniValue set = Dispatch(cat, Rpc("setmodelmirror", p));
    BOOST_CHECK(set["applied"].get_bool());
    BOOST_CHECK_EQUAL(set["publisher_id"].get_str(), "pub-mirror");
    BOOST_CHECK_EQUAL(set["keep_latest"].getInt<int>(), 3);
    BOOST_CHECK_EQUAL(set["automatic_spend_atoms"].getInt<int>(), 0);
    const UniValue got = Dispatch(cat, Rpc("getmodelmirror"));
    BOOST_REQUIRE(got["selectors"].isArray());
    BOOST_REQUIRE_GE(got["selectors"].size(), 1U);
    BOOST_CHECK_EQUAL(got["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(got["selectors"][0]["keep_latest"].getInt<int>(), 3);
    BOOST_CHECK_EQUAL(got["selectors"][0]["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue spend(UniValue::VOBJ);
    spend.pushKV("automatic_spend_atoms", 1);
    spend.pushKV("idempotency_key", "first-run-mirror-spend-reject");
    UniValue badp(UniValue::VARR);
    badp.push_back(spend);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "setmodelmirror");
    req.pushKV("params", badp);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(err.find("automatic_spend_atoms") != std::string::npos);

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = std::string(modelnet::MODEL_HTTP_ROOT) + "hello";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    UniValue hello;
    BOOST_REQUIRE(hello.read(nresp.body));
    BOOST_CHECK(hello["full_file_stream_v1"].get_bool());
    BOOST_CHECK_EQUAL(hello["capability"].get_str(), std::string(modelnet::FULL_FILE_STREAM_V1));
    BOOST_CHECK(hello["delivery"]["sequential_file_stream"].get_bool());

    nreq.method = "GET";
    nreq.path = std::string(modelnet::MODEL_HTTP_ROOT) + "files/" + std::string(96, 'a') + "/0";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK(nresp.status == 400 || nresp.status == 404);
}

BOOST_AUTO_TEST_CASE(prepare_funding_watch_drain_unsigned)
{
    const fs::path tmp = m_path_root / "first-run-prep";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue wp(UniValue::VOBJ);
    wp.pushKV("publisher_id", "pub-fund");
    wp.pushKV("action", "PREPARE_FUNDING");
    UniValue p(UniValue::VARR);
    p.push_back(wp);
    const UniValue w = Dispatch(cat, Rpc("watchmodelpublisher", p));
    BOOST_CHECK(w.exists("watch_id"));
    BOOST_CHECK_EQUAL(w["action"].get_str(), "PREPARE_FUNDING");

    modelnet::ModelEvent e;
    e.event_type = modelnet::ModelEventType::MODEL_PUBLISHED;
    e.object_id = "m-fund";
    e.model_id = "m-fund";
    e.publisher_id = "pub-fund";
    e.verification_state = "SIGNED_OK";
    e.source = "SEARCH";
    e.record_sequence = 1;
    modelnet::ObserveResult o;
    std::string err;
    BOOST_REQUIRE(modelnet::JournalObserve(e, o, err));

    const UniValue acts = Dispatch(cat, Rpc("getmodelwatchactions"));
    BOOST_REQUIRE(acts["actions"].isArray());
    bool saw = false;
    for (const auto& a : acts["actions"].getValues()) {
        if (!a.exists("action") || a["action"].get_str() != "PREPARE_FUNDING") continue;
        saw = true;
        BOOST_CHECK(a["unsigned"].get_bool());
        BOOST_CHECK(!a["wallet_signed"].get_bool());
        BOOST_CHECK(!a["wallet"].get_bool());
        BOOST_REQUIRE(a.exists("prepare_funding") && a["prepare_funding"].isObject());
        BOOST_CHECK(a["prepare_funding"]["unsigned"].get_bool());
        BOOST_CHECK(!a["prepare_funding"]["wallet_signed"].get_bool());
        BOOST_CHECK_EQUAL(a["automatic_spend_atoms"].getInt<int>(), 0);
        BOOST_CHECK(!a["spends"].get_bool());
    }
    BOOST_CHECK(saw);
}

BOOST_AUTO_TEST_CASE(fund_with_mandate_watch_drain_unsigned)
{
    const fs::path tmp = m_path_root / "first-run-fund";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    modelnet::GlobalSubscriptionStore().Reset();

    UniValue badp(UniValue::VOBJ);
    badp.pushKV("publisher_id", std::string(96, 'b'));
    badp.pushKV("action", "FUND_WITH_MANDATE");
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("watchmodelpublisher", [&] {
        UniValue a(UniValue::VARR);
        a.push_back(badp);
        return a;
    }()), result, code, err));
    BOOST_CHECK(err.find("mandate_id") != std::string::npos);

    UniValue mj(UniValue::VOBJ);
    mj.pushKV("mandate_version", 1);
    mj.pushKV("owner_identity", std::string(96, 'a'));
    mj.pushKV("network_id", std::string(64, '0'));
    mj.pushKV("publisher_id", std::string(96, 'b'));
    UniValue kinds(UniValue::VARR);
    kinds.push_back("MODEL");
    kinds.push_back("RELEASE");
    mj.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    mj.pushKV("allowed_actions", acts);
    mj.pushKV("per_action_principal_limit_atoms", "50");
    mj.pushKV("total_principal_limit_atoms", "100");
    mj.pushKV("total_fee_limit_atoms", "20");
    mj.pushKV("outstanding_exposure_limit_atoms", "200");
    mj.pushKV("max_actions", 16);
    mj.pushKV("max_concurrent_reservations", 8);
    mj.pushKV("expires_at_ms", "4000000000000");
    mj.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    mj.pushKV("minimum_confirmations", 1);
    mj.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    mj.pushKV("revocation_counter", "0");
    const UniValue created = Dispatch(cat, Rpc("createsubscriptionmandate", [&] {
        UniValue a(UniValue::VARR);
        a.push_back(mj);
        return a;
    }()));
    BOOST_REQUIRE(created.exists("mandate_id"));
    const std::string mid = created["mandate_id"].get_str();

    UniValue wp(UniValue::VOBJ);
    wp.pushKV("publisher_id", std::string(96, 'b'));
    wp.pushKV("action", "FUND_WITH_MANDATE");
    wp.pushKV("mandate_id", mid);
    UniValue p(UniValue::VARR);
    p.push_back(wp);
    const UniValue w = Dispatch(cat, Rpc("watchmodelpublisher", p));
    BOOST_CHECK_EQUAL(w["action"].get_str(), "FUND_WITH_MANDATE");
    BOOST_CHECK_EQUAL(w["mandate_id"].get_str(), mid);

    modelnet::ModelEvent e;
    e.event_type = modelnet::ModelEventType::MODEL_PUBLISHED;
    e.object_id = "m-fund-2";
    e.model_id = "m-fund-2";
    e.publisher_id = std::string(96, 'b');
    e.verification_state = "SIGNED_OK";
    e.source = "SEARCH";
    e.record_sequence = 1;
    modelnet::ObserveResult o;
    BOOST_REQUIRE(modelnet::JournalObserve(e, o, err));

    const UniValue acts_out = Dispatch(cat, Rpc("getmodelwatchactions"));
    BOOST_REQUIRE(acts_out["actions"].isArray());
    bool saw = false;
    for (const auto& a : acts_out["actions"].getValues()) {
        if (!a.exists("action") || a["action"].get_str() != "FUND_WITH_MANDATE") continue;
        saw = true;
        BOOST_CHECK(a["unsigned"].get_bool());
        BOOST_CHECK(!a["wallet_signed"].get_bool());
        BOOST_CHECK(!a["wallet"].get_bool());
        BOOST_CHECK(!a["spends"].get_bool());
        BOOST_REQUIRE(a.exists("prepare_funding") && a["prepare_funding"].isObject());
        BOOST_CHECK(a["prepare_funding"]["unsigned"].get_bool());
        BOOST_CHECK(!a["prepare_funding"]["wallet_signed"].get_bool());
        BOOST_CHECK_EQUAL(a["automatic_spend_atoms"].getInt<int>(), 0);
        BOOST_CHECK(!a["evaluate_ok"].get_bool());
        BOOST_CHECK(a.exists("evaluate_error"));
    }
    BOOST_CHECK(saw);
}

BOOST_AUTO_TEST_CASE(retrieve_jobs_persist_reload_without_worker)
{
    const fs::path tmp = m_path_root / "first-run-retrieve-persist";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const std::string mid(96, 'c');
    UniValue job(UniValue::VOBJ);
    job.pushKV("job_id", "persist-job-aa11");
    job.pushKV("model_id", mid);
    job.pushKV("status", "queued");
    job.pushKV("created_ms", 42);
    job.pushKV("bytes_committed", 0);
    UniValue jobs(UniValue::VARR);
    jobs.push_back(job);
    UniValue root(UniValue::VOBJ);
    root.pushKV("schema_version", 1);
    root.pushKV("jobs", jobs);
    {
        std::ofstream out(tmp / "retrieve_jobs.json");
        out << root.write() << "\n";
    }
    UniValue p(UniValue::VARR);
    p.push_back("persist-job-aa11");
    const UniValue listed = Dispatch(cat, Rpc("getmodeljob", p));
    BOOST_REQUIRE(listed["jobs"].isArray());
    BOOST_REQUIRE_EQUAL(listed["jobs"].size(), 1);
    BOOST_CHECK_EQUAL(listed["jobs"][0]["job_id"].get_str(), "persist-job-aa11");
    BOOST_CHECK_EQUAL(listed["jobs"][0]["status"].get_str(), "queued");
    BOOST_CHECK_EQUAL(listed["jobs"][0]["model_id"].get_str(), mid);
}

BOOST_AUTO_TEST_CASE(unix_rpc_timeout_is_short_except_long_methods)
{
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("getmodelnetworkinfo"), 120 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("getcloudstorageinfo"), 120 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("importmodel"), 24 * 60 * 60 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("hostmodel"), 24 * 60 * 60 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("getmodel"), 24 * 60 * 60 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("waitformodelevent"), 24 * 60 * 60 * 1000);
    BOOST_CHECK_EQUAL(modelnet::UnixRpcReplyTimeoutMs("scanmodelwatch"), 24 * 60 * 60 * 1000);
}

BOOST_AUTO_TEST_CASE(unknown_helper_rpc_fails_immediately_method_not_found)
{
    const fs::path tmp = m_path_root / "first-run-unknown-rpc";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue result;
    std::string code, err;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = modelnet::DispatchHelperRpc(cat, Rpc("not_a_helper_rpc"), result, code, err);
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
    BOOST_CHECK(err.find("unknown model RPC") != std::string::npos);
    BOOST_CHECK_LT(elapsed_ms, 2000);
    // Error path: callers must not require automatic_spend_atoms.
    if (result.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    }
}

BOOST_AUTO_TEST_CASE(helper_stop_method_exists_without_daemon)
{
    const fs::path tmp = m_path_root / "first-run-stop-rpc";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    std::atomic<bool> stop_flag{false};
    UniValue result;
    std::string code, err;
    const auto t0 = std::chrono::steady_clock::now();
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("stop"), result, code, err, &stop_flag));
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK_LT(elapsed_ms, 2000);
    BOOST_CHECK(result["stopping"].get_bool());
    BOOST_CHECK(stop_flag.load());
    // Live helper-death log dump is NOT_RUN: spawning btx-modeld is out of
    // scope for this unit (no process, no stderr dump).
}

BOOST_AUTO_TEST_CASE(native_file_stream_headers_omit_body_for_large_files)
{
    modelnet::NativeResponse r;
    r.status = 200;
    r.content_type = "application/octet-stream";
    r.stream_verified_file = true;
    r.stream_file_size = 400ull * 1024ull * 1024ull * 1024ull;
    r.stream_n_pieces = 102400;
    const std::string wire = modelnet::FormatHttpResponse(r);
    BOOST_CHECK(wire.find("Content-Length: 429496729600") != std::string::npos);
    const auto hdr_end = wire.find("\r\n\r\n");
    BOOST_REQUIRE(hdr_end != std::string::npos);
    BOOST_CHECK_EQUAL(wire.size(), hdr_end + 4);
    // SCALE huge: headers only. Writing a 400GiB body is NOT_RUN (disk).
    // Client shortcut fail-closes: advertised length exceeds FULL_FILE_STREAM_MAX_BYTES.
    uint64_t clen = 0;
    std::string err;
    BOOST_CHECK(!modelnet::FullFileStreamAcceptContentLength(wire, clen, err));
    BOOST_CHECK(err.find("too large") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(full_file_stream_http_body_cap_is_content_length_not_rpc)
{
    using namespace modelnet;
    BOOST_CHECK(IsFullFileStreamGet("GET", std::string(MODEL_HTTP_ROOT) + "files/" + std::string(96, 'a') + "/0"));
    BOOST_CHECK(!IsFullFileStreamGet("POST", std::string(MODEL_HTTP_ROOT) + "hello"));
    BOOST_CHECK(!IsFullFileStreamGet("GET", std::string(MODEL_HTTP_ROOT) + "hello"));
    BOOST_CHECK(!IsFullFileStreamGet("GET", std::string(MODEL_HTTP_ROOT) + "transfers/x/pieces/0"));
    BOOST_CHECK_EQUAL(FULL_FILE_STREAM_MAX_BYTES, 64ull << 20);
    BOOST_CHECK_EQUAL(FULL_FILE_STREAM_HTTP_READ_CAP,
                      FULL_FILE_STREAM_HTTP_HEADER_SLACK + static_cast<size_t>(FULL_FILE_STREAM_MAX_BYTES));
    BOOST_CHECK_GT(FULL_FILE_STREAM_HTTP_READ_CAP, static_cast<size_t>(256 * 1024 + 8192));

    auto hdr = [](const std::string& cl) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + cl +
               "\r\nX-BTX-Capability: " + std::string(FULL_FILE_STREAM_V1) + "\r\n\r\n";
    };

    size_t cap = 0;
    std::string err;
    BOOST_REQUIRE(FullFileStreamHttpBodyCap(true, 256ull * 1024ull + 1ull, cap, err));
    BOOST_CHECK_EQUAL(cap, FULL_FILE_STREAM_HTTP_HEADER_SLACK + 256u * 1024u + 1u);
    BOOST_REQUIRE(FullFileStreamHttpBodyCap(true, FULL_FILE_STREAM_MAX_BYTES, cap, err));
    BOOST_CHECK_EQUAL(cap, FULL_FILE_STREAM_HTTP_READ_CAP);
    BOOST_CHECK(!FullFileStreamHttpBodyCap(true, FULL_FILE_STREAM_MAX_BYTES + 1, cap, err));
    BOOST_CHECK(err.find("too large") != std::string::npos);
    BOOST_CHECK(!FullFileStreamHttpBodyCap(false, 0, cap, err));
    BOOST_CHECK(err.find("Content-Length") != std::string::npos);

    uint64_t clen = 0;
    BOOST_REQUIRE(FullFileStreamAcceptContentLength(hdr("262145"), clen, err));
    BOOST_CHECK_EQUAL(clen, 262145ull);
    BOOST_REQUIRE(FullFileStreamAcceptContentLength(hdr("67108864"), clen, err));
    BOOST_CHECK_EQUAL(clen, 64ull << 20);
    BOOST_REQUIRE(FullFileStreamAcceptContentLength(hdr("0"), clen, err));
    BOOST_CHECK_EQUAL(clen, 0ull);
    BOOST_CHECK(!FullFileStreamAcceptContentLength(hdr("67108865"), clen, err));
    BOOST_CHECK(err.find("too large") != std::string::npos);
    BOOST_CHECK(!FullFileStreamAcceptContentLength(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-BTX-Capability: " +
            std::string(FULL_FILE_STREAM_V1) + "\r\n\r\n",
        clen, err));
    BOOST_CHECK(err.find("missing Content-Length") != std::string::npos);
    BOOST_CHECK(!FullFileStreamAcceptContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n", clen, err));
    BOOST_CHECK_EQUAL(err, "truncated http");
}

BOOST_AUTO_TEST_CASE(setcloudstorage_rejects_link_local_flag_and_secret_shaped_ref)
{
    const fs::path tmp = m_path_root / "first-run-cloud-ref";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue cfg(UniValue::VOBJ);
    cfg.pushKV("endpoint", "https://acct.r2.cloudflarestorage.com");
    cfg.pushKV("bucket", "btx-models");
    cfg.pushKV("credential_ref", "AKIAFAKESECRETVALUE0000");
    cfg.pushKV("use_fake", true);
    cfg.pushKV("idempotency_key", "first-run-cloud-secret-ref");
    UniValue p(UniValue::VARR);
    p.push_back(cfg);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "setcloudstorage");
    req.pushKV("params", p);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(err.find("credential_ref") != std::string::npos);

    UniValue cfg2(UniValue::VOBJ);
    cfg2.pushKV("endpoint", "https://acct.r2.cloudflarestorage.com");
    cfg2.pushKV("bucket", "btx-models");
    cfg2.pushKV("credential_ref", "env:BTX_CLOUD_CREDENTIAL");
    cfg2.pushKV("use_fake", true);
    cfg2.pushKV("allow_link_local", true);
    cfg2.pushKV("idempotency_key", "first-run-cloud-link-local");
    UniValue p2(UniValue::VARR);
    p2.push_back(cfg2);
    req.pushKV("params", p2);
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(err.find("allow_link_local") != std::string::npos);

    UniValue badm(UniValue::VOBJ);
    badm.pushKV("method", 1);
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, badm, result, code, err));
    BOOST_CHECK(code == "METHOD_NOT_FOUND" || code == "INTERNAL");
}

BOOST_AUTO_TEST_CASE(btxd_unknown_method_fails_immediately_without_helper)
{
    // btxd CRPCTable lookup only. Does not CallUnixRpc / spawn btx-modeld.
    // A registered proxy (getcloudstorageinfo) is present; an unknown name
    // is RPC_METHOD_NOT_FOUND immediately. Live helper-death dump is NOT_RUN.
    CRPCTable table;
    RegisterModelNetRPCCommands(table);
    bool saw_proxy = false;
    for (const auto& name : table.listCommands()) {
        if (name == "getcloudstorageinfo") saw_proxy = true;
        BOOST_CHECK(name != "not_a_helper_rpc");
    }
    BOOST_CHECK(saw_proxy);

    JSONRPCRequest req;
    req.strMethod = "not_a_helper_rpc";
    req.params = UniValue(UniValue::VARR);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    const auto t0 = std::chrono::steady_clock::now();
    bool threw = false;
    try {
        (void)table.execute(req);
    } catch (const UniValue& e) {
        threw = true;
        BOOST_CHECK_EQUAL(e["code"].getInt<int>(), RPC_METHOD_NOT_FOUND);
        BOOST_CHECK_EQUAL(e["message"].get_str(), "Method not found");
    }
    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK(threw);
    BOOST_CHECK_LT(elapsed_ms, 2000);
}

BOOST_AUTO_TEST_CASE(setmodelprofile_live_host_auto_does_not_advertise_empty)
{
    // A3/A5: setmodelprofile applies follow/preserve/upload/host-auto live.
    // NODE_MODEL_HOST still follows AutoHostShouldAdvertise: empty/unverified
    // catalogs must not advertise. No helper restart required.
    const fs::path tmp = m_path_root / "first-run-profile-live";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue p(UniValue::VARR);
    p.push_back("personal");
    const UniValue set = Dispatch(cat, Rpc("setmodelprofile", p));
    BOOST_CHECK(set["applied"].get_bool());
    BOOST_CHECK_EQUAL(set["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(set["note"].get_str().find("applied live") != std::string::npos);
    const UniValue got = Dispatch(cat, Rpc("getmodelprofile"));
    BOOST_CHECK_EQUAL(got["profile"].get_str(), "personal");
    const UniValue net = Dispatch(cat, Rpc("getmodelnetworkinfo"));
    BOOST_CHECK(!net["advertised_host"].get_bool());
    BOOST_CHECK(!modelnet::NodeModelHostAdvertisedWanted());
}

BOOST_AUTO_TEST_CASE(crypto_pq1_reports_no_secrets)
{
    const fs::path tmp = m_path_root / "first-run-crypto";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const UniValue crypto = Dispatch(cat, Rpc("getmodelcryptoinfo"));
    BOOST_CHECK_EQUAL(crypto["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_REQUIRE(crypto.exists("pq1_ready"));
    BOOST_CHECK(crypto["pq1_ready"].isBool());
    BOOST_CHECK_EQUAL(crypto["transport"].get_str(), "pq1");
    BOOST_CHECK_EQUAL(crypto["group"].get_str(), "MLKEM768");
    BOOST_CHECK_EQUAL(crypto["sigalg"].get_str(), "mldsa44");
    BOOST_CHECK(!crypto.exists("sk_hex"));
    BOOST_CHECK(!crypto.exists("secret"));
    BOOST_CHECK(!crypto.exists("secret32_hex"));
    BOOST_CHECK(!crypto.exists("private_key"));
    BOOST_CHECK(!crypto.exists("wallet_seed"));
    BOOST_CHECK(!crypto.exists("tls_private_key"));
    BOOST_CHECK(!crypto.exists("aws_secret_access_key"));
    BOOST_CHECK(!crypto.exists("secret_access_key"));
    if (crypto.exists("cloud_storage") && crypto["cloud_storage"].isObject()) {
        BOOST_CHECK(!crypto["cloud_storage"]["secrets_in_response"].get_bool());
        BOOST_CHECK(!crypto["cloud_storage"].exists("sk_hex"));
        BOOST_CHECK(!crypto["cloud_storage"].exists("secret"));
        BOOST_CHECK(!crypto["cloud_storage"].exists("aws_secret_access_key"));
    }
}

BOOST_AUTO_TEST_CASE(seed_pin_unseed_unpin_after_host)
{
    const fs::path tmp = m_path_root / "first-run-seed-pin";
    fs::create_directories(tmp / "qwen-seed-pin");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "qwen-seed-pin" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(tmp / "qwen-seed-pin" / "README.md");
        card << "seed-pin unique sidecar for catalog isolation\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue hostp(UniValue::VARR);
    hostp.push_back(fs::PathToString(tmp / "qwen-seed-pin"));
    const UniValue hosted = Dispatch(cat, Rpc("hostmodel", hostp));
    BOOST_REQUIRE(hosted.exists("uri"));
    const std::string uri = hosted["uri"].get_str();

    UniValue idp(UniValue::VARR);
    idp.push_back(uri);
    const UniValue unpinned = Dispatch(cat, Rpc("unpinmodel", idp));
    BOOST_CHECK(!unpinned["pinned"].get_bool());
    BOOST_CHECK_EQUAL(unpinned["automatic_spend_atoms"].getInt<int>(), 0);
    const UniValue pinned = Dispatch(cat, Rpc("pinmodel", idp));
    BOOST_CHECK(pinned["pinned"].get_bool());
    BOOST_CHECK_EQUAL(pinned["automatic_spend_atoms"].getInt<int>(), 0);

    const UniValue unseeded = Dispatch(cat, Rpc("unseedmodel", idp));
    BOOST_CHECK(!unseeded["seeded"].get_bool());
    BOOST_CHECK_EQUAL(unseeded["automatic_spend_atoms"].getInt<int>(), 0);
    const UniValue seeded = Dispatch(cat, Rpc("seedmodel", idp));
    BOOST_CHECK(seeded["seeded"].get_bool());
    BOOST_CHECK_EQUAL(seeded["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(finite_mandate_rejects_all_recipients_watch_does_not_spend)
{
    const fs::path tmp = m_path_root / "first-run-mandate-watch";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue bad(UniValue::VOBJ);
    bad.pushKV("total_atoms", "100");
    bad.pushKV("per_action_atoms", "40");
    bad.pushKV("owner_approval_ref", "user-1");
    bad.pushKV("all_recipients", true);
    UniValue badp(UniValue::VARR);
    badp.push_back(bad);
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("createagentmandate", badp), result, code, err));
    BOOST_CHECK(err.find("unbounded") != std::string::npos);

    UniValue wrap(UniValue::VOBJ);
    UniValue inner(UniValue::VOBJ);
    inner.pushKV("total_atoms", "100");
    inner.pushKV("per_action_atoms", "40");
    inner.pushKV("owner_approval_ref", "user-1");
    wrap.pushKV("mandate", inner);
    wrap.pushKV("owner_approval_ref", "user-1");
    wrap.pushKV("all_recipients", true);
    UniValue wrapp(UniValue::VARR);
    wrapp.push_back(wrap);
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("createagentmandate", wrapp), result, code, err));
    BOOST_CHECK(err.find("unbounded") != std::string::npos);

    UniValue m(UniValue::VOBJ);
    m.pushKV("total_atoms", "100");
    m.pushKV("per_action_atoms", "40");
    m.pushKV("owner_approval_ref", "user-1");
    m.pushKV("all_recipients", false);
    UniValue mp(UniValue::VARR);
    mp.push_back(m);
    const UniValue created = Dispatch(cat, Rpc("createagentmandate", mp));
    BOOST_REQUIRE(created.exists("mandate_id"));
    BOOST_CHECK(!created.exists("all_recipients") || !created["all_recipients"].get_bool());
    BOOST_CHECK(!created.exists("wallet_signed") || !created["wallet_signed"].get_bool());
    BOOST_CHECK(!created.exists("wallet") || !created["wallet"].get_bool());
    if (created.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(created["automatic_spend_atoms"].getInt<int>(), 0);
    }

    UniValue wo(UniValue::VOBJ);
    wo.pushKV("bounty_id", "first-run-watch-bounty");
    UniValue wp(UniValue::VARR);
    wp.push_back(wo);
    const UniValue watched = Dispatch(cat, Rpc("watchbounty", wp));
    BOOST_REQUIRE(watched.exists("watch_id"));
    BOOST_CHECK(!watched["downloads"].get_bool());
    BOOST_CHECK(!watched["evaluates"].get_bool());
    BOOST_CHECK(!watched["spends"].get_bool());
    BOOST_CHECK(!watched.exists("wallet_signed") || !watched["wallet_signed"].get_bool());
    if (watched.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(watched["automatic_spend_atoms"].getInt<int>(), 0);
    }
}

BOOST_AUTO_TEST_CASE(remaining_alias_job_storage_ops)
{
    // exportmodellink is already fully covered by show_export_open_unhost_empty_search.
    const fs::path tmp = m_path_root / "first-run-remain";
    fs::create_directories(tmp / "qwen-remain");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "qwen-remain" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(tmp / "qwen-remain" / "README.md");
        card << "remaining-alias unique sidecar for catalog isolation\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue hostp(UniValue::VARR);
    hostp.push_back(fs::PathToString(tmp / "qwen-remain"));
    const UniValue hosted = Dispatch(cat, Rpc("hostmodel", hostp));
    BOOST_REQUIRE(hosted.exists("uri"));
    const std::string uri = hosted["uri"].get_str();

    UniValue aliasp(UniValue::VARR);
    aliasp.push_back(uri);
    aliasp.push_back("qwen-remain");
    const UniValue aliased = Dispatch(cat, Rpc("setmodelalias", aliasp));
    BOOST_CHECK_EQUAL(aliased["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!aliased.exists("wallet_signed") || !aliased["wallet_signed"].get_bool());

    UniValue rmp(UniValue::VARR);
    rmp.push_back(uri);
    rmp.push_back("qwen-remain");
    const UniValue removed = Dispatch(cat, Rpc("removemodelalias", rmp));
    BOOST_CHECK_EQUAL(removed["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!removed.exists("wallet_signed") || !removed["wallet_signed"].get_bool());

    const UniValue jobs = Dispatch(cat, Rpc("getmodeljob"));
    BOOST_REQUIRE(jobs["jobs"].isArray());
    BOOST_CHECK_EQUAL(jobs["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue cancelp(UniValue::VARR);
    cancelp.push_back("no-such-remain-job");
    const UniValue cancelled = Dispatch(cat, Rpc("cancelmodeljob", cancelp));
    BOOST_CHECK(!cancelled["cancelled"].get_bool());
    BOOST_CHECK_EQUAL(cancelled["job_id"].get_str(), "no-such-remain-job");
    BOOST_CHECK_EQUAL(cancelled["automatic_spend_atoms"].getInt<int>(), 0);

    const UniValue policy = Dispatch(cat, Rpc("setmodelstoragepolicy"));
    BOOST_CHECK(!policy["bulk_io"].get_bool());
    BOOST_CHECK_EQUAL(policy["automatic_spend_atoms"].getInt<int>(), 0);
    if (policy.exists("note")) {
        BOOST_CHECK(policy["note"].get_str().find("credentials") != std::string::npos);
        BOOST_CHECK(policy["note"].get_str().find("unlimited I/O") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(remaining_init_identity_no_wallet)
{
    const fs::path tmp = m_path_root / "first-run-init";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp, 8 << 20};

    UniValue setup = Dispatch(cat, Rpc("checkmodelsetup"));
    BOOST_CHECK_EQUAL(setup["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!setup.exists("secret"));
    BOOST_CHECK(!setup.exists("wallet_seed"));

    UniValue createp(UniValue::VARR);
    createp.push_back("first-run-init");
    const UniValue created = Dispatch(cat, Rpc("createmodelidentity", createp));
    if (!setup.exists("identity_ready") || !setup["identity_ready"].get_bool()) {
        setup = Dispatch(cat, Rpc("checkmodelsetup"));
    }

    BOOST_CHECK(setup["identity_ready"].get_bool());
    BOOST_CHECK(!setup["identity_wallet_key"].get_bool());
    BOOST_CHECK(!setup.exists("wallet_key") || !setup["wallet_key"].get_bool());
    BOOST_CHECK_EQUAL(setup["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!setup.exists("secret"));
    BOOST_CHECK(!setup.exists("wallet_seed"));

    BOOST_CHECK(!created["wallet_backed"].get_bool());
    BOOST_CHECK(!created["contains_wallet_material"].get_bool());
    BOOST_CHECK(!created.exists("wallet_key") || !created["wallet_key"].get_bool());
    if (created.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(created["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_CHECK(!created.exists("secret"));
    BOOST_CHECK(!created.exists("wallet_seed"));
    BOOST_CHECK(created["note"].get_str().find("never a wallet key") != std::string::npos);

    UniValue listed;
    std::string code, err;
    if (modelnet::DispatchHelperRpc(cat, Rpc("listmodelidentities"), listed, code, err)) {
        BOOST_REQUIRE(listed["identities"].isArray());
        if (listed.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(listed["automatic_spend_atoms"].getInt<int>(), 0);
        }
        BOOST_CHECK(!listed.exists("secret"));
        BOOST_CHECK(!listed.exists("wallet_seed"));
        for (const auto& id : listed["identities"].getValues()) {
            BOOST_CHECK(!id.exists("secret"));
            BOOST_CHECK(!id.exists("wallet_seed"));
            BOOST_CHECK(!id.exists("wallet_key") || !id["wallet_key"].get_bool());
            if (id.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(id["automatic_spend_atoms"].getInt<int>(), 0);
            }
        }
    } else {
        BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
    }
}

BOOST_AUTO_TEST_CASE(remaining_identity_policy_circle_release_ops)
{
    const fs::path tmp = m_path_root / "first-run-circle-rel";
    fs::create_directories(tmp / "qwen-circle");
    const auto st = MinimalSafeTensors();
    {
        std::ofstream out(tmp / "qwen-circle" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
        std::ofstream card(tmp / "qwen-circle" / "README.md");
        card << "remaining-circle unique sidecar for catalog isolation\n";
    }
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue hostp(UniValue::VARR);
    hostp.push_back(fs::PathToString(tmp / "qwen-circle"));
    const UniValue hosted = Dispatch(cat, Rpc("hostmodel", hostp));
    BOOST_REQUIRE(hosted.exists("uri"));
    BOOST_REQUIRE(hosted.exists("model_id"));
    const std::string uri = hosted["uri"].get_str();
    const std::string model_hex = hosted["model_id"].get_str();

    UniValue patch(UniValue::VOBJ);
    patch.pushKV("seed", "off");
    patch.pushKV("preserve_rare", true);
    UniValue setp(UniValue::VARR);
    setp.push_back(patch);
    const UniValue setpol = Dispatch(cat, Rpc("setmodelpolicy", setp));
    BOOST_CHECK_EQUAL(setpol["seed"].get_str(), "off");
    BOOST_CHECK(setpol["preserve_rare"].get_bool());
    BOOST_CHECK_EQUAL(setpol["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!setpol.exists("wallet_signed") || !setpol["wallet_signed"].get_bool());
    const UniValue gotpol = Dispatch(cat, Rpc("getmodelpolicy"));
    BOOST_CHECK_EQUAL(gotpol["seed"].get_str(), "off");
    BOOST_CHECK(gotpol["preserve_rare"].get_bool());
    BOOST_CHECK_EQUAL(gotpol["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!gotpol.exists("wallet_signed") || !gotpol["wallet_signed"].get_bool());

    const UniValue ids = Dispatch(cat, Rpc("listmodelidentities"));
    BOOST_REQUIRE(ids["identities"].isArray());
    BOOST_CHECK(!ids.exists("secret"));
    BOOST_CHECK(!ids.exists("wallet_seed"));
    if (ids.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(ids["automatic_spend_atoms"].getInt<int>(), 0);
    }
    for (const auto& id : ids["identities"].getValues()) {
        BOOST_CHECK(!id.exists("secret"));
        BOOST_CHECK(!id.exists("wallet_seed"));
        BOOST_CHECK(!id.exists("wallet_key") || !id["wallet_key"].get_bool());
        if (id.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(id["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }

    UniValue jp(UniValue::VARR);
    jp.push_back(model_hex);
    const UniValue joined = Dispatch(cat, Rpc("joinmodelcircle", jp));
    BOOST_CHECK_EQUAL(joined["on_chain_membership"].get_bool(), false);
    if (joined.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(joined["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_CHECK(!joined.exists("wallet_signed") || !joined["wallet_signed"].get_bool());

    UniValue leave;
    std::string code, err;
    if (modelnet::DispatchHelperRpc(cat, Rpc("leavemodelcircle", jp), leave, code, err)) {
        BOOST_CHECK_EQUAL(leave["on_chain_membership"].get_bool(), false);
        if (leave.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(leave["automatic_spend_atoms"].getInt<int>(), 0);
        }
        BOOST_CHECK(!leave.exists("wallet_signed") || !leave["wallet_signed"].get_bool());
    } else {
        BOOST_CHECK(code != "crash");
        if (leave.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(leave["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }

    const UniValue recip = Dispatch(cat, Rpc("getmodelreciprocity"));
    if (recip.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(recip["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_CHECK(!recip.exists("wallet_signed") || !recip["wallet_signed"].get_bool());

    UniValue colp(UniValue::VARR);
    colp.push_back(model_hex);
    UniValue sub;
    code.clear();
    err.clear();
    if (modelnet::DispatchHelperRpc(cat, Rpc("subscribemodelcollection", colp), sub, code, err)) {
        if (sub.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(sub["automatic_spend_atoms"].getInt<int>(), 0);
        }
        BOOST_CHECK(!sub.exists("wallet_signed") || !sub["wallet_signed"].get_bool());
        UniValue unsub;
        std::string ucode, uerr;
        if (modelnet::DispatchHelperRpc(cat, Rpc("unsubscribemodelcollection", colp), unsub, ucode, uerr)) {
            if (unsub.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(unsub["automatic_spend_atoms"].getInt<int>(), 0);
            }
            BOOST_CHECK(!unsub.exists("wallet_signed") || !unsub["wallet_signed"].get_bool());
        } else {
            BOOST_CHECK(ucode != "crash");
            if (unsub.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(unsub["automatic_spend_atoms"].getInt<int>(), 0);
            }
        }
    } else {
        BOOST_CHECK(code != "crash");
        if (sub.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(sub["automatic_spend_atoms"].getInt<int>(), 0);
        }
    }

    UniValue cp(UniValue::VARR);
    cp.push_back(uri);
    cp.push_back(std::string(64, 'a'));
    cp.push_back(100000);
    UniValue created_rel;
    code.clear();
    err.clear();
    if (modelnet::DispatchHelperRpc(cat, Rpc("createmodelrelease", cp), created_rel, code, err)) {
        BOOST_CHECK(!created_rel.exists("wallet_signed") || !created_rel["wallet_signed"].get_bool());
        BOOST_CHECK(!created_rel.exists("wallet") || !created_rel["wallet"].get_bool());
        if (created_rel.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(created_rel["automatic_spend_atoms"].getInt<int>(), 0);
        }
        UniValue gp(UniValue::VARR);
        if (created_rel.exists("release_id") && created_rel["release_id"].isStr()) {
            gp.push_back(created_rel["release_id"].get_str());
        }
        UniValue gotrel;
        std::string gcode, gerr;
        if (modelnet::DispatchHelperRpc(cat, Rpc("getmodelrelease", gp), gotrel, gcode, gerr)) {
            BOOST_CHECK_EQUAL(gotrel["automatic_spend_atoms"].getInt<int>(), 0);
            BOOST_CHECK(!gotrel.exists("wallet_signed") || !gotrel["wallet_signed"].get_bool());
        } else {
            BOOST_CHECK(gcode != "METHOD_NOT_FOUND");
            if (gotrel.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(gotrel["automatic_spend_atoms"].getInt<int>(), 0);
            }
        }
    } else {
        BOOST_CHECK(code != "METHOD_NOT_FOUND");
        if (created_rel.exists("automatic_spend_atoms")) {
            BOOST_CHECK_EQUAL(created_rel["automatic_spend_atoms"].getInt<int>(), 0);
        }
        UniValue listed_rel;
        std::string gcode, gerr;
        if (modelnet::DispatchHelperRpc(cat, Rpc("getmodelrelease"), listed_rel, gcode, gerr)) {
            if (listed_rel.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(listed_rel["automatic_spend_atoms"].getInt<int>(), 0);
            }
            BOOST_CHECK(!listed_rel.exists("wallet_signed") || !listed_rel["wallet_signed"].get_bool());
        } else {
            BOOST_CHECK(gcode != "METHOD_NOT_FOUND");
            if (listed_rel.exists("automatic_spend_atoms")) {
                BOOST_CHECK_EQUAL(listed_rel["automatic_spend_atoms"].getInt<int>(), 0);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
