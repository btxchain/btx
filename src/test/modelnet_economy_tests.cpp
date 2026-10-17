// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/catalog.h>
#include <modelnet/compute_economy.h>
#include <modelnet/crypto.h>
#include <modelnet/economy.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/release.h>
#include <modelnet/search.h>
#include <crypto/common.h>
#include <matmul/compute_profile.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_economy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(econ_fund_01_card_math)
{
    using namespace modelnet;
    int64_t milli = 0;
    const int64_t target = 500 * COIN_ATOMS;
    const int64_t confirmed = 371 * COIN_ATOMS;
    BOOST_REQUIRE(FundedPercentMilli(confirmed, target, milli));
    BOOST_CHECK_EQUAL(milli, 74200);
    BOOST_CHECK_CLOSE(MilliToDisplayPercent(milli), 74.2, 0.0001);
    BOOST_CHECK_EQUAL(RemainingAtoms(target, confirmed), 129 * COIN_ATOMS);
    BOOST_CHECK(!FundedPercentMilli(0, 0, milli));
    BOOST_CHECK_EQUAL(AutomaticSpendAtoms(), 0);
    BOOST_CHECK(!EconomyTouchesMonetaryConsensus());
}

BOOST_AUTO_TEST_CASE(econ_fund_02_pledged_not_funded)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.display_name = "Campaign";
    h.rec.canonical_name = "Campaign";
    ReleaseCampaign c;
    c.release_id.data[0] = 1;
    c.model_id.data[0] = 2;
    c.target_atoms = 500 * COIN_ATOMS;
    c.pledged_atoms = 450 * COIN_ATOMS;
    FundingObservation f;
    f.confirmed_known = true;
    f.confirmed_funded_atoms = 200 * COIN_ATOMS;
    f.funding_source = "CHAIN_OBSERVATION";
    const auto e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(e.value_known);
    BOOST_CHECK_EQUAL(e.remaining_atoms, 300 * COIN_ATOMS);
    BOOST_CHECK_EQUAL(e.campaign.pledged_atoms, 450 * COIN_ATOMS);
    BOOST_CHECK_NE(e.funded_percent_milli, 90000);
    const UniValue j = EconomyReleaseJson(e);
    BOOST_CHECK_EQUAL(j["pledged_atoms"].getInt<int64_t>(), 450 * COIN_ATOMS);
    BOOST_CHECK_EQUAL(j["confirmed_funded_atoms"].getInt<int64_t>(), 200 * COIN_ATOMS);
    BOOST_CHECK(j.exists("pledged_percent"));
    BOOST_CHECK(j.exists("funded_percent"));
    BOOST_CHECK_LT(j["funded_percent"].get_real(), 50.0);
}

BOOST_AUTO_TEST_CASE(econ_fund_03_hashlock_sha256)
{
    using namespace modelnet;
    SearchHit h;
    ReleaseCampaign c;
    c.release_id.data[0] = 9;
    c.model_id.data[0] = 8;
    c.target_atoms = 1;
    c.key_hash.data[0] = 0xab;
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("hashlock_algorithm", "HASH160");
    std::string err;
    BOOST_CHECK(!RejectHash160Campaign(opts, err));
    const auto e = ComposeEconomyEntry(h, &c, {});
    const UniValue j = EconomyReleaseJson(e);
    BOOST_CHECK_EQUAL(j["hashlock_algorithm"].get_str(), "SHA256");
    BOOST_CHECK_EQUAL(j["assurance"].get_str(), "KEY_RELEASE_ONLY");
    BOOST_CHECK_EQUAL(j["key_hash"].get_str(), c.key_hash.Hex());
    BOOST_CHECK(!j.exists("secret"));
}

BOOST_AUTO_TEST_CASE(econ_fund_04_refund_status)
{
    using namespace modelnet;
    SearchHit h;
    ReleaseCampaign c;
    c.release_id.data[0] = 3;
    c.target_atoms = 10;
    c.refund_height = 100;
    FundingObservation f;
    f.refund_status = RefundStatus::NOT_MATURE;
    f.chain_height_known = true;
    f.chain_height = 50;
    auto e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(std::string(RefundStatusName(e.fund.refund_status)), "NOT_MATURE");
    f.refund_status = RefundStatus::AVAILABLE;
    f.refund_available_locally = true;
    f.wallet_contributor = true;
    e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e.lifecycle, ModelLifecycle::REFUND_AVAILABLE);
    bool has_refund = false;
    for (const auto a : e.actions) {
        if (a == EconomyAction::REFUND) has_refund = true;
    }
    BOOST_CHECK(has_refund);
}

BOOST_AUTO_TEST_CASE(econ_action_01_to_04)
{
    using namespace modelnet;
    SearchHit pub;
    pub.rec.display_name = "Public";
    pub.rec.canonical_name = "Public";
    auto e = ComposeEconomyEntry(pub, nullptr, {});
    BOOST_CHECK_EQUAL(std::string(ModelResultTypeName(e.result_type)), "PUBLIC_MODEL");
    BOOST_CHECK(e.downloadable_now);
    std::string acts;
    for (const auto a : e.actions) acts += std::string(EconomyActionName(a)) + ",";
    BOOST_CHECK(acts.find("DOWNLOAD") != std::string::npos);
    BOOST_CHECK(acts.find("KEEP") != std::string::npos);
    BOOST_CHECK(acts.find("COPY_URI") != std::string::npos);

    ReleaseCampaign c;
    c.release_id.data[0] = 1;
    c.target_atoms = 500;
    SearchHit h = pub;
    FundingObservation f;
    e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e.lifecycle, ModelLifecycle::FUNDING);
    BOOST_CHECK(e.fundable_now);
    acts.clear();
    for (const auto a : e.actions) acts += std::string(EconomyActionName(a)) + ",";
    BOOST_CHECK(acts.find("VIEW_RELEASE") != std::string::npos);
    BOOST_CHECK(acts.find("FUND_RELEASE") != std::string::npos);

    f.confirmed_known = true;
    f.confirmed_funded_atoms = 500;
    e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e.lifecycle, ModelLifecycle::FUNDED_AWAITING_RELEASE);
    acts.clear();
    for (const auto a : e.actions) acts += std::string(EconomyActionName(a)) + ",";
    BOOST_CHECK(acts.find("WAIT_FOR_UNLOCK") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(econ_lifecycle_transition_same_model)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.model_id.data[0] = 7;
    h.rec.display_name = "X";
    h.rec.canonical_name = "X";
    ReleaseCampaign c;
    c.release_id.data[0] = 7;
    c.model_id = h.rec.model_id;
    c.target_atoms = 10;
    FundingObservation f;
    auto e1 = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e1.lifecycle, ModelLifecycle::FUNDING);
    f.confirmed_known = true;
    f.confirmed_funded_atoms = 10;
    auto e2 = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e2.lifecycle, ModelLifecycle::FUNDED_AWAITING_RELEASE);
    c.secret_disclosed = true;
    auto e3 = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e3.lifecycle, ModelLifecycle::SECRET_DISCLOSED);
    c.plaintext_verified = true;
    auto e4 = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK_EQUAL(e4.lifecycle, ModelLifecycle::PUBLIC_RELEASED);
    BOOST_CHECK_EQUAL(e1.hit.rec.model_id.Hex(), e4.hit.rec.model_id.Hex());
}

BOOST_AUTO_TEST_CASE(econ_feed_04_nearly_funded_order)
{
    using namespace modelnet;
    auto mk = [](unsigned char id, int64_t confirmed) {
        SearchHit h;
        h.rec.model_id.data[0] = id;
        h.rec.display_name = std::string("C") + std::to_string(id);
        h.rec.canonical_name = h.rec.display_name;
        ReleaseCampaign c;
        c.release_id.data[0] = id;
        c.model_id = h.rec.model_id;
        c.target_atoms = 100 * COIN_ATOMS;
        FundingObservation f;
        f.confirmed_known = true;
        f.confirmed_funded_atoms = confirmed;
        f.funding_source = "CHAIN_OBSERVATION";
        return ComposeEconomyEntry(h, &c, f);
    };
    std::vector<ModelEconomyEntry> v;
    v.push_back(mk(1, 10 * COIN_ATOMS));
    v.push_back(mk(2, 99 * COIN_ATOMS));
    v.push_back(mk(3, 75 * COIN_ATOMS));
    SortEconomyEntries(v, SearchSort::NEARLY_FUNDED);
    BOOST_CHECK_EQUAL(static_cast<int>(v[0].hit.rec.model_id.data[0]), 2);
    BOOST_CHECK_EQUAL(static_cast<int>(v[1].hit.rec.model_id.data[0]), 3);
    BOOST_CHECK_EQUAL(static_cast<int>(v[2].hit.rec.model_id.data[0]), 1);
}

BOOST_AUTO_TEST_CASE(econ_cipher_wrap_unwrap)
{
    using namespace modelnet;
    std::vector<unsigned char> secret(32, 0x5a);
    std::vector<unsigned char> plain(256, 0x11);
    plain[0] = 'S';
    std::vector<unsigned char> wrapped;
    std::string err;
    BOOST_REQUIRE(WrapBtxEnc2(secret, plain, wrapped, err));
    BOOST_CHECK(LooksLikeBtxEnc2(wrapped));
    BOOST_CHECK(!LooksLikeBtxEnc2(plain));
    std::vector<unsigned char> out;
    BOOST_REQUIRE(UnwrapBtxEnc2(secret, wrapped, out, err));
    BOOST_CHECK(out == plain);
    std::vector<unsigned char> bad(32, 0x00);
    std::vector<unsigned char> fail;
    BOOST_CHECK(!UnwrapBtxEnc2(bad, wrapped, fail, err));
    BOOST_CHECK(fail.empty());
}

BOOST_AUTO_TEST_CASE(econ_chain_join_json)
{
    using namespace modelnet;
    UniValue card(UniValue::VOBJ);
    UniValue rel(UniValue::VOBJ);
    rel.pushKV("target_atoms", 500);
    rel.pushKV("funded_atoms", 0);
    rel.pushKV("release_id", std::string(96, 'a'));
    card.pushKV("release", rel);
    card.pushKV("fundable_now", true);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_RELEASE");
    card.pushKV("actions", acts);
    UniValue remote(UniValue::VOBJ);
    remote.pushKV("confirmed_known", true);
    remote.pushKV("funding_source", "OBSERVED_NETWORK_STATE");
    remote.pushKV("confirmed_funded_atoms", 500);
    ApplyChainObservationJson(card, remote);
    BOOST_CHECK(card["fundable_now"].isTrue());
    BOOST_CHECK_EQUAL(card["release"]["funded_atoms"].getInt<int64_t>(), 0);

    UniValue obs(UniValue::VOBJ);
    obs.pushKV("confirmed_known", true);
    obs.pushKV("funding_source", "CHAIN_OBSERVATION");
    obs.pushKV("confirmed_funded_atoms", 500);
    obs.pushKV("pending_funded_atoms", 0);
    ApplyChainObservationJson(card, obs);
    BOOST_CHECK_EQUAL(card["release"]["funding_source"].get_str(), "CHAIN_OBSERVATION");
    BOOST_CHECK_EQUAL(card["release"]["confirmed_funded_atoms"].getInt<int64_t>(), 500);
    BOOST_CHECK(card["fundable_now"].isFalse());
    BOOST_CHECK_EQUAL(card["lifecycle_state"].get_str(), "FUNDED_AWAITING_RELEASE");
}

BOOST_AUTO_TEST_CASE(econ_ingest_rejects_remote_unsigned)
{
    using namespace modelnet;
    const fs::path tmp = m_args.GetDataDirBase() / "ingest-chain";
    ModelCatalog cat{tmp, 1 << 20};
    UniValue obs(UniValue::VOBJ);
    obs.pushKV("confirmed_known", true);
    obs.pushKV("funding_source", "OBSERVED_NETWORK_STATE");
    obs.pushKV("confirmed_funded_atoms", 999);
    obs.pushKV("release_id", std::string(96, 'a'));
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back(obs);
    req.pushKV("method", "ingestchainfundingobservation");
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(result.exists("accepted"));
    BOOST_CHECK(result["accepted"].isFalse());
}

BOOST_AUTO_TEST_CASE(econ_ciphertext_needs_provider)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.display_name = "Enc";
    h.rec.canonical_name = "Enc";
    ReleaseCampaign c;
    c.release_id.data[0] = 9;
    c.model_id.data[0] = 9;
    c.artifact_id.data[0] = 9;
    c.target_atoms = 10;
    FundingObservation f;
    f.ciphertext_providers_observed = 0;
    auto e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(!e.ciphertext_available);
    BOOST_CHECK(!e.ciphertext_cacheable);
    f.ciphertext_providers_observed = 1;
    e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(e.ciphertext_available);
    BOOST_CHECK(e.ciphertext_cacheable);
}

BOOST_AUTO_TEST_CASE(econ_known_zero_is_not_value_known)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.display_name = "z";
    ReleaseCampaign c;
    c.release_id.data[0] = 1;
    c.model_id.data[0] = 1;
    c.target_atoms = 5'000'000;
    FundingObservation f;
    f.confirmed_known = true;
    f.confirmed_funded_atoms = 0;
    f.funding_source = "CHAIN_OBSERVATION";
    auto e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(!e.value_known);
    BOOST_CHECK(e.fundable_now);
    f.confirmed_funded_atoms = 2'000'000;
    e = ComposeEconomyEntry(h, &c, f);
    BOOST_CHECK(e.value_known);
    BOOST_CHECK_EQUAL(e.fund.confirmed_funded_atoms, 2'000'000);
    BOOST_CHECK(e.fundable_now);

    UniValue card(UniValue::VOBJ);
    UniValue rel(UniValue::VOBJ);
    rel.pushKV("target_atoms", 5'000'000);
    rel.pushKV("funded_atoms", 0);
    rel.pushKV("value_known", true);
    card.pushKV("release", rel);
    UniValue miss(UniValue::VOBJ);
    miss.pushKV("confirmed_known", true);
    miss.pushKV("funding_source", "CHAIN_OBSERVATION");
    miss.pushKV("confirmed_funded_atoms", 0);
    ApplyChainObservationJson(card, miss);
    BOOST_CHECK(card["release"]["value_known"].isFalse());
    BOOST_CHECK_EQUAL(card["release"]["funded_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(econ_card_omits_null_publisher_and_keeps_size)
{
    using namespace modelnet;
    SearchHit h;
    h.rec.display_name = "named";
    h.rec.size_bytes = 16496;
    UniValue card = SearchResultCard(h);
    BOOST_CHECK(card.exists("publisher"));
    BOOST_CHECK(!card["publisher"].exists("id"));
    BOOST_CHECK_EQUAL(card["size_bytes"].getInt<int64_t>(), 16496);
    h.rec.publisher_identity.data[0] = 0xab;
    card = SearchResultCard(h);
    BOOST_REQUIRE(card["publisher"].exists("id"));
    BOOST_CHECK_NE(card["publisher"]["id"].get_str(), std::string(96, '0'));
    BOOST_CHECK_EQUAL(card["publisher"]["id"].get_str().size(), 96U);

    ReleaseCampaign c;
    c.release_id.data[0] = 2;
    c.model_id.data[0] = 2;
    c.target_atoms = 10;
    auto entry = EconomyEntryToJson(ComposeEconomyEntry(h, &c, {}));
    BOOST_REQUIRE(entry["publisher"].exists("id"));
    BOOST_CHECK_NE(entry["publisher"]["id"].get_str(), std::string(96, '0'));
    BOOST_CHECK_EQUAL(entry["model"]["size_bytes"].getInt<int64_t>(), 16496);
    SearchHit blank;
    blank.rec.display_name = "absent";
    auto absent = EconomyEntryToJson(ComposeEconomyEntry(blank, &c, {}));
    BOOST_CHECK(absent.exists("publisher"));
    BOOST_CHECK(!absent["publisher"].exists("id"));
}

BOOST_AUTO_TEST_CASE(helper_refusal_is_structured_json)
{
    std::string code, message;
    BOOST_CHECK(modelnet::HelperRefusalFromError(
        "{\"code\":\"IMPORT_FAILED\",\"message\":\"path does not exist\",\"schema_version\":2}", code, message));
    BOOST_CHECK_EQUAL(code, "IMPORT_FAILED");
    BOOST_CHECK_EQUAL(message, "path does not exist");
    BOOST_CHECK(modelnet::HelperRefusalFromError(
        "{\"code\":\"COMPUTE_RECORD_INVALID\",\"message\":\"agreement\"}", code, message));
    BOOST_CHECK_EQUAL(code, "COMPUTE_RECORD_INVALID");
    BOOST_CHECK(!modelnet::HelperRefusalFromError("helper unix connect failed (btx-modeld not running)", code, message));
    BOOST_CHECK(!modelnet::HelperRefusalFromError("helper reply json", code, message));
    BOOST_CHECK(!modelnet::HelperRefusalFromError("unix write", code, message));
}

namespace {

std::vector<unsigned char> TinySafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

UniValue HelperDispatch(modelnet::ModelCatalog& cat, const std::string& method, const UniValue& params)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err),
                          method + " " + code + " " + err);
    return result;
}

UniValue ComputeCall(const fs::path& dir, const std::string& method, const UniValue& req)
{
    UniValue params(UniValue::VARR);
    params.push_back(req);
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ComputeEconomySelfTestHook(dir, "regtest", method, params, result, code, err),
                          method + " " + code + " " + err);
    return result;
}

bool ComputeFail(const fs::path& dir, const std::string& method, const UniValue& req, const std::string& expect)
{
    UniValue params(UniValue::VARR);
    params.push_back(req);
    UniValue result;
    std::string code, err;
    const bool ok = modelnet::ComputeEconomySelfTestHook(dir, "regtest", method, params, result, code, err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(code, expect);
    return !ok && code == expect;
}

void WriteResearchIdentity(const fs::path& dir, std::vector<unsigned char>& pk)
{
    std::vector<unsigned char> sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue store(UniValue::VOBJ);
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    std::ofstream out(dir / "research_identity.json");
    out << store.write();
}

const UniValue* FindReleaseCard(const UniValue& res, const std::string& release_id)
{
    if (!res.exists("results") || !res["results"].isArray()) return nullptr;
    for (size_t i = 0; i < res["results"].size(); ++i) {
        const UniValue& card = res["results"][i];
        if (card.write().find(release_id) != std::string::npos) return &res["results"][i];
    }
    return nullptr;
}

} // namespace

BOOST_AUTO_TEST_CASE(release_card_keeps_display_name_publisher_and_size)
{
    using namespace modelnet;
    const fs::path root = m_args.GetDataDirBase() / "release-cards";
    const fs::path model = root / "toy.safetensors.dir";
    fs::create_directories(model);
    const auto st = TinySafeTensors();
    {
        std::ofstream out(model / "toy.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    ModelCatalog cat{root, 8 << 20};
    UniValue host_params(UniValue::VARR);
    host_params.push_back(fs::PathToString(model));
    const UniValue hosted = HelperDispatch(cat, "hostmodel", host_params);
    BOOST_REQUIRE(hosted.exists("uri"));

    UniValue body(UniValue::VOBJ);
    body.pushKV("uri", hosted["uri"].get_str());
    body.pushKV("secret32_hex", std::string(64, 'a'));
    body.pushKV("refund_height", 100000);
    body.pushKV("target_atoms", 5'000'000);
    body.pushKV("display_name", "Pretty Beta");
    body.pushKV("short_description", "kept description");
    UniValue meta(UniValue::VOBJ);
    meta.pushKV("family", "toy");
    meta.pushKV("format", "safetensors");
    body.pushKV("searchable_metadata", meta);
    UniValue create_params(UniValue::VARR);
    create_params.push_back(body);
    const UniValue rel = HelperDispatch(cat, "createmodelrelease", create_params);
    BOOST_CHECK_EQUAL(rel["publish_state"].get_str(), "published");
    BOOST_CHECK(!rel["search_record_id"].get_str().empty());
    const std::string rid = rel["release_id"].get_str();
    const std::string model_id = rel["model_id"].get_str();

    UniValue rec_params(UniValue::VARR);
    rec_params.push_back(model_id);
    const UniValue rec = HelperDispatch(cat, "getmodelsearchrecord", rec_params);
    BOOST_CHECK_EQUAL(rec["display_name"].get_str(), "Pretty Beta");
    BOOST_CHECK_EQUAL(rec["short_description"].get_str(), "kept description");
    BOOST_CHECK_NE(rec["display_name"].get_str(), "toy.safetensors");
    BOOST_CHECK(rec["size_bytes"].getInt<int64_t>() > 0);

    UniValue list_q(UniValue::VOBJ);
    list_q.pushKV("scope", "LOCAL");
    list_q.pushKV("limit", 10);
    UniValue list_params(UniValue::VARR);
    list_params.push_back(list_q);
    const UniValue recent = HelperDispatch(cat, "getrecentreleases", list_params);
    const UniValue* card = FindReleaseCard(recent, rid);
    BOOST_REQUIRE(card != nullptr);
    BOOST_CHECK_EQUAL((*card)["name"].get_str(), "Pretty Beta");
    BOOST_CHECK((*card)["size_bytes"].getInt<int64_t>() > 0);
    BOOST_REQUIRE((*card)["publisher"].exists("id"));
    BOOST_CHECK_NE((*card)["publisher"]["id"].get_str(), std::string(96, '0'));
    BOOST_CHECK_EQUAL((*card)["entry"]["model"]["name"].get_str(), "Pretty Beta");
    BOOST_CHECK((*card)["entry"]["model"]["size_bytes"].getInt<int64_t>() > 0);
    BOOST_CHECK_EQUAL((*card)["entry"]["model"]["description"].get_str(), "kept description");

    const UniValue fundable = HelperDispatch(cat, "getfundablemodels", list_params);
    const UniValue* fcard = FindReleaseCard(fundable, rid);
    BOOST_REQUIRE(fcard != nullptr);
    BOOST_CHECK_EQUAL((*fcard)["name"].get_str(), "Pretty Beta");
    BOOST_CHECK((*fcard)["size_bytes"].getInt<int64_t>() > 0);
    BOOST_REQUIRE((*fcard)["publisher"].exists("id"));
    BOOST_CHECK_NE((*fcard)["publisher"]["id"].get_str(), std::string(96, '0'));

    UniValue op(UniValue::VOBJ);
    op.pushKV("release_id", rid);
    op.pushKV("txid", std::string(64, 'b'));
    op.pushKV("vout", 1);
    op.pushKV("output_script", "51");
    op.pushKV("amount_atoms", 2'000'000);
    UniValue op_params(UniValue::VARR);
    op_params.push_back(op);
    const UniValue recorded = HelperDispatch(cat, "recordmodelfundingoutpoint", op_params);
    BOOST_CHECK(recorded["accepted"].isTrue());

    UniValue econ_params(UniValue::VARR);
    econ_params.push_back(rid);
    UniValue econ = HelperDispatch(cat, "getmodelreleaseeconomics", econ_params);
    BOOST_CHECK(econ["value_known"].isFalse());
    BOOST_REQUIRE(econ.exists("funding_outpoints"));
    BOOST_CHECK_EQUAL(econ["funding_outpoints"][0]["txid"].get_str(), std::string(64, 'b'));

    UniValue zero(UniValue::VOBJ);
    zero.pushKV("confirmed_known", true);
    zero.pushKV("funding_source", "CHAIN_OBSERVATION");
    zero.pushKV("confirmed_funded_atoms", 0);
    zero.pushKV("release_id", rid);
    UniValue zero_params(UniValue::VARR);
    zero_params.push_back(zero);
    const UniValue rejected = HelperDispatch(cat, "ingestchainfundingobservation", zero_params);
    BOOST_CHECK(rejected["accepted"].isFalse());
    econ = HelperDispatch(cat, "getmodelreleaseeconomics", econ_params);
    BOOST_CHECK(econ["value_known"].isFalse());

    UniValue hit(UniValue::VOBJ);
    hit.pushKV("confirmed_known", true);
    hit.pushKV("funding_source", "CHAIN_OBSERVATION");
    hit.pushKV("confirmed_funded_atoms", 2'000'000);
    hit.pushKV("release_id", rid);
    UniValue hit_params(UniValue::VARR);
    hit_params.push_back(hit);
    const UniValue ingested = HelperDispatch(cat, "ingestchainfundingobservation", hit_params);
    BOOST_CHECK(ingested["accepted"].isTrue());
    econ = HelperDispatch(cat, "getmodelreleaseeconomics", econ_params);
    BOOST_CHECK(econ["value_known"].isTrue());
    BOOST_CHECK_EQUAL(econ["confirmed_funded_atoms"].getInt<int64_t>(), 2'000'000);
    const UniValue still = HelperDispatch(cat, "getfundablemodels", list_params);
    BOOST_REQUIRE(FindReleaseCard(still, rid) != nullptr);
}

BOOST_AUTO_TEST_CASE(verifycomputereceipt_does_not_persist)
{
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    const fs::path issuer = m_args.GetDataDirBase() / "receipt-issuer";
    const fs::path reader = m_args.GetDataDirBase() / "receipt-reader";
    fs::create_directories(issuer);
    fs::create_directories(reader);
    std::vector<unsigned char> pk;
    WriteResearchIdentity(issuer, pk);
    const std::string hex = HexStr(pk);

    UniValue offer(UniValue::VOBJ);
    offer.pushKV("record_type", "compute_offer_v1");
    offer.pushKV("schema_version", 1);
    offer.pushKV("created_at_ms", 1);
    offer.pushKV("expires_at_ms", 10'000'000);
    offer.pushKV("nonce", "aa");
    offer.pushKV("resource_ref", "urn:btx:pwc:demo-model");
    offer.pushKV("issuer_pubkey", hex);
    UniValue access(UniValue::VOBJ);
    access.pushKV("access_kind", "MODEL_ACCESS");
    access.pushKV("period_ms", 1'800'000);
    UniValue rights(UniValue::VARR);
    rights.push_back("USE");
    access.pushKV("rights", rights);
    offer.pushKV("access", access);
    UniValue settlement(UniValue::VOBJ);
    settlement.pushKV("profile_id", profile);
    settlement.pushKV("required_p1e_microunits", 1000);
    settlement.pushKV("schedule", "PREPAID");
    UniValue modes(UniValue::VARR);
    modes.push_back("USEFUL_JOB_RECEIPTS");
    settlement.pushKV("allowed_settlement_modes", modes);
    settlement.pushKV("qualification_required", false);
    UniValue classes(UniValue::VARR);
    classes.push_back("REGTEST_DETERMINISTIC");
    settlement.pushKV("allowed_job_classes", classes);
    UniValue sched(UniValue::VARR);
    sched.push_back(hex);
    settlement.pushKV("authorized_job_scheduler_pubkeys", sched);
    UniValue issuers(UniValue::VARR);
    issuers.push_back(hex);
    settlement.pushKV("authorized_receipt_issuer_pubkeys", issuers);
    offer.pushKV("settlement", settlement);
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("transferable", false);
    policy.pushKV("cash_redeemable", false);
    policy.pushKV("cross_agreement_credit", false);
    policy.pushKV("carryover", false);
    offer.pushKV("policy", policy);

    UniValue create_offer(UniValue::VOBJ);
    create_offer.pushKV("offer", offer);
    create_offer.pushKV("now_ms", 1000);
    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", ComputeCall(issuer, "createcomputeoffer", create_offer)["offer_id"]);
    agr.pushKV("subject_pubkey", hex);
    agr.pushKV("period_start_ms", 1000);
    agr.pushKV("period_end_ms", 5000);
    agr.pushKV("now_ms", 1000);
    const UniValue agreement = ComputeCall(issuer, "issuecomputeagreement", agr);

    UniValue job(UniValue::VOBJ);
    job.pushKV("agreement_id", agreement["agreement_id"]);
    job.pushKV("subject_pubkey", hex);
    job.pushKV("job_class", "REGTEST_DETERMINISTIC");
    job.pushKV("credit_p1e_microunits", 1000);
    job.pushKV("input_commitment", "in-verify");
    job.pushKV("executor_spec_commitment", "regtest-runner");
    job.pushKV("expires_at_ms", 4000);
    job.pushKV("nonce", "job-verify");
    job.pushKV("now_ms", 1100);
    UniValue res(UniValue::VOBJ);
    res.pushKV("job_id", ComputeCall(issuer, "createcomputejob", job)["job_id"]);
    res.pushKV("output_commitment", "out-verify");
    res.pushKV("now_ms", 1200);
    UniValue acc(UniValue::VOBJ);
    acc.pushKV("result_id", ComputeCall(issuer, "submitcomputejobresult", res)["result_id"]);
    acc.pushKV("expected_output_commitment", "out-verify");
    acc.pushKV("now_ms", 1300);
    const UniValue receipt = ComputeCall(issuer, "acceptcomputejobresult", acc);

    UniValue junk(UniValue::VOBJ);
    UniValue junk_env(UniValue::VOBJ);
    junk_env.pushKV("junk", 1);
    junk.pushKV("envelope", junk_env);
    BOOST_CHECK(ComputeFail(reader, "verifycomputereceipt", junk, "COMPUTE_RECORD_INVALID"));
    const UniValue empty_list = ComputeCall(reader, "listcomputereceipts", UniValue(UniValue::VOBJ));
    BOOST_CHECK_EQUAL(empty_list["records"].size(), 0U);

    UniValue ia(UniValue::VOBJ);
    ia.pushKV("envelope", agreement);
    ComputeCall(reader, "importcomputeagreement", ia);
    UniValue gj(UniValue::VOBJ);
    gj.pushKV("id", receipt["body"]["payload"]["job_id"]);
    const UniValue stored_job = ComputeCall(issuer, "getcomputejob", gj);
    UniValue ij(UniValue::VOBJ);
    ij.pushKV("envelope", stored_job);
    ij.pushKV("now_ms", 1400);
    ComputeCall(reader, "importcomputejob", ij);

    UniValue vr(UniValue::VOBJ);
    vr.pushKV("envelope", receipt);
    const UniValue checked = ComputeCall(reader, "verifycomputereceipt", vr);
    BOOST_CHECK(checked["accepted"].isTrue());
    BOOST_CHECK(checked["persisted"].isFalse());
    BOOST_CHECK_EQUAL(checked["agreement_id"].get_str(), agreement["agreement_id"].get_str());
    BOOST_CHECK_EQUAL(checked["credited_p1e_microunits"].getInt<uint64_t>(), 1000U);
    BOOST_CHECK(!checked["receipt_id"].get_str().empty());
    const UniValue still_empty = ComputeCall(reader, "listcomputereceipts", UniValue(UniValue::VOBJ));
    BOOST_CHECK_EQUAL(still_empty["records"].size(), 0U);
    UniValue get(UniValue::VOBJ);
    get.pushKV("id", checked["receipt_id"].get_str());
    BOOST_CHECK(ComputeFail(reader, "getcomputereceipt", get, "COMPUTE_RECORD_INVALID"));

    ComputeCall(reader, "importcomputereceipt", vr);
    const UniValue listed = ComputeCall(reader, "listcomputereceipts", UniValue(UniValue::VOBJ));
    BOOST_CHECK_EQUAL(listed["records"].size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
