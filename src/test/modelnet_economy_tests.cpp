// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/catalog.h>
#include <modelnet/crypto.h>
#include <modelnet/economy.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/release.h>
#include <modelnet/search.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_SUITE_END()
