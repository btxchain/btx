// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11 matrix id -> BOOST_AUTO_TEST_CASE
// V11-FREE-01  v11_free_01
// V11-FREE-05  v11_free_05
// V11-FREE-11  v11_free_11
// V11-FREE-14  v11_free_14
// V11-FREE-15  v11_free_15

#include <test/util/setup_common.h>

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/policy.h>
#include <modelnet/protocol.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <optional>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_free_remaining_tests, BasicTestingSetup)

namespace {

void WriteTinySafetensors(const fs::path& src)
{
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    std::ofstream out(src / "model.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    BOOST_REQUIRE(out.good());
}

bool PlanIsFreeOrLocal(const UniValue& result)
{
    const std::string plan = result.exists("plan") ? result["plan"].get_str() : "";
    const std::string status = result.exists("status") ? result["status"].get_str() : "";
    return plan == "FREE" || plan == "local" || status == "local";
}

} // namespace

BOOST_AUTO_TEST_CASE(v11_free_01)
{
    // Identity-only catalog: no wallet, no peers. FREE_ONLY getmodel of a local import.
    std::string err;
    const fs::path tmp = m_path_root / "v11-free-01";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    WriteTinySafetensors(tmp / "src");
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));
    BOOST_CHECK(cat.Peers().empty());

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    params.push_back("FREE_ONLY");
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK(PlanIsFreeOrLocal(result));
    BOOST_REQUIRE(result.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(result["paid_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(result["paid_piece_count"].getInt<int>(), 0);
    BOOST_CHECK(!result.exists("bypass_rejected"));
    BOOST_CHECK(result["plan"].get_str() != "PAID");
    BOOST_CHECK(result["plan"].get_str() != "APPROVAL_REQUIRED");
}

BOOST_AUTO_TEST_CASE(v11_free_05)
{
    std::string err;
    const fs::path tmp = m_path_root / "v11-free-05";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    WriteTinySafetensors(tmp / "src");
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));

    modelnet::Quote zero;
    BOOST_REQUIRE(modelnet::MakePrepaidQuote(zero, imported.model_id, imported.artifact_id, 0, 1, 0, err));
    BOOST_CHECK_EQUAL(zero.price_atoms, 0);
    BOOST_CHECK_EQUAL(zero.fee_cap_atoms, 0);
    UniValue requester(UniValue::VOBJ);
    requester.pushKV("price_atoms", 0);
    BOOST_CHECK(modelnet::QuoteMayBeTakenAsFree(zero, requester));
    modelnet::Quote paid;
    BOOST_REQUIRE(modelnet::MakePrepaidQuote(paid, imported.model_id, imported.artifact_id, 0, 1, 42, err));
    BOOST_CHECK(!modelnet::QuoteMayBeTakenAsFree(paid, requester));

    std::vector<modelnet::Quote> quotes{zero};
    std::vector<modelnet::PaymentJournal> journal;
    const fs::path paydir = cat.Store().Root().parent_path();
    BOOST_REQUIRE(modelnet::SavePaymentState(paydir, quotes, journal, err));

    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodel");
    UniValue params(UniValue::VARR);
    params.push_back(imported.model_id.Hex());
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("price_atoms", 0);
    params.push_back(opts);
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK(PlanIsFreeOrLocal(result));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result["plan"].get_str() != "APPROVAL_REQUIRED");
    BOOST_CHECK(!result.exists("bypass_rejected") || !result["bypass_rejected"].get_bool());
}

BOOST_AUTO_TEST_CASE(v11_free_11)
{
    std::vector<modelnet::PaymentJournal> journal;
    BOOST_CHECK(!modelnet::DuplicatePayment(journal, "aa11bb22"));
    journal.push_back({"offer-1", "aa11bb22", /*accepted=*/false, /*delivered=*/false});
    BOOST_CHECK(modelnet::DuplicatePayment(journal, "aa11bb22"));
    BOOST_CHECK(!modelnet::DuplicatePayment(journal, "cc33dd44"));

    journal.back().file_index = 0;
    journal.back().first_piece = 2;
    journal.back().piece_count = 3;

    BOOST_CHECK(!modelnet::RangesOverlap(0, 0, 0, 0, 0, 4));
    BOOST_CHECK(!modelnet::RangesOverlap(0, 0, 4, 1, 0, 4));
    BOOST_CHECK(!modelnet::RangesOverlap(0, 0, 4, 0, 4, 4));
    BOOST_CHECK(modelnet::RangesOverlap(0, 0, 4, 0, 3, 2));
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 3, 2));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(journal, 0, 5, 2));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(journal, 1, 2, 3));
    modelnet::PaymentJournal no_range;
    no_range.txid = "no-range";
    BOOST_CHECK(!modelnet::DuplicateReservedRange({no_range}, 0, 0, 4));

    std::string err;
    const fs::path tmp = m_path_root / "v11-free-11";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    WriteTinySafetensors(tmp / "src");
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));

    const fs::path paydir = cat.Store().Root().parent_path();
    BOOST_REQUIRE(modelnet::SavePaymentState(paydir, {}, journal, err));
    std::vector<modelnet::Quote> loaded_quotes;
    std::vector<modelnet::PaymentJournal> restarted;
    BOOST_REQUIRE(modelnet::LoadPaymentState(paydir, loaded_quotes, restarted, err));
    BOOST_CHECK(modelnet::DuplicatePayment(restarted, "aa11bb22"));
    BOOST_REQUIRE_EQUAL(restarted.size(), 1U);
    BOOST_CHECK_EQUAL(restarted[0].file_index, 0U);
    BOOST_CHECK_EQUAL(restarted[0].first_piece, 2U);
    BOOST_CHECK_EQUAL(restarted[0].piece_count, 3U);
    BOOST_CHECK(modelnet::DuplicateReservedRange(restarted, 0, 4, 1));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(restarted, 0, 5, 1));

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = std::string(modelnet::MODEL_HTTP_ROOT) + "transfers/" + imported.artifact_id.Hex() + "/payment";
    nreq.body = "{\"quote_id\":\"offer-1\",\"txid\":\"aa11bb22\"}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 409);

    nreq.body = "{\"quote_id\":\"offer-1\",\"txid\":\"ee55ff66\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 409);

    modelnet::PieceNeed reserved;
    BOOST_CHECK(!reserved.reserved_paid);
    reserved.piece_index = 3;
    reserved.reserved_paid = true;
    BOOST_REQUIRE(reserved.reserved_paid);
    modelnet::HybridPlan plan;
    plan.paid_pieces.push_back(reserved);
    BOOST_REQUIRE_EQUAL(plan.paid_pieces.size(), 1U);
    BOOST_CHECK(plan.paid_pieces[0].reserved_paid);
    BOOST_CHECK_EQUAL(plan.paid_pieces[0].piece_index, 3U);

    std::vector<modelnet::PieceNeed> missing(1);
    missing[0].piece_index = 3;
    modelnet::SourceOffer paid;
    paid.peer = "paid";
    paid.paid = true;
    paid.price_atoms = 50;
    paid.available = true;
    paid.piece_count = 0;
    auto newly = modelnet::PlanRetrieval(missing, {paid}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 50, true);
    BOOST_REQUIRE_EQUAL(newly.paid_pieces.size(), 1U);
    BOOST_CHECK(newly.paid_pieces[0].reserved_paid);
    BOOST_CHECK_EQUAL(newly.paid_pieces[0].piece_index, 3U);
    BOOST_CHECK_EQUAL(newly.paid_atoms, 50);

    missing[0].reserved_paid = true;
    auto again = modelnet::PlanRetrieval(missing, {paid}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 50, true);
    BOOST_REQUIRE_EQUAL(again.paid_pieces.size(), 1U);
    BOOST_CHECK(again.paid_pieces[0].reserved_paid);
    BOOST_CHECK_EQUAL(again.paid_pieces[0].piece_index, 3U);
    BOOST_CHECK_EQUAL(again.paid_atoms, 0);
}

BOOST_AUTO_TEST_CASE(v11_free_14)
{
    std::vector<modelnet::PieceNeed> missing(2);
    missing[0].piece_index = 0;
    missing[1].piece_index = 1;

    modelnet::SourceOffer a;
    a.peer = "paid-a";
    a.paid = true;
    a.available = true;
    a.price_atoms = 50;
    a.fee_atoms = 20;
    a.first_piece = 0;
    a.piece_count = 1;
    a.queue_s = 10;
    a.conf_s = 600;
    a.mempool_s = 30;

    modelnet::SourceOffer b;
    b.peer = "paid-b";
    b.paid = true;
    b.available = true;
    b.price_atoms = 50;
    b.fee_atoms = 20;
    b.first_piece = 1;
    b.piece_count = 1;
    b.queue_s = 7;
    b.conf_s = 100;
    b.mempool_s = 5;

    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(a.queue_s, a.conf_s, a.fee_atoms, a.mempool_s), 640);
    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(b.queue_s, b.conf_s, b.fee_atoms, b.mempool_s), 112);
    BOOST_CHECK(modelnet::EtaWithFees(a.queue_s, a.conf_s, a.fee_atoms, a.mempool_s) >
                modelnet::EtaWithFees(b.queue_s, b.conf_s, b.fee_atoms, b.mempool_s));

    auto over = modelnet::PlanRetrieval(missing, {a, b}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 100, true);
    BOOST_CHECK(over.paid_pieces.empty());
    BOOST_CHECK_EQUAL(over.paid_atoms, 0);
    BOOST_CHECK(over.wait_free);
    BOOST_CHECK_EQUAL(over.eta_s, modelnet::EtaWithFees(a.queue_s, a.conf_s, a.fee_atoms, a.mempool_s));

    auto fits = modelnet::PlanRetrieval(missing, {a, b}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 140, true);
    BOOST_CHECK_EQUAL(fits.paid_pieces.size(), 2U);
    BOOST_CHECK_EQUAL(fits.paid_atoms, 140);
    BOOST_CHECK_EQUAL(fits.eta_s, modelnet::EtaWithFees(a.queue_s, a.conf_s, a.fee_atoms, a.mempool_s));

    auto over_outstanding = modelnet::PlanRetrieval(missing, {a, b}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 140, true,
                                                    /*outstanding_paid_atoms=*/1);
    BOOST_CHECK(over_outstanding.paid_pieces.empty());
    BOOST_CHECK_EQUAL(over_outstanding.paid_atoms, 0);
    BOOST_CHECK(over_outstanding.wait_free);
}

BOOST_AUTO_TEST_CASE(v11_free_15)
{
    modelnet::PaidPlan release;
    release.price_atoms = 1;
    release.fee_atoms = 1;
    release.total_eta_s = 1;
    release.safe = true;
    release.deliverable = true;
    release.requires_release = true;

    const modelnet::RetrievalMode modes[] = {
        modelnet::RetrievalMode::FREE_ONLY,
        modelnet::RetrievalMode::FREE_FIRST_APPROVAL,
        modelnet::RetrievalMode::FREE_FIRST_BUDGET,
        modelnet::RetrievalMode::EXPLICIT_PAID,
    };
    const std::optional<int> etas[] = {std::nullopt, 50};
    for (const auto mode : modes) {
        for (const auto& free_eta : etas) {
            modelnet::PlanChoice choice;
            std::string err;
            BOOST_REQUIRE(modelnet::ChoosePlan(mode, free_eta, &release, 1'000'000, true, 1, 1000, true, choice, err));
            BOOST_CHECK(choice != modelnet::PlanChoice::PAID);
            BOOST_CHECK(choice == modelnet::PlanChoice::FREE || choice == modelnet::PlanChoice::WAIT_FREE);
        }
    }

    modelnet::PaidPlan no_release = release;
    no_release.requires_release = false;
    modelnet::PlanChoice paid_ok;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &no_release, 1'000'000, true, 1, 1000, true, paid_ok, err));
    BOOST_CHECK(paid_ok == modelnet::PlanChoice::PAID);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &release, 1'000'000, true, 1, 1000, true, paid_ok, err));
    BOOST_CHECK(paid_ok != modelnet::PlanChoice::PAID);
    BOOST_CHECK(paid_ok == modelnet::PlanChoice::WAIT_FREE);
}

BOOST_AUTO_TEST_SUITE_END()
