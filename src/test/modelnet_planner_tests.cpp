// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/records.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_planner_tests, BasicTestingSetup)

namespace {

void FillBuyer(modelnet::Digest48& buyer)
{
    for (size_t i = 0; i < buyer.data.size(); ++i) buyer.data[i] = static_cast<unsigned char>(0x11);
}

modelnet::SignedFreeGrant IssueSample(const std::vector<unsigned char>& sk,
                                        const std::vector<unsigned char>& pk,
                                        const modelnet::Digest48& buyer,
                                        const modelnet::Digest48& model,
                                        const modelnet::Digest48& artifact,
                                        uint32_t first_piece,
                                        uint32_t piece_count)
{
    modelnet::FreeGrantParams p;
    p.buyer_id = buyer;
    p.model_id = model;
    p.artifact_id = artifact;
    p.file_index = 0;
    p.first_piece = first_piece;
    p.piece_count = piece_count;
    p.maximum_bytes = uint64_t{piece_count} * 64;
    p.queue_class = 0;
    modelnet::SignedFreeGrant g;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::IssueFreeGrant(p, sk, pk, g, err), err);
    return g;
}

} // namespace

BOOST_AUTO_TEST_CASE(v11_free_02)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::Digest48 buyer, model, artifact;
    FillBuyer(buyer);
    model = buyer;
    artifact = buyer;
    artifact.data[0] = 0x22;
    const auto g = IssueSample(sk, pk, buyer, model, artifact, /*first_piece=*/1, /*piece_count=*/4);
    BOOST_CHECK(!modelnet::GrantHasPaymentFields(g.body));
    BOOST_CHECK_EQUAL(g.body["buyer_id"].get_str(), buyer.Hex());
    BOOST_CHECK_EQUAL(g.body["model_id"].get_str(), model.Hex());
    BOOST_CHECK_EQUAL(g.body["artifact_id"].get_str(), artifact.Hex());
    BOOST_CHECK_EQUAL(g.body["first_piece"].getInt<uint32_t>(), 1U);
    BOOST_CHECK_EQUAL(g.body["piece_count"].getInt<uint32_t>(), 4U);
    BOOST_CHECK_EQUAL(g.body["signer_role"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(g.body["signer_id"].get_str(), modelnet::ServiceSignerId(pk).Hex());
    UniValue decoded;
    BOOST_REQUIRE(modelnet::VerifyFreeGrant(g.payload, g.signature, pk, 0, {}, decoded, err));
    BOOST_CHECK_EQUAL(decoded["buyer_id"].get_str(), buyer.Hex());
    BOOST_CHECK_EQUAL(decoded["first_piece"].getInt<uint32_t>(), 1U);

    const fs::path tmp = m_path_root / "v11-free-02";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    UniValue req(UniValue::VOBJ);
    req.pushKV("model_id", imported.model_id.Hex());
    req.pushKV("buyer_id", buyer.Hex());
    req.pushKV("first_piece", 0);
    req.pushKV("piece_count", 1);
    nreq.body = req.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    UniValue gj;
    BOOST_REQUIRE(gj.read(nresp.body));
    BOOST_CHECK(gj["signed"].get_bool());
    BOOST_CHECK(gj.exists("payload_hex"));
    BOOST_CHECK(gj.exists("sig_hex"));
    BOOST_CHECK(!gj.exists("price_atoms"));
    BOOST_CHECK(!gj.exists("address"));
    const auto payload = TryParseHex<unsigned char>(gj["payload_hex"].get_str());
    const auto sig = TryParseHex<unsigned char>(gj["sig_hex"].get_str());
    const auto gpk = TryParseHex<unsigned char>(gj["pubkey_hex"].get_str());
    BOOST_REQUIRE(payload && sig && gpk);
    UniValue http_body;
    BOOST_REQUIRE(modelnet::VerifyFreeGrant(*payload, *sig, *gpk, 0, {}, http_body, err));
    BOOST_CHECK_EQUAL(http_body["buyer_id"].get_str(), buyer.Hex());
    BOOST_CHECK_EQUAL(http_body["model_id"].get_str(), imported.model_id.Hex());
    BOOST_CHECK_EQUAL(http_body["artifact_id"].get_str(), imported.artifact_id.Hex());
}

BOOST_AUTO_TEST_CASE(v11_free_03)
{
    std::vector<unsigned char> pk, sk, other_pk, other_sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(other_pk, other_sk, err));
    modelnet::Digest48 buyer;
    FillBuyer(buyer);
    const auto g = IssueSample(sk, pk, buyer, buyer, buyer, 0, 1);
    const int64_t issued = g.body["issued_at"].getInt<int64_t>();
    const int64_t expires = g.body["expires_at"].getInt<int64_t>();
    BOOST_CHECK(expires - issued <= modelnet::FREE_GRANT_LIFETIME_S);

    modelnet::GrantRejectReason reason = modelnet::GrantRejectReason::NONE;
    BOOST_CHECK(!modelnet::RejectExpiredTamperedReplay(g.payload, g.signature, pk, issued + 1, {}, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::NONE);

    BOOST_REQUIRE(modelnet::RejectExpiredTamperedReplay(g.payload, g.signature, pk, expires + 1, {}, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::EXPIRED);
    UniValue body;
    BOOST_CHECK(!modelnet::VerifyFreeGrant(g.payload, g.signature, pk, expires + 1, {}, body, err));

    auto tampered = g.payload;
    BOOST_REQUIRE(!tampered.empty());
    tampered.back() ^= 0x01;
    BOOST_REQUIRE(modelnet::RejectExpiredTamperedReplay(tampered, g.signature, pk, issued + 1, {}, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::TAMPERED);

    BOOST_REQUIRE(modelnet::RejectExpiredTamperedReplay(g.payload, g.signature, other_pk, issued + 1, {}, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::TAMPERED);

    std::set<std::string> seen{g.body["grant_nonce"].get_str()};
    BOOST_REQUIRE(modelnet::RejectExpiredTamperedReplay(g.payload, g.signature, pk, issued + 1, seen, reason, err));
    BOOST_CHECK(reason == modelnet::GrantRejectReason::REPLAY);

    const fs::path tmp = m_path_root / "v11-free-03";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    const std::string nonce(64, 'a');
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.body = std::string("{\"model_id\":\"") + imported.model_id.Hex() + "\",\"grant_nonce\":\"" + nonce + "\"}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 409);

    nreq.body = std::string("{\"model_id\":\"") + imported.model_id.Hex() + "\",\"expires_at\":1}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 400);
}

BOOST_AUTO_TEST_CASE(v11_free_04)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::Digest48 buyer;
    FillBuyer(buyer);
    const auto g = IssueSample(sk, pk, buyer, buyer, buyer, 0, 1);
    BOOST_CHECK(!modelnet::GrantHasPaymentFields(g.body));
    BOOST_CHECK(!modelnet::GrantHasPaymentFields(modelnet::SignedGrantToJson(g)));
    UniValue pay(UniValue::VOBJ);
    pay.pushKV("price_atoms", 0);
    BOOST_CHECK(modelnet::GrantHasPaymentFields(pay));
    UniValue addr(UniValue::VOBJ);
    addr.pushKV("address", "bc1qexample");
    BOOST_CHECK(modelnet::GrantHasPaymentFields(addr));
    UniValue fee(UniValue::VOBJ);
    fee.pushKV("fee_atoms", 1);
    BOOST_CHECK(modelnet::GrantHasPaymentFields(fee));
    UniValue conf(UniValue::VOBJ);
    conf.pushKV("chain_confirmation", 6);
    BOOST_CHECK(modelnet::GrantHasPaymentFields(conf));

    const fs::path tmp = m_path_root / "v11-free-04";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.body = std::string("{\"model_id\":\"") + imported.model_id.Hex() + "\",\"price_atoms\":0}";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 400);
}

BOOST_AUTO_TEST_CASE(v11_free_06)
{
    std::vector<modelnet::PieceNeed> missing(3);
    for (uint32_t i = 0; i < 3; ++i) missing[i].piece_index = i;
    std::vector<modelnet::SourceOffer> src;
    modelnet::SourceOffer paid;
    paid.peer = "paid";
    paid.paid = true;
    paid.price_atoms = 50;
    paid.fee_atoms = 5;
    paid.available = true;
    src.push_back(paid);
    auto plan = modelnet::PlanRetrieval(missing, src, modelnet::RetrievalMode::FREE_ONLY, 1'000'000, /*approved=*/true);
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.paid_atoms, 0);
    BOOST_CHECK(plan.wait_free);

    modelnet::PaidPlan pp;
    pp.price_atoms = 10;
    pp.fee_atoms = 10;
    pp.total_eta_s = 1;
    modelnet::PlanChoice choice;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, 50'000, &pp, 100000, true, 1, 1000, true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::FREE);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, &pp, 100000, true, 1, 1000, true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
}

BOOST_AUTO_TEST_CASE(v11_free_07)
{
    std::vector<modelnet::PieceNeed> missing(4);
    for (uint32_t i = 0; i < 4; ++i) missing[i].piece_index = i;
    modelnet::SourceOffer free;
    free.peer = "free";
    free.paid = false;
    free.available = true;
    free.first_piece = 0;
    free.piece_count = 3;
    modelnet::SourceOffer paid;
    paid.peer = "paid";
    paid.paid = true;
    paid.price_atoms = 90;
    paid.fee_atoms = 10;
    paid.available = true;
    paid.piece_count = 0;
    auto plan = modelnet::PlanRetrieval(missing, {free, paid}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 100, false);
    BOOST_CHECK_EQUAL(plan.free_pieces.size(), 3U);
    BOOST_CHECK_EQUAL(plan.paid_pieces.size(), 1U);
    BOOST_CHECK_EQUAL(plan.paid_pieces[0].piece_index, 3U);
    BOOST_CHECK_EQUAL(plan.paid_atoms, 100);

    auto over = modelnet::PlanRetrieval(missing, {free, paid}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 99, false);
    BOOST_CHECK(over.paid_pieces.empty());
    BOOST_CHECK_EQUAL(over.paid_atoms, 0);

    auto approval = modelnet::PlanRetrieval(missing, {free, paid}, modelnet::RetrievalMode::FREE_FIRST_APPROVAL, 100, false);
    BOOST_CHECK_EQUAL(approval.free_pieces.size(), 3U);
    BOOST_CHECK(approval.paid_pieces.empty());
}

BOOST_AUTO_TEST_CASE(v11_free_08)
{
    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(10, 600, 100, 30), 640);
    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(10, 600, 0, 30), 10);
    BOOST_CHECK(modelnet::EtaWithFees(10, 600, 100, 30) > modelnet::EtaWithFees(10, 0, 0, 0));
    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(-1, 1, 1, 1), -1);
    modelnet::PaidPlan paid;
    paid.price_atoms = 1;
    paid.fee_atoms = 1;
    paid.total_eta_s = modelnet::EtaWithFees(0, 200, 1, 0);
    modelnet::PlanChoice choice;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, 1000, &paid, 100, true, 100, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::FREE);
}

BOOST_AUTO_TEST_CASE(v11_free_09)
{
    std::vector<modelnet::PieceNeed> missing(2);
    missing[0].piece_index = 0;
    missing[1].piece_index = 1;
    auto plan = modelnet::PlanRetrieval(missing, {}, modelnet::RetrievalMode::FREE_FIRST_BUDGET, 1'000'000'000, true);
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.paid_atoms, 0);
    BOOST_CHECK(plan.unknown_eta);
    BOOST_CHECK(plan.wait_free);

    modelnet::PlanChoice choice;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, nullptr, 100000, true, std::nullopt, 0, true, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
}

BOOST_AUTO_TEST_CASE(v11_free_10)
{
    modelnet::HybridPlan plan;
    modelnet::PieceNeed a, b;
    a.piece_index = 7;
    b.piece_index = 8;
    plan.paid_pieces = {a, b};
    plan.paid_atoms = 50;
    modelnet::PieceNeed arrived = a;
    arrived.verified = true;
    modelnet::InvalidatePaidWhenFreeArrives(plan, {arrived});
    BOOST_CHECK(plan.stale_paid);
    BOOST_CHECK_EQUAL(plan.paid_atoms, 0);
    BOOST_REQUIRE_EQUAL(plan.paid_pieces.size(), 1U);
    BOOST_CHECK_EQUAL(plan.paid_pieces[0].piece_index, 8U);

    arrived = b;
    arrived.verified = true;
    modelnet::InvalidatePaidWhenFreeArrives(plan, {arrived});
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.paid_atoms, 0);
}

BOOST_AUTO_TEST_CASE(v11_free_12)
{
    modelnet::Quote paid;
    paid.price_atoms = 42;
    paid.fee_cap_atoms = 3;
    UniValue requester(UniValue::VOBJ);
    requester.pushKV("price_atoms", 0);
    BOOST_CHECK(!modelnet::QuoteMayBeTakenAsFree(paid, requester));
    modelnet::Quote z;
    BOOST_CHECK(modelnet::QuoteMayBeTakenAsFree(z, requester));

    const fs::path tmp = m_path_root / "v11-free-12";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    std::vector<modelnet::Quote> quotes;
    std::vector<modelnet::PaymentJournal> journal;
    std::string err;
    modelnet::Digest48 mid;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(std::string(96, '1'), mid, err));
    BOOST_REQUIRE(modelnet::MakePrepaidQuote(paid, mid, mid, 0, 2, 42, err));
    paid.fee_cap_atoms = 3;
    quotes.push_back(paid);
    BOOST_REQUIRE(modelnet::SavePaymentState(tmp, quotes, journal, err));
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodel");
    UniValue params(UniValue::VARR);
    params.push_back(mid.Hex());
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("retrieval_policy", "FREE_FIRST_BUDGET");
    opts.pushKV("price_atoms", 0);
    opts.pushKV("max_atoms", 1000);
    params.push_back(opts);
    rpc.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK(result.exists("bypass_rejected") && result["bypass_rejected"].get_bool());
}

BOOST_AUTO_TEST_CASE(v11_free_13)
{
    modelnet::Quote approved;
    std::string err;
    BOOST_REQUIRE(modelnet::MakePrepaidQuote(approved, modelnet::Digest48{}, modelnet::Digest48{}, 0, 4, 10, err));
    approved.fee_cap_atoms = 2;
    modelnet::Quote same = approved;
    BOOST_CHECK(!modelnet::QuoteMutationRequiresReapproval(approved, same));
    modelnet::Quote mutated = approved;
    mutated.price_atoms = 11;
    BOOST_CHECK(modelnet::QuoteMutationRequiresReapproval(approved, mutated));
    mutated = approved;
    mutated.fee_cap_atoms = 9;
    BOOST_CHECK(modelnet::QuoteMutationRequiresReapproval(approved, mutated));
    mutated = approved;
    mutated.piece_count = 8;
    BOOST_CHECK(modelnet::QuoteMutationRequiresReapproval(approved, mutated));
}

BOOST_AUTO_TEST_CASE(v11_free_grant_piece_headers)
{
    std::string err;
    const fs::path tmp = m_path_root / "v11-free-grant-piece-headers";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    UniValue req(UniValue::VOBJ);
    req.pushKV("model_id", imported.model_id.Hex());
    req.pushKV("first_piece", 0);
    req.pushKV("piece_count", 1);
    nreq.body = req.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_REQUIRE_EQUAL(nresp.status, 200);
    UniValue gj;
    BOOST_REQUIRE(gj.read(nresp.body));
    BOOST_REQUIRE(gj.exists("payload_hex") && gj.exists("sig_hex") && gj.exists("pubkey_hex"));

    nreq = {};
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    nreq.headers.emplace_back("X-BTX-Grant-Payload", gj["payload_hex"].get_str());
    nreq.headers.emplace_back("X-BTX-Grant-Sig", gj["sig_hex"].get_str());
    nreq.headers.emplace_back("X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str());
    size_t grant_hdr = nreq.method.size() + nreq.path.size() + 32;
    for (const auto& h : nreq.headers) grant_hdr += h.first.size() + h.second.size() + 4;
    BOOST_CHECK_LT(grant_hdr, modelnet::PQ1_HTTP_HEADER_CAP);
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    BOOST_CHECK_EQUAL(nresp.content_type, "application/octet-stream");
    BOOST_CHECK_EQUAL(nresp.body.size(), st.size());

    std::string tampered_sig = gj["sig_hex"].get_str();
    BOOST_REQUIRE(!tampered_sig.empty());
    tampered_sig.back() = (tampered_sig.back() == '0') ? '1' : '0';
    nreq.headers.clear();
    nreq.headers.emplace_back("X-BTX-Grant-Payload", gj["payload_hex"].get_str());
    nreq.headers.emplace_back("X-BTX-Grant-Sig", tampered_sig);
    nreq.headers.emplace_back("X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str());
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(v11_getmodel_job_rpc)
{
    std::string err;
    const fs::path tmp = m_path_root / "v11-getmodel-job-rpc";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", "getmodeljob");
    rpc.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK_EQUAL(result["schema_version"].getInt<int>(), 2);
    BOOST_REQUIRE(result.exists("jobs"));
    BOOST_CHECK(result["jobs"].isArray());
    BOOST_CHECK_EQUAL(result["jobs"].size(), 0);
    BOOST_REQUIRE(result.exists("used_bytes"));
    BOOST_CHECK(result["used_bytes"].isNum());
    BOOST_CHECK_EQUAL(result["used_bytes"].getInt<int64_t>(), static_cast<int64_t>(cat.UsedBytes()));

    rpc.pushKV("method", "cancelmodeljob");
    result = UniValue();
    code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, rpc, result, code, err));
    BOOST_CHECK(result.isObject());
}

BOOST_AUTO_TEST_CASE(retrieve_job_is_newer)
{
    // Later created_ms wins regardless of job_id.
    BOOST_CHECK(modelnet::RetrieveJobIsNewer(300, "aa", 200, "zz"));
    BOOST_CHECK(!modelnet::RetrieveJobIsNewer(100, "zz", 200, "aa"));
    // Equal timestamps: larger job_id wins.
    BOOST_CHECK(modelnet::RetrieveJobIsNewer(5, "b", 5, "a"));
    BOOST_CHECK(!modelnet::RetrieveJobIsNewer(5, "a", 5, "b"));
    BOOST_CHECK(modelnet::RetrieveJobIsNewer(5, "job-10", 5, "job-09"));
    std::vector<std::pair<int64_t, std::string>> recs{{100, "aa"}, {300, "bb"}, {200, "cc"}, {300, "zz"}};
    std::sort(recs.begin(), recs.end(), [](const auto& a, const auto& b) {
        return modelnet::RetrieveJobIsNewer(a.first, a.second, b.first, b.second);
    });
    BOOST_CHECK_EQUAL(recs[0].second, "zz");
    BOOST_CHECK_EQUAL(recs[1].second, "bb");
    BOOST_CHECK_EQUAL(recs[2].second, "cc");
    BOOST_CHECK_EQUAL(recs[3].second, "aa");
}

BOOST_AUTO_TEST_SUITE_END()
