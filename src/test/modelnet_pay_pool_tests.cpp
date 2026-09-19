// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// B0 PAY-01..10 / POOL-01..14 / SCRIPT library negatives (no new opcodes).
// Chain inclusion is wallet_modelnet_funding.py + wallet_htlc_atomicswap.py.
//
// POOL-01  exact target / freeze amount
// PAY-05  reorg payment hold (ApplyPaymentDelivery)
// PAY-09  partial delivery (RemainingUndeliveredRange)
// POOL-02  all-input/all-output template (MatchFrozenTemplate)
// POOL-03  changed round invalidates fingerprint
// POOL-04  missing participant (empty claimant / refund)
// POOL-05  double-used input (DuplicatePayment)
// POOL-06  refund ownership (refund_pubkey in fingerprint)
// POOL-07  wrong key / HASH160 refuse
// POOL-08  key-valid / bad-model (plaintext_verified stays false)
// POOL-09  refund race (ValidRefundWindow)
// POOL-10  delayed signed funding vs refund_height
// POOL-11  coordinator loss (campaigns.json reload)
// POOL-12  secret leak / reorg (secret_retained false; secret_disclosed)
// POOL-13  cap enforcement (max_atoms, ExposureWithinCeiling)
// POOL-14  helper-absent recovery (wallet-only funding RPCs)

#include <crypto/common.h>
#include <modelnet/access_policy.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/policy.h>
#include <modelnet/protocol.h>
#include <modelnet/release.h>
#include <modelnet/resource_uri.h>
#include <modelnet/transfer.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#ifdef ENABLE_WALLET
#include <core_io.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <wallet/model_funding.h>
#endif

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_pay_pool_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors()
{
    const std::string json = "{}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat, const fs::path& dir)
{
    fs::create_directories(dir);
    const auto st = TinySafeTensors();
    {
        std::ofstream out(dir / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(dir), /*pin=*/true, imported, err), err);
    return imported;
}

modelnet::FrozenModelFunding SampleFunding()
{
    modelnet::FrozenModelFunding in;
    in.key_hash_hex = std::string(64, 'a');
    in.claimant = "claimant";
    in.refund_pubkey = "refund";
    in.refund_height = 2048;
    in.amount_atoms = 1000;
    in.max_atoms = 1000;
    return in;
}

} // namespace

BOOST_AUTO_TEST_CASE(pay_01_quote_json_zero_cannot_make_paid_free)
{
    modelnet::Quote q;
    q.price_atoms = 1000;
    UniValue req(UniValue::VOBJ);
    req.pushKV("price_atoms", 0);
    BOOST_CHECK(!modelnet::QuoteMayBeTakenAsFree(q, req));
    q.price_atoms = 0;
    BOOST_CHECK(modelnet::QuoteMayBeTakenAsFree(q, req));
}

BOOST_AUTO_TEST_CASE(pay_03_10_duplicate_txid_and_range)
{
    std::vector<modelnet::PaymentJournal> journal;
    modelnet::PaymentJournal a;
    a.txid = "aa";
    a.file_index = 0;
    a.first_piece = 0;
    a.piece_count = 4;
    journal.push_back(a);
    BOOST_CHECK(modelnet::DuplicatePayment(journal, "aa"));
    BOOST_CHECK(!modelnet::DuplicatePayment(journal, "bb"));
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 2, 2));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(journal, 0, 4, 2));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(journal, 1, 0, 4));
}

BOOST_AUTO_TEST_CASE(pay_02_quote_mutation_requires_reapproval)
{
    modelnet::Quote approved, observed;
    approved.price_atoms = 10;
    observed = approved;
    BOOST_CHECK(!modelnet::QuoteMutationRequiresReapproval(approved, observed));
    observed.price_atoms = 11;
    BOOST_CHECK(modelnet::QuoteMutationRequiresReapproval(approved, observed));
}

BOOST_AUTO_TEST_CASE(pay_06_eta_includes_fees)
{
    BOOST_CHECK(modelnet::EtaWithFees(1, 2, 1, 3) >= 6);
    BOOST_CHECK_EQUAL(modelnet::EtaWithFees(-1, 0, 0, 0), -1);
}

BOOST_AUTO_TEST_CASE(pool_13_caps_and_hash160_refused)
{
    const std::string desc = modelnet::HtlcSha256Descriptor(std::string(64, '1'), "22", 1024, "33");
    BOOST_CHECK(desc.find("htlc_sha256") != std::string::npos);
    BOOST_CHECK(desc.find("hash160") == std::string::npos);
    BOOST_CHECK(desc.find("HASH160") == std::string::npos);

    const fs::path tmp = m_path_root / "pay-pool-http";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::NativeRequest req;
    req.method = "POST";
    req.path = std::string(modelnet::MODEL_HTTP_ROOT) + "transfers/x/payment";
    req.body = "{\"txid\":\"aa\",\"quote_id\":\"q\"}";
    modelnet::NativeResponse resp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    // Unsigned/fake payment POST must be refused. HTTP 200 here is a real bug
    // (NativeResponse defaults to 200; do not treat journal-intent as success).
    BOOST_CHECK_NE(resp.status, 200);
    BOOST_CHECK_MESSAGE(resp.status == 400 || resp.status == 404,
                        "unsigned/fake payment POST must be 400 or 404, never 200; status=" +
                            std::to_string(resp.status));

    modelnet::AccessPolicy acl;
    BOOST_CHECK(!acl.WritesBanMan());
    BOOST_CHECK(!acl.AffectsMonetaryBan());
}

BOOST_AUTO_TEST_CASE(pay_04_08_buyer_bind_and_durable_journal)
{
    const fs::path tmp = m_path_root / "pay-durable";
    fs::create_directories(tmp);
    std::vector<modelnet::Quote> quotes;
    std::vector<modelnet::PaymentJournal> journal;
    modelnet::Quote q;
    q.price_atoms = 100;
    q.buyer_id.data[0] = 0x0A;
    quotes.push_back(q);
    modelnet::PaymentJournal j;
    j.txid = "aa11";
    j.quote_id = "q1";
    j.file_index = 0;
    j.first_piece = 0;
    j.piece_count = 1;
    journal.push_back(j);
    std::string err;
    BOOST_REQUIRE(modelnet::SavePaymentState(tmp, quotes, journal, err));
    std::vector<modelnet::Quote> quotes2;
    std::vector<modelnet::PaymentJournal> journal2;
    BOOST_REQUIRE(modelnet::LoadPaymentState(tmp, quotes2, journal2, err));
    BOOST_REQUIRE_EQUAL(journal2.size(), 1U);
    BOOST_CHECK(modelnet::DuplicatePayment(journal2, "aa11"));
    BOOST_CHECK(!modelnet::DuplicatePayment(journal2, "bb22"));
}

BOOST_AUTO_TEST_CASE(pay_07_helper_cannot_sign_or_verify_chain)
{
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["paid_chain_verify"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(caps["buildmodelhtlcclaim"].get_bool(), true);
    const fs::path tmp = m_path_root / "pay-helper";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "submitmodelfunding");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_CHECK(err.find("hex required") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(pay_05_reorg_payment_hold)
{
    modelnet::PaymentJournal e;
    e.txid = "aa11";
    e.quote_id = "q1";
    e.file_index = 0;
    e.first_piece = 0;
    e.piece_count = 4;
    std::string err;
    BOOST_CHECK(!modelnet::ApplyPaymentDelivery(e, /*reorg_hold_active=*/true, err));
    BOOST_CHECK(!e.delivered);
    BOOST_CHECK(e.held_for_reorg);
    BOOST_CHECK(err.find("reorg") != std::string::npos);

    std::vector<modelnet::PaymentJournal> journal{e};
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 0, 4));
    BOOST_REQUIRE(modelnet::ReleaseReorgHold(journal, "aa11", err));
    BOOST_CHECK(journal[0].delivered);
    BOOST_CHECK(!journal[0].held_for_reorg);
    BOOST_CHECK(!modelnet::ReleaseReorgHold(journal, "missing", err));
}

BOOST_AUTO_TEST_CASE(pay_09_partial_delivery)
{
    std::vector<modelnet::PaymentJournal> journal;
    modelnet::PaymentJournal first;
    first.txid = "aa";
    first.file_index = 0;
    first.first_piece = 0;
    first.piece_count = 2;
    first.delivered = true;
    journal.push_back(first);
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 0, 2));
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 0, 4));
    BOOST_CHECK(!modelnet::DuplicateReservedRange(journal, 0, 2, 2));
    uint32_t remain_first = 0, remain_count = 0;
    BOOST_REQUIRE(modelnet::RemainingUndeliveredRange(journal, 0, 0, 4, remain_first, remain_count));
    BOOST_CHECK_EQUAL(remain_first, 2U);
    BOOST_CHECK_EQUAL(remain_count, 2U);
    modelnet::PaymentJournal rest;
    rest.txid = "bb";
    rest.file_index = 0;
    rest.first_piece = remain_first;
    rest.piece_count = remain_count;
    rest.delivered = true;
    journal.push_back(rest);
    BOOST_CHECK(!modelnet::RemainingUndeliveredRange(journal, 0, 0, 4, remain_first, remain_count));
}

BOOST_AUTO_TEST_CASE(pool_01_exact_target_freeze)
{
    modelnet::FrozenModelFunding in = SampleFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK_EQUAL(out.amount_atoms, in.amount_atoms);
    BOOST_CHECK(out.descriptor.find("htlc_sha256") != std::string::npos);
    BOOST_CHECK(out.descriptor.find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(!out.fingerprint.empty());
}

BOOST_AUTO_TEST_CASE(pool_03_changed_round_invalidates_fingerprint)
{
    modelnet::FrozenModelFunding in = SampleFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(modelnet::FundingUnchanged(out, out, err));
    modelnet::FrozenModelFunding mutated = out;
    mutated.amount_atoms = 2000;
    mutated.fingerprint = modelnet::FundingFingerprint(mutated);
    BOOST_CHECK(!modelnet::FundingUnchanged(out, mutated, err));
    BOOST_CHECK(err.find("mutated") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(pool_04_missing_participant)
{
    modelnet::FrozenModelFunding in = SampleFunding();
    in.claimant.clear();
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    in = SampleFunding();
    in.refund_pubkey.clear();
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
}

BOOST_AUTO_TEST_CASE(pool_05_double_used_input)
{
    std::vector<modelnet::PaymentJournal> journal;
    modelnet::PaymentJournal a;
    a.txid = "same-txid";
    a.piece_count = 1;
    journal.push_back(a);
    BOOST_CHECK(modelnet::DuplicatePayment(journal, "same-txid"));
    BOOST_CHECK(modelnet::DuplicateReservedRange(journal, 0, 0, 1));
}

BOOST_AUTO_TEST_CASE(pool_06_refund_ownership_in_fingerprint)
{
    modelnet::FrozenModelFunding a = SampleFunding();
    modelnet::FrozenModelFunding b = a;
    b.refund_pubkey = "other-refund";
    BOOST_CHECK(modelnet::FundingFingerprint(a) != modelnet::FundingFingerprint(b));
    a.refund_height = 2048;
    b = a;
    b.refund_height = 4096;
    BOOST_CHECK(modelnet::FundingFingerprint(a) != modelnet::FundingFingerprint(b));
}

BOOST_AUTO_TEST_CASE(pool_07_wrong_key_hash160)
{
    modelnet::FrozenModelFunding in = SampleFunding();
    in.key_hash_hex = std::string(40, '1');
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("32-byte") != std::string::npos);
    modelnet::Hash32 h;
    BOOST_CHECK(!modelnet::Hash32::FromHex(std::string(40, 'a'), h, err));
}

BOOST_AUTO_TEST_CASE(pool_08_10_12_campaign_key_valid_not_useful)
{
    const fs::path tmp = m_path_root / "pool-campaign";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src");
    std::string uri, err, code;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, imported.model_id, uri, err));
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 7);
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back(uri);
    params.push_back(HexStr(Span{secret, 32}));
    params.push_back(100000);
    params.push_back(5000);
    req.pushKV("method", "createmodelrelease");
    req.pushKV("params", params);
    UniValue created;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, created, code, err), err);
    BOOST_CHECK_EQUAL(created["secret_retained"].get_bool(), false);
    BOOST_CHECK_EQUAL(created["plaintext_verified"].get_bool(), false);
    BOOST_CHECK_EQUAL(created["secret_disclosed"].get_bool(), false);
    BOOST_CHECK(created["claim"].get_str().find("buildhtlcclaim") != std::string::npos);
    BOOST_CHECK(created["claim"].get_str().find("htlc_sha256") != std::string::npos);
    const std::string release_id = created["release_id"].get_str();

    UniValue pledge(UniValue::VOBJ);
    UniValue pparams(UniValue::VARR);
    pparams.push_back(release_id);
    pparams.push_back(100);
    pledge.pushKV("method", "pledgemodelrelease");
    pledge.pushKV("params", pparams);
    UniValue pledged;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, pledge, pledged, code, err));
    BOOST_CHECK_EQUAL(pledged["pledged_atoms"].getInt<int64_t>(), 100);

    UniValue claim(UniValue::VOBJ);
    UniValue cparams(UniValue::VARR);
    cparams.push_back(uri);
    claim.pushKV("method", "claimmodelrelease");
    claim.pushKV("params", cparams);
    UniValue claimed;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, claim, claimed, code, err));
    BOOST_CHECK_EQUAL(claimed["use"].get_str(), "buildhtlcclaim");
    BOOST_CHECK_EQUAL(claimed["template"].get_str(), "htlc_sha256");

    // POOL-11: coordinator loss — reopen catalog dir; campaigns.json still loads.
    std::vector<modelnet::ReleaseCampaign> reloaded;
    BOOST_REQUIRE(modelnet::LoadCampaigns(tmp, reloaded, err));
    BOOST_REQUIRE_EQUAL(reloaded.size(), 1U);
    BOOST_CHECK(!reloaded[0].plaintext_verified);
    BOOST_CHECK(!reloaded[0].secret_disclosed);
    BOOST_CHECK(modelnet::ValidRefundWindow(reloaded[0].latest_funding_height == 0 ? 1 : reloaded[0].latest_funding_height,
                                            1, 1, reloaded[0].refund_height));
}

BOOST_AUTO_TEST_CASE(pool_09_refund_race_window)
{
    BOOST_CHECK(modelnet::ValidRefundWindow(10, 2, 2, 100));
    BOOST_CHECK(!modelnet::ValidRefundWindow(0, 1, 1, 10));
    BOOST_CHECK(!modelnet::ValidRefundWindow(50, 1, 1, 50));
    BOOST_CHECK(!modelnet::ValidRefundWindow(10, 2, 2, 13));
}

BOOST_AUTO_TEST_CASE(pool_13_amount_and_exposure_caps)
{
    modelnet::FrozenModelFunding in = SampleFunding();
    in.amount_atoms = 2000;
    in.max_atoms = 1000;
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("max_atoms") != std::string::npos);
    BOOST_CHECK(modelnet::ExposureWithinCeiling(0, 100, 100));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(90, 20, 100));
    BOOST_CHECK(!modelnet::ExposureWithinCeiling(-1, 0, 100));
}

BOOST_AUTO_TEST_CASE(pool_14_helper_funding_requires_params)
{
    const fs::path tmp = m_path_root / "pool-helper-absent";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    for (const char* method : {"preparemodelfunding", "signmodelfunding", "submitmodelfunding",
                                "exportmodelrecovery", "buildmodelhtlcclaim", "buildmodelhtlcrefund"}) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", UniValue(UniValue::VARR));
        UniValue result;
        std::string code, err;
        const bool ok = modelnet::DispatchHelperRpc(cat, req, result, code, err);
        BOOST_CHECK(code != "NOT_IMPLEMENTED");
        if (ok) {
            BOOST_CHECK(result.exists("schema_version"));
            BOOST_CHECK(!result.exists("implemented") || result["implemented"].get_bool());
        } else {
            BOOST_CHECK(code == "INVALID_PARAMETER" || code == "PREIMAGE_MISMATCH");
        }
    }
}

BOOST_AUTO_TEST_CASE(recip_07_10_delayed_credit_never_banman)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(!ledger.TouchesBanMan());
    BOOST_CHECK_EQUAL(ledger.AutomaticSpendAtoms(), 0);
    BOOST_REQUIRE(ledger.Received("203.0.113.9:1", "art", 0, 0, 4096, /*when=*/10, true, true, false, /*observed_sources=*/3));
    BOOST_CHECK_EQUAL(ledger.Effective("203.0.113.9:1", /*now=*/10 + 3600), 4096);
    BOOST_CHECK(!ledger.CreditThirdPartyReceipt("203.0.113.9:1", 99999, 11));
    BOOST_CHECK_EQUAL(ledger.Effective("203.0.113.9:1", 11 + 3600), 4096);
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(pool_02_all_outputs_match_frozen_template)
{
    wallet::FrozenFundingQuote q;
    q.release_id = "aa";
    q.key_hash_hex = HexStr(std::vector<unsigned char>(32, 0x11));
    q.claimant_key = HexStr(std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0x21));
    q.refund_key = HexStr(std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0x31));
    q.refund_height = 1024;
    q.amount_atoms = 100000;
    std::string err;
    BOOST_REQUIRE(wallet::BuildHtlcSha256Descriptor(q, err));
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(q.amount_atoms, q.output_script);
    q.unsigned_hex = EncodeHexTx(CTransaction(mtx));
    q.unsigned_txid = mtx.GetHash().ToUint256();
    BOOST_CHECK(wallet::MatchFrozenTemplate(q, mtx, err));
    CMutableTransaction mutated = mtx;
    mutated.vout[0].nValue = q.amount_atoms + 1;
    BOOST_CHECK(!wallet::MatchFrozenTemplate(q, mutated, err));
    UniValue forbidden(UniValue::VOBJ);
    forbidden.pushKV("htlc", "htlc_tx");
    BOOST_CHECK(!wallet::RejectForbiddenHtlc(forbidden, err));
}
#endif

BOOST_AUTO_TEST_SUITE_END()
