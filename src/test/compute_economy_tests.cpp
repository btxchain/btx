// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_profile.h>
#include <modelnet/compute_economy.h>
#include <modelnet/identity.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <fstream>

namespace {

UniValue Call(const fs::path& dir, const std::string& chain, const std::string& method, const UniValue& req)
{
    UniValue params(UniValue::VARR);
    params.push_back(req);
    UniValue result;
    std::string code, err;
    const bool ok = modelnet::ComputeEconomySelfTestHook(dir, chain, method, params, result, code, err);
    BOOST_TEST_INFO("method " << method << " code " << code << " err " << err);
    BOOST_REQUIRE(ok);
    return result;
}

bool CallFail(const fs::path& dir, const std::string& chain, const std::string& method, const UniValue& req, const std::string& expect)
{
    UniValue params(UniValue::VARR);
    params.push_back(req);
    UniValue result;
    std::string code, err;
    const bool ok = modelnet::ComputeEconomySelfTestHook(dir, chain, method, params, result, code, err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(code, expect);
    return !ok && code == expect;
}

void WriteIdentity(const fs::path& dir, std::vector<unsigned char>& pk)
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

UniValue Offer(const std::string& profile, const std::string& issuer, const std::string& scheduler,
               const std::string& receipt_issuer, const char* schedule, uint64_t required, const char* job_class,
               bool transferable = false)
{
    UniValue offer(UniValue::VOBJ);
    offer.pushKV("record_type", "compute_offer_v1");
    offer.pushKV("schema_version", 1);
    offer.pushKV("created_at_ms", 1);
    offer.pushKV("expires_at_ms", 10'000'000);
    offer.pushKV("nonce", "aa");
    offer.pushKV("resource_ref", "urn:btx:pwc:demo-model");
    offer.pushKV("issuer_pubkey", issuer);
    UniValue access(UniValue::VOBJ);
    access.pushKV("access_kind", "MODEL_ACCESS");
    access.pushKV("period_ms", 1'800'000);
    UniValue rights(UniValue::VARR);
    rights.push_back("USE");
    access.pushKV("rights", rights);
    offer.pushKV("access", access);
    UniValue settlement(UniValue::VOBJ);
    settlement.pushKV("profile_id", profile);
    settlement.pushKV("required_p1e_microunits", required);
    settlement.pushKV("schedule", schedule);
    UniValue modes(UniValue::VARR);
    modes.push_back("USEFUL_JOB_RECEIPTS");
    modes.push_back("DIRECT_COMPUTE");
    settlement.pushKV("allowed_settlement_modes", modes);
    settlement.pushKV("qualification_required", false);
    UniValue classes(UniValue::VARR);
    classes.push_back(job_class);
    settlement.pushKV("allowed_job_classes", classes);
    UniValue sched(UniValue::VARR);
    sched.push_back(scheduler);
    settlement.pushKV("authorized_job_scheduler_pubkeys", sched);
    UniValue issuers(UniValue::VARR);
    issuers.push_back(receipt_issuer);
    settlement.pushKV("authorized_receipt_issuer_pubkeys", issuers);
    offer.pushKV("settlement", settlement);
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("transferable", transferable);
    policy.pushKV("cash_redeemable", false);
    policy.pushKV("cross_agreement_credit", false);
    policy.pushKV("carryover", false);
    offer.pushKV("policy", policy);
    return offer;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(compute_economy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepaid_useful_job_reaches_grant_and_restart)
{
    const fs::path dir = m_path_root / "pwc-a";
    fs::create_directories(dir);
    std::vector<unsigned char> pk;
    WriteIdentity(dir, pk);
    const std::string hex = HexStr(pk);
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", Offer(profile, hex, hex, hex, "PREPAID", 3000000, "REGTEST_DETERMINISTIC"));
    req.pushKV("now_ms", 1000);
    const UniValue created = Call(dir, "regtest", "createcomputeoffer", req);
    const std::string offer_id = created["offer_id"].get_str();

    UniValue quote_req(UniValue::VOBJ);
    quote_req.pushKV("offer_id", offer_id);
    UniValue passport(UniValue::VOBJ);
    passport.pushKV("profile_id", profile);
    passport.pushKV("p1e_microunits_per_hour", 3600000000);
    passport.pushKV("sample_count", 100);
    quote_req.pushKV("passport", passport);
    quote_req.pushKV("duty_cycle_bps", 3500);
    const UniValue quote = Call(dir, "regtest", "quotecomputeaccess", quote_req);
    BOOST_CHECK(quote["profile_match"].get_bool());
    BOOST_CHECK(quote["estimate_only"].get_bool());
    BOOST_CHECK(quote["settlement_requires_receipts"].get_bool());
    BOOST_CHECK_EQUAL((quote["automatic_spend_atoms"].getInt<int64_t>()), 0);

    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", offer_id);
    agr.pushKV("subject_pubkey", hex);
    agr.pushKV("period_start_ms", 1000);
    agr.pushKV("period_end_ms", 5000);
    agr.pushKV("now_ms", 1000);
    const UniValue agreement = Call(dir, "regtest", "issuecomputeagreement", agr);
    const std::string agreement_id = agreement["agreement_id"].get_str();

    UniValue job(UniValue::VOBJ);
    job.pushKV("agreement_id", agreement_id);
    job.pushKV("subject_pubkey", hex);
    job.pushKV("job_class", "REGTEST_DETERMINISTIC");
    job.pushKV("credit_p1e_microunits", 2000000);
    job.pushKV("input_commitment", "11");
    job.pushKV("executor_spec_commitment", "22");
    job.pushKV("expires_at_ms", 4000);
    job.pushKV("beneficiary_ref", "urn:btx:pwc:another-model");
    job.pushKV("now_ms", 1500);
    const UniValue job_env = Call(dir, "regtest", "createcomputejob", job);
    UniValue result_req(UniValue::VOBJ);
    result_req.pushKV("job_id", job_env["job_id"].get_str());
    result_req.pushKV("output_commitment", "33");
    result_req.pushKV("now_ms", 1600);
    const UniValue result = Call(dir, "regtest", "submitcomputejobresult", result_req);
    UniValue accept(UniValue::VOBJ);
    accept.pushKV("result_id", result["result_id"].get_str());
    accept.pushKV("expected_output_commitment", "33");
    accept.pushKV("now_ms", 1700);
    Call(dir, "regtest", "acceptcomputejobresult", accept);
    UniValue bal_req(UniValue::VOBJ);
    bal_req.pushKV("agreement_id", agreement_id);
    bal_req.pushKV("now_ms", 1800);
    UniValue bal = Call(dir, "regtest", "getcomputebalance", bal_req);
    BOOST_CHECK_EQUAL((bal["credited_p1e_microunits"].getInt<uint64_t>()), 2000000u);
    BOOST_CHECK_EQUAL(bal["status"].get_str(), "OPEN");
    UniValue grant_req(UniValue::VOBJ);
    grant_req.pushKV("agreement_id", agreement_id);
    grant_req.pushKV("now_ms", 1800);
    BOOST_CHECK(CallFail(dir, "regtest", "issuecomputeaccessgrant", grant_req, "COMPUTE_NOT_SATISFIED"));

    UniValue job2(UniValue::VOBJ);
    job2.pushKV("agreement_id", agreement_id);
    job2.pushKV("subject_pubkey", hex);
    job2.pushKV("job_class", "REGTEST_DETERMINISTIC");
    job2.pushKV("credit_p1e_microunits", 1000000);
    job2.pushKV("input_commitment", "44");
    job2.pushKV("executor_spec_commitment", "55");
    job2.pushKV("expires_at_ms", 4000);
    job2.pushKV("now_ms", 1900);
    const UniValue job2_env = Call(dir, "regtest", "createcomputejob", job2);
    UniValue result_req2(UniValue::VOBJ);
    result_req2.pushKV("job_id", job2_env["job_id"].get_str());
    result_req2.pushKV("output_commitment", "66");
    result_req2.pushKV("now_ms", 2000);
    const UniValue result2 = Call(dir, "regtest", "submitcomputejobresult", result_req2);
    UniValue accept2(UniValue::VOBJ);
    accept2.pushKV("result_id", result2["result_id"].get_str());
    accept2.pushKV("expected_output_commitment", "66");
    accept2.pushKV("now_ms", 2100);
    const UniValue receipt = Call(dir, "regtest", "acceptcomputejobresult", accept2);
    BOOST_CHECK(CallFail(dir, "regtest", "acceptcomputejobresult", accept2, "COMPUTE_JOB_ALREADY_SETTLED"));
    bal_req.pushKV("now_ms", 2200);
    bal = Call(dir, "regtest", "getcomputebalance", bal_req);
    BOOST_CHECK_EQUAL(bal["status"].get_str(), "SATISFIED");
    grant_req.pushKV("now_ms", 2200);
    const UniValue grant = Call(dir, "regtest", "issuecomputeaccessgrant", grant_req);
    UniValue verify(UniValue::VOBJ);
    verify.pushKV("envelope", grant);
    verify.pushKV("subject_pubkey", hex);
    verify.pushKV("resource_ref", "urn:btx:pwc:demo-model");
    verify.pushKV("now_ms", 2300);
    const UniValue verdict = Call(dir, "regtest", "verifycomputeaccessgrant", verify);
    BOOST_CHECK(verdict["valid"].get_bool());
    BOOST_CHECK_EQUAL((verdict["automatic_spend_atoms"].getInt<int64_t>()), 0);
    (void)receipt;
}

BOOST_AUTO_TEST_CASE(pro_rata_and_rejects)
{
    const fs::path dir = m_path_root / "pwc-b";
    fs::create_directories(dir);
    std::vector<unsigned char> pk;
    WriteIdentity(dir, pk);
    const std::string hex = HexStr(pk);
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", Offer(profile, hex, hex, hex, "PRO_RATA", 8'000'000, "REGTEST_DETERMINISTIC"));
    req.pushKV("now_ms", 0);
    const std::string offer_id = Call(dir, "regtest", "createcomputeoffer", req)["offer_id"].get_str();
    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", offer_id);
    agr.pushKV("subject_pubkey", hex);
    agr.pushKV("period_start_ms", 0);
    agr.pushKV("period_end_ms", 8000);
    agr.pushKV("now_ms", 0);
    const std::string agreement_id = Call(dir, "regtest", "issuecomputeagreement", agr)["agreement_id"].get_str();
    UniValue bal_req(UniValue::VOBJ);
    bal_req.pushKV("agreement_id", agreement_id);
    bal_req.pushKV("now_ms", 2000);
    UniValue bal = Call(dir, "regtest", "getcomputebalance", bal_req);
    BOOST_CHECK_EQUAL((bal["due_now_p1e_microunits"].getInt<uint64_t>()), 2000000u);
    BOOST_CHECK_EQUAL(bal["status"].get_str(), "OPEN");

    UniValue bad(UniValue::VOBJ);
    bad.pushKV("offer", Offer(profile, hex, hex, hex, "PREPAID", 1000, "REGTEST_DETERMINISTIC", true));
    bad.pushKV("now_ms", 1);
    BOOST_CHECK(CallFail(dir, "regtest", "createcomputeoffer", bad, "COMPUTE_RECORD_INVALID"));
    const fs::path maindir = m_path_root / "pwc-main";
    fs::create_directories(maindir);
    std::vector<unsigned char> main_pk;
    WriteIdentity(maindir, main_pk);
    const std::string main_hex = HexStr(main_pk);
    UniValue main_req(UniValue::VOBJ);
    main_req.pushKV("offer", Offer(profile, main_hex, main_hex, main_hex, "PREPAID", 1000, "INFERENCE_BATCH"));
    main_req.pushKV("now_ms", 1);
    BOOST_CHECK(CallFail(maindir, "main", "createcomputeoffer", main_req, "COMPUTE_TEST_PROFILE_DISABLED"));
}

BOOST_AUTO_TEST_SUITE_END()
