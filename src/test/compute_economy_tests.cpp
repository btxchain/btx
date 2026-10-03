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
#include <string>

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

// Satisfy `aid` in `dir` through createcomputejob -> submitcomputejobresult ->
// acceptcomputejobresult. The local identity must be scheduler, subject and
// receipt issuer. Returns the receipt.
UniValue SettleByJob(const fs::path& dir, const UniValue& aid, const std::string& subject, uint64_t credit,
                     const std::string& tag, int64_t t0)
{
    UniValue job(UniValue::VOBJ);
    job.pushKV("agreement_id", aid);
    job.pushKV("subject_pubkey", subject);
    job.pushKV("job_class", "REGTEST_DETERMINISTIC");
    job.pushKV("credit_p1e_microunits", credit);
    job.pushKV("input_commitment", "in-" + tag);
    job.pushKV("executor_spec_commitment", "regtest-runner");
    job.pushKV("expires_at_ms", 4000);
    job.pushKV("nonce", "job-" + tag);
    job.pushKV("now_ms", t0);
    UniValue res(UniValue::VOBJ);
    res.pushKV("job_id", Call(dir, "regtest", "createcomputejob", job)["job_id"]);
    res.pushKV("output_commitment", "out-" + tag);
    res.pushKV("now_ms", t0 + 100);
    UniValue acc(UniValue::VOBJ);
    acc.pushKV("result_id", Call(dir, "regtest", "submitcomputejobresult", res)["result_id"]);
    acc.pushKV("expected_output_commitment", "out-" + tag);
    acc.pushKV("now_ms", t0 + 200);
    return Call(dir, "regtest", "acceptcomputejobresult", acc);
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
    verify.pushKV("trusted_issuer_pubkey", hex);
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
    BOOST_CHECK(CallFail(maindir, "main", "createcomputeoffer", main_req, "COMPUTE_TEST_PROFILE_DISABLED"));
    main_req.pushKV("now_ms", 1);
    BOOST_CHECK(CallFail(maindir, "main", "createcomputeoffer", main_req, "COMPUTE_RECORD_INVALID"));
}

BOOST_AUTO_TEST_CASE(reservation_job_cap_and_import_authorization)
{
    const fs::path dir = m_path_root / "pwc-c";
    fs::create_directories(dir);
    std::vector<unsigned char> pk;
    WriteIdentity(dir, pk);
    const std::string hex = HexStr(pk);
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    std::vector<unsigned char> other_pk, other_sk;
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(other_pk, other_sk, gen_err));
    const std::string other = HexStr(other_pk);

    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", Offer(profile, hex, other, hex, "PREPAID", 2000000, "REGTEST_DETERMINISTIC"));
    req.pushKV("now_ms", 1000);
    const UniValue created = Call(dir, "regtest", "createcomputeoffer", req);
    UniValue mutated = created;
    std::string sig = mutated["signature"].get_str();
    sig.back() = sig.back() == 'a' ? 'b' : 'a';
    mutated.pushKV("signature", sig);
    UniValue bad_import(UniValue::VOBJ);
    bad_import.pushKV("envelope", mutated);
    bad_import.pushKV("now_ms", 1000);
    BOOST_CHECK(CallFail(dir, "regtest", "importcomputeoffer", bad_import, "COMPUTE_SIGNATURE_INVALID"));

    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", created["offer_id"].get_str());
    agr.pushKV("subject_pubkey", hex);
    agr.pushKV("period_start_ms", 1000);
    agr.pushKV("period_end_ms", 9'000'000);
    agr.pushKV("now_ms", 1000);
    const std::string agreement_id = Call(dir, "regtest", "issuecomputeagreement", agr)["agreement_id"].get_str();
    UniValue denied(UniValue::VOBJ);
    denied.pushKV("agreement_id", agreement_id);
    denied.pushKV("subject_pubkey", hex);
    denied.pushKV("job_class", "REGTEST_DETERMINISTIC");
    denied.pushKV("credit_p1e_microunits", 1000000);
    denied.pushKV("input_commitment", "nope");
    denied.pushKV("executor_spec_commitment", "22");
    denied.pushKV("expires_at_ms", 8'000'000);
    denied.pushKV("now_ms", 1100);
    BOOST_CHECK(CallFail(dir, "regtest", "createcomputejob", denied, "COMPUTE_UNAUTHORIZED_SCHEDULER"));

    const fs::path dir2 = m_path_root / "pwc-d";
    fs::create_directories(dir2);
    std::vector<unsigned char> pk2;
    WriteIdentity(dir2, pk2);
    const std::string hex2 = HexStr(pk2);
    UniValue req2(UniValue::VOBJ);
    req2.pushKV("offer", Offer(profile, hex2, hex2, hex2, "PREPAID", 2000000, "REGTEST_DETERMINISTIC"));
    req2.pushKV("now_ms", 1000);
    const std::string offer2 = Call(dir2, "regtest", "createcomputeoffer", req2)["offer_id"].get_str();
    UniValue agr2(UniValue::VOBJ);
    agr2.pushKV("offer_id", offer2);
    agr2.pushKV("subject_pubkey", hex2);
    agr2.pushKV("period_start_ms", 1000);
    agr2.pushKV("period_end_ms", 9'000'000);
    agr2.pushKV("now_ms", 1000);
    const std::string aid2 = Call(dir2, "regtest", "issuecomputeagreement", agr2)["agreement_id"].get_str();

    auto make_job = [&](uint64_t credit, const std::string& nonce, int64_t now) {
        UniValue job(UniValue::VOBJ);
        job.pushKV("agreement_id", aid2);
        job.pushKV("subject_pubkey", hex2);
        job.pushKV("job_class", "REGTEST_DETERMINISTIC");
        job.pushKV("credit_p1e_microunits", credit);
        job.pushKV("input_commitment", nonce);
        job.pushKV("executor_spec_commitment", "22");
        job.pushKV("expires_at_ms", 8'000'000);
        job.pushKV("nonce", nonce);
        job.pushKV("now_ms", now);
        return job;
    };
    const UniValue first = Call(dir2, "regtest", "createcomputejob", make_job(1000000, "a", 1200));
    UniValue result_req(UniValue::VOBJ);
    result_req.pushKV("job_id", first["job_id"].get_str());
    result_req.pushKV("output_commitment", "out-a");
    result_req.pushKV("now_ms", 1300);
    const UniValue result = Call(dir2, "regtest", "submitcomputejobresult", result_req);
    UniValue accept(UniValue::VOBJ);
    accept.pushKV("result_id", result["result_id"].get_str());
    accept.pushKV("expected_output_commitment", "out-a");
    accept.pushKV("now_ms", 1400);
    Call(dir2, "regtest", "acceptcomputejobresult", accept);
    BOOST_CHECK(CallFail(dir2, "regtest", "createcomputejob", make_job(1500000, "too-big", 1500), "COMPUTE_CREDIT_OVERFLOW"));
    Call(dir2, "regtest", "createcomputejob", make_job(1000000, "fits", 1500));

    const fs::path dir3 = m_path_root / "pwc-e";
    fs::create_directories(dir3);
    std::vector<unsigned char> pk3;
    WriteIdentity(dir3, pk3);
    const std::string hex3 = HexStr(pk3);
    UniValue req3(UniValue::VOBJ);
    req3.pushKV("offer", Offer(profile, hex3, hex3, hex3, "PREPAID", 128, "REGTEST_DETERMINISTIC"));
    req3.pushKV("now_ms", 1000);
    const std::string offer3 = Call(dir3, "regtest", "createcomputeoffer", req3)["offer_id"].get_str();
    UniValue agr3(UniValue::VOBJ);
    agr3.pushKV("offer_id", offer3);
    agr3.pushKV("subject_pubkey", hex3);
    agr3.pushKV("period_start_ms", 1000);
    agr3.pushKV("period_end_ms", 9'000'000);
    agr3.pushKV("now_ms", 1000);
    const std::string aid3 = Call(dir3, "regtest", "issuecomputeagreement", agr3)["agreement_id"].get_str();
    std::string first_job;
    for (int i = 0; i < 64; ++i) {
        UniValue job(UniValue::VOBJ);
        job.pushKV("agreement_id", aid3);
        job.pushKV("subject_pubkey", hex3);
        job.pushKV("job_class", "REGTEST_DETERMINISTIC");
        job.pushKV("credit_p1e_microunits", 1);
        job.pushKV("input_commitment", "c" + std::to_string(i));
        job.pushKV("executor_spec_commitment", "22");
        job.pushKV("expires_at_ms", 8'000'000);
        job.pushKV("nonce", "n" + std::to_string(i));
        job.pushKV("now_ms", 2000);
        const UniValue made = Call(dir3, "regtest", "createcomputejob", job);
        if (i == 0) first_job = made["job_id"].get_str();
    }
    UniValue overflow(UniValue::VOBJ);
    overflow.pushKV("agreement_id", aid3);
    overflow.pushKV("subject_pubkey", hex3);
    overflow.pushKV("job_class", "REGTEST_DETERMINISTIC");
    overflow.pushKV("credit_p1e_microunits", 1);
    overflow.pushKV("input_commitment", "c64");
    overflow.pushKV("executor_spec_commitment", "22");
    overflow.pushKV("expires_at_ms", 8'000'000);
    overflow.pushKV("nonce", "n64");
    overflow.pushKV("now_ms", 2000);
    BOOST_CHECK(CallFail(dir3, "regtest", "createcomputejob", overflow, "COMPUTE_RECORD_INVALID"));
    UniValue settle_req(UniValue::VOBJ);
    settle_req.pushKV("job_id", first_job);
    settle_req.pushKV("output_commitment", "done");
    settle_req.pushKV("now_ms", 2100);
    const UniValue settled = Call(dir3, "regtest", "submitcomputejobresult", settle_req);
    UniValue settle_accept(UniValue::VOBJ);
    settle_accept.pushKV("result_id", settled["result_id"].get_str());
    settle_accept.pushKV("expected_output_commitment", "done");
    settle_accept.pushKV("now_ms", 2200);
    Call(dir3, "regtest", "acceptcomputejobresult", settle_accept);
    overflow.pushKV("nonce", "n65");
    overflow.pushKV("input_commitment", "c65");
    Call(dir3, "regtest", "createcomputejob", overflow);
}

BOOST_AUTO_TEST_CASE(grant_requires_agreement_issued_by_this_node)
{
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    const fs::path provider = m_path_root / "own-provider";
    const fs::path outsider = m_path_root / "own-outsider";
    fs::create_directories(provider);
    fs::create_directories(outsider);
    std::vector<unsigned char> pk;
    WriteIdentity(provider, pk);
    WriteIdentity(outsider, pk);
    const std::string xpk = HexStr(pk);
    // The outsider writes its own offer and agreement for the provider's
    // resource_ref, lists itself as scheduler and receipt issuer, and settles
    // a useful job on its own node.
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", Offer(profile, xpk, xpk, xpk, "PREPAID", 1000, "REGTEST_DETERMINISTIC"));
    req.pushKV("now_ms", 1000);
    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", Call(outsider, "regtest", "createcomputeoffer", req)["offer_id"]);
    agr.pushKV("subject_pubkey", xpk);
    agr.pushKV("period_start_ms", 1000);
    agr.pushKV("period_end_ms", 5000);
    agr.pushKV("now_ms", 1000);
    const UniValue agreement = Call(outsider, "regtest", "issuecomputeagreement", agr);
    const UniValue receipt = SettleByJob(outsider, agreement["agreement_id"], xpk, 1000, "d2", 1100);
    UniValue gj(UniValue::VOBJ);
    gj.pushKV("id", receipt["body"]["payload"]["job_id"]);
    const UniValue job = Call(outsider, "regtest", "getcomputejob", gj);
    // Agreement, job and receipt reach the provider through the import RPCs.
    UniValue ia(UniValue::VOBJ);
    ia.pushKV("envelope", agreement);
    Call(provider, "regtest", "importcomputeagreement", ia);
    UniValue ij(UniValue::VOBJ);
    ij.pushKV("envelope", job);
    ij.pushKV("now_ms", 1150);
    Call(provider, "regtest", "importcomputejob", ij);
    UniValue ir(UniValue::VOBJ);
    ir.pushKV("envelope", receipt);
    Call(provider, "regtest", "importcomputereceipt", ir);
    UniValue g(UniValue::VOBJ);
    g.pushKV("agreement_id", agreement["agreement_id"]);
    g.pushKV("now_ms", 1400);
    BOOST_CHECK(CallFail(provider, "regtest", "issuecomputeaccessgrant", g, "COMPUTE_RECORD_INVALID"));
}

BOOST_AUTO_TEST_CASE(pro_rata_not_in_good_standing_before_period_start)
{
    const std::string profile = pwc::ProfileIdHex(pwc::ToyProfile());
    const fs::path dir = m_path_root / "pwc-prestart";
    fs::create_directories(dir);
    std::vector<unsigned char> pk;
    WriteIdentity(dir, pk);
    const std::string hex = HexStr(pk);
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", Offer(profile, hex, hex, hex, "PRO_RATA", 8'000'000, "REGTEST_DETERMINISTIC"));
    req.pushKV("now_ms", 1000);
    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", Call(dir, "regtest", "createcomputeoffer", req)["offer_id"]);
    agr.pushKV("subject_pubkey", hex);
    agr.pushKV("period_start_ms", 100'000'000);
    agr.pushKV("period_end_ms", 200'000'000);
    agr.pushKV("now_ms", 1000);
    UniValue bal_req(UniValue::VOBJ);
    bal_req.pushKV("agreement_id", Call(dir, "regtest", "issuecomputeagreement", agr)["agreement_id"]);
    bal_req.pushKV("now_ms", 1000);
    const UniValue bal = Call(dir, "regtest", "getcomputebalance", bal_req);
    BOOST_CHECK_EQUAL((bal["credited_p1e_microunits"].getInt<uint64_t>()), 0u);
    BOOST_CHECK_EQUAL(bal["status"].get_str(), "OPEN");
    BOOST_CHECK(CallFail(dir, "regtest", "issuecomputeaccessgrant", bal_req, "COMPUTE_NOT_SATISFIED"));
}

BOOST_AUTO_TEST_SUITE_END()
