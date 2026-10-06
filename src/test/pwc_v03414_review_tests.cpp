// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// v0.34.14 re-review of Pay With Compute (PWC/1): new findings and stress.
// the property it holds. Regtest toy profile only; nothing here is consensus.

#include <crypto/sha256.h>
#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>
#include <matmul/compute_qualification.h>
#include <modelnet/bounty.h>
#include <modelnet/compute_economy.h>
#include <modelnet/identity.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <limits>
#include <string>

namespace {

const std::string kResource = "urn:btx:pwc:demo-model";

/** Run one economy method. Exceptions count as a failed call, as they do
 *  behind btx-modeld's DispatchHelperRpc. */
bool TryCall(const fs::path& dir, const std::string& method, const UniValue& req, UniValue& out, std::string& code)
{
    UniValue params(UniValue::VARR);
    params.push_back(req);
    std::string err;
    code.clear();
    try {
        const bool ok = modelnet::ComputeEconomySelfTestHook(dir, "regtest", method, params, out, code, err);
        if (!ok) BOOST_TEST_MESSAGE(method << " -> " << code << " " << err);
        return ok;
    } catch (const std::exception& e) {
        code = std::string("EXCEPTION: ") + e.what();
        BOOST_TEST_MESSAGE(method << " threw " << e.what());
        return false;
    }
}

UniValue Call(const fs::path& dir, const std::string& method, const UniValue& req)
{
    UniValue out;
    std::string code;
    const bool ok = TryCall(dir, method, req, out, code);
    BOOST_TEST_INFO("method " << method << " code " << code);
    BOOST_REQUIRE(ok);
    return out;
}

bool Refused(const fs::path& dir, const std::string& method, const UniValue& req, const std::string& expect)
{
    UniValue out;
    std::string code;
    const bool ok = TryCall(dir, method, req, out, code);
    BOOST_CHECK_MESSAGE(!ok, method << " was accepted; expected " << expect);
    BOOST_CHECK_MESSAGE(ok || code == expect, method << " failed with " << code << "; expected " << expect);
    return !ok && code == expect;
}

void WriteIdentity(const fs::path& dir, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    UniValue store(UniValue::VOBJ);
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    std::ofstream out(dir / "research_identity.json");
    out << store.write();
}

fs::path NewDir(const fs::path& root, const std::string& name, std::vector<unsigned char>& pk, std::vector<unsigned char>& sk)
{
    const fs::path dir = root / fs::PathFromString(name);
    fs::create_directories(dir);
    WriteIdentity(dir, pk, sk);
    return dir;
}

UniValue Keys(std::initializer_list<std::string> keys)
{
    UniValue arr(UniValue::VARR);
    for (const auto& k : keys) arr.push_back(k);
    return arr;
}

UniValue Offer(const std::string& issuer, const UniValue& schedulers, const UniValue& receipt_issuers,
               const char* schedule, uint64_t required, const std::string& nonce)
{
    UniValue offer(UniValue::VOBJ);
    offer.pushKV("record_type", "compute_offer_v1");
    offer.pushKV("schema_version", 1);
    offer.pushKV("created_at_ms", 1);
    offer.pushKV("expires_at_ms", 10'000'000);
    offer.pushKV("nonce", nonce);
    offer.pushKV("resource_ref", kResource);
    offer.pushKV("issuer_pubkey", issuer);
    UniValue access(UniValue::VOBJ);
    access.pushKV("access_kind", "MODEL_ACCESS");
    access.pushKV("period_ms", 1'800'000);
    access.pushKV("rights", Keys({"USE"}));
    offer.pushKV("access", access);
    UniValue settlement(UniValue::VOBJ);
    settlement.pushKV("profile_id", pwc::ProfileIdHex(pwc::ToyProfile()));
    settlement.pushKV("required_p1e_microunits", required);
    settlement.pushKV("schedule", schedule);
    settlement.pushKV("allowed_settlement_modes", Keys({"USEFUL_JOB_RECEIPTS", "DIRECT_COMPUTE"}));
    settlement.pushKV("qualification_required", false);
    settlement.pushKV("allowed_job_classes", Keys({"REGTEST_DETERMINISTIC"}));
    settlement.pushKV("authorized_job_scheduler_pubkeys", schedulers);
    settlement.pushKV("authorized_receipt_issuer_pubkeys", receipt_issuers);
    offer.pushKV("settlement", settlement);
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("transferable", false);
    policy.pushKV("cash_redeemable", false);
    policy.pushKV("cross_agreement_credit", false);
    policy.pushKV("carryover", false);
    offer.pushKV("policy", policy);
    return offer;
}

std::string CreateOffer(const fs::path& dir, const UniValue& offer)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", offer);
    req.pushKV("now_ms", 1000);
    return Call(dir, "createcomputeoffer", req)["offer_id"].get_str();
}

UniValue AgreementReq(const std::string& offer_id, const std::string& subject, int64_t start, int64_t end, const std::string& nonce)
{
    UniValue agr(UniValue::VOBJ);
    agr.pushKV("offer_id", offer_id);
    agr.pushKV("subject_pubkey", subject);
    agr.pushKV("period_start_ms", start);
    agr.pushKV("period_end_ms", end);
    agr.pushKV("nonce", nonce);
    agr.pushKV("now_ms", 1000);
    return agr;
}

UniValue JobReq(const std::string& aid, const std::string& subject, uint64_t credit, const std::string& tag, int64_t now, int64_t expires)
{
    UniValue job(UniValue::VOBJ);
    job.pushKV("agreement_id", aid);
    job.pushKV("subject_pubkey", subject);
    job.pushKV("job_class", "REGTEST_DETERMINISTIC");
    job.pushKV("credit_p1e_microunits", credit);
    job.pushKV("input_commitment", "in-" + tag);
    job.pushKV("executor_spec_commitment", "regtest-runner");
    job.pushKV("expires_at_ms", expires);
    job.pushKV("nonce", "job-" + tag);
    job.pushKV("now_ms", now);
    return job;
}

/** createcomputejob -> submitcomputejobresult -> acceptcomputejobresult on one
 *  node whose identity is scheduler, subject and receipt issuer. */
bool TrySettleByJob(const fs::path& dir, const std::string& aid, const std::string& subject, uint64_t credit,
                    const std::string& tag, int64_t t0, UniValue& receipt, UniValue* job_out = nullptr)
{
    UniValue job, res;
    std::string code;
    if (!TryCall(dir, "createcomputejob", JobReq(aid, subject, credit, tag, t0, 8'000'000), job, code)) return false;
    if (job_out) *job_out = job;
    UniValue rq(UniValue::VOBJ);
    rq.pushKV("job_id", job["job_id"]);
    rq.pushKV("output_commitment", "out-" + tag);
    rq.pushKV("now_ms", t0 + 100);
    if (!TryCall(dir, "submitcomputejobresult", rq, res, code)) return false;
    UniValue acc(UniValue::VOBJ);
    acc.pushKV("result_id", res["result_id"]);
    acc.pushKV("expected_output_commitment", "out-" + tag);
    acc.pushKV("now_ms", t0 + 200);
    return TryCall(dir, "acceptcomputejobresult", acc, receipt, code);
}

UniValue SignEnvelope(const std::string& type, const std::vector<unsigned char>& pk, const std::vector<unsigned char>& sk, const UniValue& payload)
{
    modelnet::SignedEnvelope env;
    std::string err;
    BOOST_REQUIRE(modelnet::BuildSignedEnvelope(type, modelnet::PwcNetworkId("regtest"), pk, sk, payload, UniValue(UniValue::VNULL), env, err));
    return modelnet::EnvelopeToJson(env);
}

UniValue DirectReceipt(const std::string& aid, const std::string& subject, uint64_t credit, const std::string& evidence, const std::string& nonce)
{
    UniValue r(UniValue::VOBJ);
    r.pushKV("record_type", "compute_receipt_v1");
    r.pushKV("schema_version", 1);
    r.pushKV("agreement_id", aid);
    r.pushKV("subject_pubkey", subject);
    r.pushKV("profile_id", pwc::ProfileIdHex(pwc::ToyProfile()));
    r.pushKV("credited_p1e_microunits", credit);
    r.pushKV("verification_method", "DIRECT_COMPUTE");
    r.pushKV("evidence_commitment", evidence);
    r.pushKV("accepted_at_ms", 2000);
    r.pushKV("nonce", nonce);
    return r;
}

UniValue Envelope(const UniValue& env, int64_t now = -1)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("envelope", env);
    if (now >= 0) req.pushKV("now_ms", now);
    return req;
}

uint64_t Credited(const fs::path& dir, const std::string& aid, int64_t now)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("agreement_id", aid);
    req.pushKV("now_ms", now);
    UniValue out;
    std::string code;
    if (!TryCall(dir, "getcomputebalance", req, out, code)) return std::numeric_limits<uint64_t>::max();
    return out["credited_p1e_microunits"].getInt<uint64_t>();
}

/** Issue, solve and redeem a toy challenge for `subject_pk` in a fresh registry. */
void RedeemedChallenge(const fs::path& qpath, const std::vector<unsigned char>& subject_pk, uint32_t episodes,
                       UniValue& challenge, UniValue& response)
{
    pwc::QualificationFreshness in;
    in.network = "regtest";
    in.profile_name = "btx-rc-p1e-toy-v1";
    CSHA256().Write(subject_pk.data(), subject_pk.size()).Finalize(in.subject.data());
    in.issuer_nonce.fill(9);
    in.issued_at_ms = 1'000;
    in.expires_at_ms = 2'000;
    in.episode_count = episodes;
    std::string code, err;
    UniValue summary;
    BOOST_REQUIRE(pwc::IssueQualification(in, true, challenge, code, err));
    BOOST_REQUIRE(pwc::SolveQualification(challenge, 60000, false, response, code, err));
    pwc::QualificationRegistry reg;
    BOOST_REQUIRE(reg.Open(qpath, err));
    BOOST_REQUIRE(reg.RememberIssued(challenge, code, err));
    BOOST_REQUIRE(reg.Verify(challenge, response, true, 1'500, summary, code, err));
}

} // namespace

namespace {

UniValue ForeignAgreement(const std::string& subject, const std::string& receipt_issuer, int64_t start, int64_t end,
                          const std::string& nonce, uint64_t required = 3'000'000)
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("record_type", "compute_agreement_v1");
    p.pushKV("schema_version", 1);
    p.pushKV("offer_id", std::string(96, 'e'));
    p.pushKV("subject_pubkey", subject);
    p.pushKV("resource_ref", kResource);
    p.pushKV("period_start_ms", start);
    p.pushKV("period_end_ms", end);
    UniValue s(UniValue::VOBJ);
    s.pushKV("profile_id", pwc::ProfileIdHex(pwc::ToyProfile()));
    s.pushKV("required_p1e_microunits", required);
    s.pushKV("schedule", "PREPAID");
    s.pushKV("allowed_settlement_modes", Keys({"DIRECT_COMPUTE"}));
    s.pushKV("authorized_job_scheduler_pubkeys", Keys({receipt_issuer}));
    s.pushKV("authorized_receipt_issuer_pubkeys", Keys({receipt_issuer}));
    p.pushKV("settlement", s);
    UniValue access(UniValue::VOBJ);
    access.pushKV("access_kind", "MODEL_ACCESS");
    access.pushKV("period_ms", 1'800'000);
    access.pushKV("rights", Keys({"USE"}));
    p.pushKV("access", access);
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("transferable", false);
    policy.pushKV("cash_redeemable", false);
    policy.pushKV("cross_agreement_credit", false);
    policy.pushKV("carryover", false);
    p.pushKV("policy", policy);
    p.pushKV("issued_at_ms", 1000);
    p.pushKV("nonce", nonce);
    return p;
}

bool Listed(const fs::path& dir, const std::string& method, const std::string& id)
{
    UniValue req(UniValue::VOBJ);
    UniValue out = Call(dir, method, req);
    for (const auto& r : out["records"].getValues()) {
        if (r.exists("id") && r["id"].get_str() == id) return true;
    }
    return false;
}

int64_t NowMsReal() { return TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()); }

void WriteRegistry(const fs::path& qpath, size_t n, bool redeemed, int64_t expires_at)
{
    UniValue entries(UniValue::VARR);
    const std::string toy = pwc::ProfileIdHex(pwc::ToyProfile());
    for (size_t i = 0; i < n; ++i) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("id", strprintf("%096x", i + 1));
        row.pushKV("profile_id", toy);
        row.pushKV("subject", std::string(64, '0'));
        row.pushKV("issued_at_ms", NowMsReal());
        row.pushKV("expires_at_ms", expires_at);
        row.pushKV("episode_count", 1);
        row.pushKV("max_elapsed_ms", 0);
        row.pushKV("redeemed", redeemed);
        row.pushKV("redeemed_at_ms", redeemed ? NowMsReal() : 0);
        row.pushKV("canonical", "");
        entries.push_back(row);
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("schema", 1);
    root.pushKV("entries", entries);
    std::ofstream out(qpath, std::ios::trunc);
    out << root.write() << "\n";
}

bool TryIssueFresh(const fs::path& qpath, std::string& code, std::string& err, unsigned char tag)
{
    pwc::QualificationRegistry reg;
    if (!reg.Open(qpath, err)) return false;
    pwc::QualificationFreshness in;
    in.network = "regtest";
    in.profile_name = "btx-rc-p1e-toy-v1";
    in.subject.fill(3);
    in.issuer_nonce.fill(tag);
    in.issued_at_ms = NowMsReal();
    in.expires_at_ms = in.issued_at_ms + 60'000;
    in.episode_count = 1;
    UniValue fresh;
    if (!pwc::IssueQualification(in, true, fresh, code, err)) return false;
    code.clear();
    err.clear();
    return reg.RememberIssued(fresh, code, err);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pwc_v03414_review_tests, BasicTestingSetup)

// W-A. A DIRECT receipt for a challenge THIS node issued is only useful on an
// agreement this node signed. A receipt on an imported, foreign-signed
// agreement must not consume the challenge and block the honest receipt.
BOOST_AUTO_TEST_CASE(foreign_agreement_cannot_consume_local_challenge)
{
    std::vector<unsigned char> pk, sk, kpk, ksk;
    const fs::path dir = NewDir(m_path_root, "w-front", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(kpk, ksk, gen_err));
    const std::string me = HexStr(pk), attacker = HexStr(kpk);
    const fs::path qpath = m_path_root / "w-front-qual.dat";
    UniValue challenge, response;
    RedeemedChallenge(qpath, pk, 1, challenge, response);
    const std::string cid = challenge["challenge_id"].get_str();
    modelnet::SetPwcQualificationRegistryPath(fs::PathToString(qpath));

    const std::string offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me}), "PREPAID", 3'000'000, "front"));
    const std::string aid = Call(dir, "issuecomputeagreement", AgreementReq(offer, me, 1000, 9'000'000, "a"))["agreement_id"].get_str();

    // The attacker signs its own agreement naming the same subject and lists
    // itself as receipt issuer. The provider imports it (an import is a normal
    // operator action; the record verifies).
    UniValue evil = SignEnvelope("ComputeAgreement", kpk, ksk, ForeignAgreement(me, attacker, 1000, 9'000'000, "evil"));
    UniValue imported;
    std::string code;
    BOOST_REQUIRE(TryCall(dir, "importcomputeagreement", Envelope(evil, 2000), imported, code));
    const std::string evil_aid = imported["agreement_id"].get_str();
    // Its receipt names the victim's redeemed challenge with the right credit.
    UniValue out;
    const bool attacker_receipt_ok = TryCall(dir, "importcomputereceipt",
        Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(evil_aid, me, 1'000'000, cid, "evil-r")), 2000), out, code);
    BOOST_TEST_MESSAGE("attacker receipt on foreign agreement accepted=" << attacker_receipt_ok << " code=" << code);
    BOOST_CHECK_MESSAGE(!attacker_receipt_ok, "a foreign-signed agreement consumed a challenge this node issued");

    // The provider's own receipt for the subject's work on its own agreement.
    UniValue rq(UniValue::VOBJ);
    rq.pushKV("agreement_id", aid);
    rq.pushKV("credited_p1e_microunits", 1'000'000);
    rq.pushKV("profile_id", pwc::ProfileIdHex(pwc::ToyProfile()));
    rq.pushKV("subject_pubkey", me);
    rq.pushKV("verification_method", "DIRECT_COMPUTE");
    rq.pushKV("evidence_commitment", cid);
    rq.pushKV("now_ms", 2500);
    UniValue honest;
    const bool honest_ok = TryCall(dir, "issuecomputereceipt", rq, honest, code);
    BOOST_CHECK_MESSAGE(honest_ok, "honest DIRECT receipt refused after the foreign import: " << code);
    BOOST_CHECK_EQUAL(Credited(dir, aid, 3000), honest_ok ? 1'000'000u : 0u);
    modelnet::SetPwcQualificationRegistryPath("");
}

// W-B. An import that is refused must not be stored. importcomputeagreement
// writes the record before it validates subject, profile and period.
BOOST_AUTO_TEST_CASE(refused_agreement_import_is_not_stored)
{
    std::vector<unsigned char> pk, sk, kpk, ksk;
    const fs::path dir = NewDir(m_path_root, "w-store", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(kpk, ksk, gen_err));
    const std::string me = HexStr(pk), attacker = HexStr(kpk);
    // Inverted period: refused with COMPUTE_RECORD_INVALID.
    UniValue bad = SignEnvelope("ComputeAgreement", kpk, ksk, ForeignAgreement(me, attacker, 9'000'000, 1000, "inv"));
    BOOST_CHECK(Refused(dir, "importcomputeagreement", Envelope(bad, 2000), "COMPUTE_RECORD_INVALID"));
    const std::string rid = bad["record_id"].get_str();
    BOOST_CHECK_MESSAGE(!Listed(dir, "listcomputeagreements", rid), "a refused agreement import was stored and is listed");
    UniValue gq(UniValue::VOBJ);
    gq.pushKV("id", rid);
    UniValue got;
    std::string code;
    BOOST_CHECK_MESSAGE(!TryCall(dir, "getcomputeagreement", gq, got, code), "a refused agreement import is returned by getcomputeagreement");
    // It survives a reload (restart) as well.
    std::vector<unsigned char> opk, osk;
    const fs::path other = NewDir(m_path_root, "w-store-other", opk, osk);
    UniValue tmp;
    TryCall(other, "listcomputeagreements", UniValue(UniValue::VOBJ), tmp, code);
    BOOST_CHECK_MESSAGE(!Listed(dir, "listcomputeagreements", rid), "the refused agreement is still listed after reload");
    // Bad subject key: also refused, also stored.
    UniValue bad2 = SignEnvelope("ComputeAgreement", kpk, ksk, ForeignAgreement("zz", attacker, 1000, 9'000'000, "subj"));
    BOOST_CHECK(Refused(dir, "importcomputeagreement", Envelope(bad2, 2000), "COMPUTE_RECORD_INVALID"));
    BOOST_CHECK_MESSAGE(!Listed(dir, "listcomputeagreements", bad2["record_id"].get_str()), "a refused agreement (bad subject) was stored");
}

// P4 residual (characterization, asserts CURRENT behaviour). The fix branch
// drops only redeemed AND expired entries; unredeemed expired ones were always
// purged. So the registry can still be full, but only until the newest entry
// expires: at most expires_in_s (RPC cap 86400 s) after the last issue.
BOOST_AUTO_TEST_CASE(registry_fill_window_characterization)
{
    std::string code, err;
    const int64_t day = 86'400'000;
    // (a) 4096 unredeemed challenges issued with the maximum 24 h expiry.
    const fs::path qa = m_path_root / "w-fill-a.dat";
    WriteRegistry(qa, pwc::kQualRegistryMax, /*redeemed=*/false, NowMsReal() + day);
    const bool a_ok = TryIssueFresh(qa, code, err, 5);
    BOOST_TEST_MESSAGE("(a) 4096 unredeemed, unexpired: issue ok=" << a_ok << " " << code << " " << err);
    BOOST_CHECK(!a_ok && err == "registry full");
    // (b) 4096 redeemed challenges that have not expired yet.
    const fs::path qb = m_path_root / "w-fill-b.dat";
    WriteRegistry(qb, pwc::kQualRegistryMax, /*redeemed=*/true, NowMsReal() + day);
    const bool b_ok = TryIssueFresh(qb, code, err, 6);
    BOOST_TEST_MESSAGE("(b) 4096 redeemed, unexpired: issue ok=" << b_ok << " " << code << " " << err);
    BOOST_CHECK(!b_ok && err == "registry full");
    // (c) Same as (b) but expiring in 1.5 s: issuance resumes once they expire.
    const fs::path qc = m_path_root / "w-fill-c.dat";
    WriteRegistry(qc, pwc::kQualRegistryMax, /*redeemed=*/true, NowMsReal() + 1500);
    BOOST_CHECK(!TryIssueFresh(qc, code, err, 7));
    UninterruptibleSleep(std::chrono::milliseconds{2000});
    const bool c_ok = TryIssueFresh(qc, code, err, 8);
    BOOST_TEST_MESSAGE("(c) after expiry: issue ok=" << c_ok << " " << code << " " << err);
    BOOST_CHECK(c_ok);
    // (d) Unredeemed entries that expire in 1.5 s are purged as before.
    const fs::path qd = m_path_root / "w-fill-d.dat";
    WriteRegistry(qd, pwc::kQualRegistryMax, /*redeemed=*/false, NowMsReal() + 1500);
    UninterruptibleSleep(std::chrono::milliseconds{2000});
    BOOST_CHECK(TryIssueFresh(qd, code, err, 9));
    // (e) Entries stamped with a far-future expiry (wall clock was wrong when
    // they were issued) keep the registry full until that time.
    const fs::path qe = m_path_root / "w-fill-e.dat";
    WriteRegistry(qe, pwc::kQualRegistryMax, /*redeemed=*/true, NowMsReal() + 365 * day);
    const bool e_ok = TryIssueFresh(qe, code, err, 10);
    BOOST_TEST_MESSAGE("(e) far-future expiry: issue ok=" << e_ok << " " << err);
    BOOST_CHECK(!e_ok);
}

// Stress (measurement). One agreement accumulates many imported DIRECT
// receipts from a listed third-party issuer (challenges issued elsewhere, so
// they rest on the issuer). Times import, balance, settlement and reload.
BOOST_AUTO_TEST_CASE(ledger_volume_stress)
{
    std::vector<unsigned char> pk, sk, kpk, ksk;
    const fs::path dir = NewDir(m_path_root, "w-stress", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(kpk, ksk, gen_err));
    const std::string me = HexStr(pk), third = HexStr(kpk);
    modelnet::SetPwcQualificationRegistryPath("");
    const std::string offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me, third}), "PREPAID", 9'000'000'000'000'000ULL, "stress"));
    const std::string a1 = Call(dir, "issuecomputeagreement", AgreementReq(offer, me, 1000, 9'000'000, "s1"))["agreement_id"].get_str();
    const std::string a2 = Call(dir, "issuecomputeagreement", AgreementReq(offer, me, 1000, 9'000'000, "s2"))["agreement_id"].get_str();
    const int n = 2000;
    auto t0 = SteadyClock::now();
    auto tlast = t0;
    for (int i = 0; i < n; ++i) {
        if (i == n - 100) tlast = SteadyClock::now();
        UniValue out;
        std::string code;
        const std::string ev = strprintf("%096x", 0xabc000 + i);
        BOOST_REQUIRE(TryCall(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(a1, me, 16'000'000, ev, strprintf("n%d", i))), 2000), out, code));
    }
    auto t1 = SteadyClock::now();
    const auto ms = [](auto d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };
    BOOST_TEST_MESSAGE("STRESS imported " << n << " receipts in " << ms(t1 - t0) << " ms; last 100 took " << ms(t1 - tlast) << " ms");
    BOOST_CHECK_EQUAL(Credited(dir, a1, 3000), uint64_t(n) * 16'000'000u);
    auto t2 = SteadyClock::now();
    for (int i = 0; i < 10; ++i) Credited(dir, a2, 3000);
    auto t3 = SteadyClock::now();
    BOOST_TEST_MESSAGE("STRESS getcomputebalance (other agreement) avg " << ms(t3 - t2) / 10.0 << " ms");
    UniValue receipt;
    auto t4 = SteadyClock::now();
    BOOST_CHECK(TrySettleByJob(dir, a2, me, 1'000'000, "stress-job", 2000, receipt));
    auto t5 = SteadyClock::now();
    BOOST_TEST_MESSAGE("STRESS settle one job end-to-end " << ms(t5 - t4) << " ms");
    // Reload, as on restart.
    std::vector<unsigned char> opk, osk;
    const fs::path other = NewDir(m_path_root, "w-stress-other", opk, osk);
    UniValue tmp;
    std::string code;
    TryCall(other, "listcomputeagreements", UniValue(UniValue::VOBJ), tmp, code);
    auto t6 = SteadyClock::now();
    BOOST_CHECK_EQUAL(Credited(dir, a1, 3000), uint64_t(n) * 16'000'000u);
    auto t7 = SteadyClock::now();
    BOOST_TEST_MESSAGE("STRESS reload of " << n + 6 << " records + balance " << ms(t7 - t6) << " ms");
    // Listing pages stay answerable.
    UniValue lq(UniValue::VOBJ);
    UniValue page = Call(dir, "listcomputereceipts", lq);
    BOOST_TEST_MESSAGE("STRESS first receipt page holds " << page["records"].size() << " records, next_start "
                       << (page.exists("next_start") ? page["next_start"].write() : "none") << ", " << page.write().size() << " bytes");
    BOOST_CHECK(page.write().size() < 256 * 1024);
}

BOOST_AUTO_TEST_SUITE_END()
