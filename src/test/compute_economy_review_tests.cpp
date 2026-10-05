// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Regression tests from the Pay With Compute (PWC/1) review. Each case states
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

BOOST_FIXTURE_TEST_SUITE(compute_economy_review_tests, BasicTestingSetup)

// P1. A grant must not cover time before the agreement period starts.
BOOST_AUTO_TEST_CASE(grant_never_starts_before_agreement)
{
    std::vector<unsigned char> pk, sk;
    const fs::path dir = NewDir(m_path_root, "r-grant", pk, sk);
    const std::string me = HexStr(pk);
    constexpr int64_t START = 5'000'000, END = 6'000'000;

    // PREPAID, fully paid long before the agreement starts.
    const std::string prepaid_offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me}), "PREPAID", 1'000'000, "prepaid"));
    const std::string a1 = Call(dir, "issuecomputeagreement", AgreementReq(prepaid_offer, me, START, END, "a1"))["agreement_id"].get_str();
    UniValue receipt;
    BOOST_REQUIRE(TrySettleByJob(dir, a1, me, 1'000'000, "pre", 1100, receipt));
    UniValue g(UniValue::VOBJ);
    g.pushKV("agreement_id", a1);
    g.pushKV("now_ms", 1500);
    const UniValue grant = Call(dir, "issuecomputeaccessgrant", g);
    const UniValue& gp = grant["body"]["payload"];
    BOOST_CHECK_MESSAGE(gp["valid_from_ms"].getInt<int64_t>() >= START,
                        "prepaid grant valid_from_ms " << gp["valid_from_ms"].getInt<int64_t>() << " is before period_start_ms " << START);
    BOOST_CHECK_EQUAL(gp["valid_until_ms"].getInt<int64_t>(), END);
    // An external gate asked at t=2000, before the agreement starts, must deny.
    UniValue v(UniValue::VOBJ);
    v.pushKV("envelope", grant);
    v.pushKV("trusted_issuer_pubkey", me);
    v.pushKV("resource_ref", kResource);
    v.pushKV("now_ms", 2000);
    BOOST_CHECK(Refused(dir, "verifycomputeaccessgrant", v, "COMPUTE_GRANT_EXPIRED"));
    v.pushKV("now_ms", START + 10);
    Call(dir, "verifycomputeaccessgrant", v);

    // PRO_RATA, fully credited before the start: the documented rule is that a
    // pro-rata grant is refused until the period has started.
    const std::string prorata_offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me}), "PRO_RATA", 1'000'000, "prorata"));
    const std::string a2 = Call(dir, "issuecomputeagreement", AgreementReq(prorata_offer, me, START, END, "a2"))["agreement_id"].get_str();
    BOOST_REQUIRE(TrySettleByJob(dir, a2, me, 1'000'000, "pro", 1100, receipt));
    UniValue g2(UniValue::VOBJ);
    g2.pushKV("agreement_id", a2);
    g2.pushKV("now_ms", 1500);
    BOOST_CHECK(Refused(dir, "issuecomputeaccessgrant", g2, "COMPUTE_NOT_SATISFIED"));
    g2.pushKV("now_ms", START + 1);
    const UniValue g2ok = Call(dir, "issuecomputeaccessgrant", g2);
    BOOST_CHECK_EQUAL(g2ok["body"]["payload"]["valid_from_ms"].getInt<int64_t>(), START + 1);
}

// P2. A receipt field of the wrong type must not block settlement of every
// other agreement on the node, whether it arrives by import or is already on disk.
BOOST_AUTO_TEST_CASE(malformed_receipt_cannot_block_settlement)
{
    std::vector<unsigned char> pk, sk, kpk, ksk;
    const fs::path dir = NewDir(m_path_root, "r-poison", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(kpk, ksk, gen_err));
    const std::string me = HexStr(pk), third = HexStr(kpk);
    // The provider lists a third-party receipt issuer on one agreement only.
    const std::string shared = CreateOffer(dir, Offer(me, Keys({me}), Keys({me, third}), "PREPAID", 3'000'000, "shared"));
    const std::string own = CreateOffer(dir, Offer(me, Keys({me}), Keys({me}), "PREPAID", 3'000'000, "own"));
    const std::string a1 = Call(dir, "issuecomputeagreement", AgreementReq(shared, me, 1000, 9'000'000, "a1"))["agreement_id"].get_str();
    const std::string a2 = Call(dir, "issuecomputeagreement", AgreementReq(own, me, 1000, 9'000'000, "a2"))["agreement_id"].get_str();

    UniValue bad = DirectReceipt(a1, me, 1'000'000, std::string(96, 'a'), "poison");
    bad.pushKV("job_id", 7);
    const UniValue bad_env = SignEnvelope("ComputeReceipt", kpk, ksk, bad);
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(bad_env), "COMPUTE_RECORD_INVALID"));
    UniValue receipt;
    BOOST_CHECK_MESSAGE(TrySettleByJob(dir, a2, me, 1'000'000, "after-import", 1200, receipt),
                        "settlement of an unrelated agreement failed after the import");

    // The same record already in the store (written by an older build, or
    // restored from a backup) must not wedge settlement either. A receipt whose
    // agreement id is not a string is the same class: the balance scan walks
    // every receipt.
    UniValue worse = DirectReceipt(a1, me, 1'000'000, std::string(96, 'b'), "poison-aid");
    worse.pushKV("agreement_id", 7);
    const UniValue worse_env = SignEnvelope("ComputeReceipt", kpk, ksk, worse);
    const fs::path rdir = dir / "compute" / "receipts";
    fs::create_directories(rdir);
    {
        std::ofstream out(rdir / fs::PathFromString(bad_env["record_id"].get_str() + ".json"));
        out << bad_env.write() << "\n";
        std::ofstream out2(rdir / fs::PathFromString(worse_env["record_id"].get_str() + ".json"));
        out2 << worse_env.write() << "\n";
    }
    // Rebind the store so it reloads from disk.
    std::vector<unsigned char> opk, osk;
    const fs::path other = NewDir(m_path_root, "r-poison-other", opk, osk);
    Call(other, "getcomputesigningidentity", UniValue(UniValue::VOBJ));
    BOOST_CHECK_MESSAGE(TrySettleByJob(dir, a2, me, 1'000'000, "after-load", 1300, receipt),
                        "settlement of an unrelated agreement failed with the record on disk");
}

// P3. An imported direct-compute receipt names a redeemed challenge and credits
// whole episodes of it; one challenge backs one receipt.
BOOST_AUTO_TEST_CASE(imported_direct_receipt_is_bound_to_work)
{
    std::vector<unsigned char> pk, sk, kpk, ksk;
    const fs::path dir = NewDir(m_path_root, "r-direct", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(kpk, ksk, gen_err));
    const std::string me = HexStr(pk), third = HexStr(kpk);
    const fs::path qpath = m_path_root / "r-direct-qual.dat";
    UniValue challenge, response;
    RedeemedChallenge(qpath, pk, 1, challenge, response);
    modelnet::SetPwcQualificationRegistryPath(fs::PathToString(qpath));
    const std::string offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me, third}), "PREPAID", 3'000'000, "direct"));
    const std::string aid = Call(dir, "issuecomputeagreement", AgreementReq(offer, me, 1000, 9'000'000, "a"))["agreement_id"].get_str();

    // No evidence, any credit, repeatable.
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 50'000'000, "", "e1"))), "COMPUTE_RECORD_INVALID"));
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 50'000'000, "", "e2"))), "COMPUTE_RECORD_INVALID"));
    // A challenge this node redeemed for one episode cannot carry five.
    const std::string cid = challenge["challenge_id"].get_str();
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 5'000'000, cid, "c5"))), "COMPUTE_RECEIPT_CREDIT_MISMATCH"));
    // The upper-case spelling of the same id is not a second challenge.
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 1'000'000, ToUpper(cid), "cU"))), "COMPUTE_RECORD_INVALID"));
    // The honest receipt for it is accepted once.
    UniValue out;
    std::string code;
    BOOST_CHECK(TryCall(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 1'000'000, cid, "c1"))), out, code));
    BOOST_CHECK(Refused(dir, "importcomputereceipt", Envelope(SignEnvelope("ComputeReceipt", kpk, ksk, DirectReceipt(aid, me, 1'000'000, cid, "c1b"))), "COMPUTE_CHALLENGE_REDEEMED"));
    BOOST_CHECK_EQUAL(Credited(dir, aid, 3000), 1'000'000u);
    modelnet::SetPwcQualificationRegistryPath("");
}

// P4. The registry must keep issuing after kQualRegistryMax redemptions, and a
// challenge dropped to make room must still never redeem again.
BOOST_AUTO_TEST_CASE(registry_keeps_issuing_after_many_redemptions)
{
    std::vector<unsigned char> pk, sk;
    std::string err, code;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const fs::path qpath = m_path_root / "r-full-qual.dat";
    UniValue first, first_response;
    RedeemedChallenge(qpath, pk, 1, first, first_response);
    // Fill the rest with redeemed, expired entries, as years of use would.
    UniValue root;
    {
        std::ifstream in(qpath);
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_REQUIRE(root.read(raw));
    }
    UniValue entries = root["entries"];
    const std::string toy = pwc::ProfileIdHex(pwc::ToyProfile());
    for (size_t i = entries.size(); i < pwc::kQualRegistryMax; ++i) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("id", strprintf("%096x", i));
        row.pushKV("profile_id", toy);
        row.pushKV("subject", std::string(64, '0'));
        row.pushKV("issued_at_ms", 1000);
        row.pushKV("expires_at_ms", 2000);
        row.pushKV("episode_count", 1);
        row.pushKV("max_elapsed_ms", 0);
        row.pushKV("redeemed", true);
        row.pushKV("redeemed_at_ms", static_cast<int64_t>(1600 + i));
        row.pushKV("canonical", "");
        entries.push_back(row);
    }
    root.pushKV("entries", entries);
    {
        std::ofstream out(qpath, std::ios::trunc);
        out << root.write() << "\n";
    }
    pwc::QualificationRegistry reg;
    BOOST_REQUIRE(reg.Open(qpath, err));
    pwc::QualificationFreshness in;
    in.network = "regtest";
    in.profile_name = "btx-rc-p1e-toy-v1";
    in.subject.fill(3);
    in.issuer_nonce.fill(4);
    in.issued_at_ms = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    in.expires_at_ms = in.issued_at_ms + 60'000;
    in.episode_count = 1;
    UniValue fresh;
    BOOST_REQUIRE(pwc::IssueQualification(in, true, fresh, code, err));
    code.clear();
    err.clear();
    BOOST_CHECK_MESSAGE(reg.RememberIssued(fresh, code, err), "issuance refused: " << code << " " << err);
    // Whatever was dropped, the first challenge stays unredeemable.
    UniValue summary;
    code.clear();
    BOOST_CHECK(!reg.Verify(first, first_response, true, 1'700, summary, code, err));
    BOOST_CHECK(code == "COMPUTE_CHALLENGE_UNKNOWN" || code == "COMPUTE_CHALLENGE_REDEEMED");
}

// P5. verifycomputeaccessgrant must accept only a ComputeAccessGrant.
BOOST_AUTO_TEST_CASE(grant_verifier_rejects_other_record_types)
{
    std::vector<unsigned char> pk, sk;
    const fs::path dir = NewDir(m_path_root, "r-type", pk, sk);
    const std::string me = HexStr(pk);
    // A public offer that happens to carry its own validity window.
    UniValue offer = Offer(me, Keys({me}), Keys({me}), "PREPAID", 1'000'000, "windowed");
    offer.pushKV("valid_from_ms", 0);
    offer.pushKV("valid_until_ms", 9'000'000);
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", offer);
    req.pushKV("now_ms", 1000);
    const UniValue created = Call(dir, "createcomputeoffer", req);
    UniValue v(UniValue::VOBJ);
    v.pushKV("envelope", created);
    v.pushKV("trusted_issuer_pubkey", me);
    v.pushKV("resource_ref", kResource);
    v.pushKV("now_ms", 5000);
    BOOST_CHECK(Refused(dir, "verifycomputeaccessgrant", v, "COMPUTE_GRANT_INVALID"));
}

// P6. An agreement freezes this node's own offer. An imported offer (and one
// whose payload names another issuer) must not become an agreement whose
// third-party scheduler and receipt issuer can earn this node's grant.
BOOST_AUTO_TEST_CASE(agreement_requires_own_offer)
{
    std::vector<unsigned char> ppk, psk, apk, ask;
    const fs::path prov = NewDir(m_path_root, "r-prov", ppk, psk);
    const fs::path att = NewDir(m_path_root, "r-att", apk, ask);
    const std::string P = HexStr(ppk), A = HexStr(apk);

    // Spoofed: payload says the provider issued it; the attacker signed it.
    const UniValue spoof = SignEnvelope("ComputeOffer", apk, ask, Offer(P, Keys({A}), Keys({A}), "PREPAID", 1'000'000, "spoof"));
    BOOST_CHECK(Refused(prov, "importcomputeoffer", Envelope(spoof), "COMPUTE_RECORD_INVALID"));

    // Honest foreign offer for the provider's resource. It may be imported,
    // but the provider must not freeze it into an agreement it signs.
    UniValue foreign_payload = Offer(A, Keys({A}), Keys({A}), "PREPAID", 1'000'000, "foreign");
    const UniValue foreign = SignEnvelope("ComputeOffer", apk, ask, foreign_payload);
    Call(prov, "importcomputeoffer", Envelope(foreign));
    UniValue agreement;
    std::string code;
    const bool issued = TryCall(prov, "issuecomputeagreement", AgreementReq(foreign["record_id"].get_str(), A, 1000, 9'000'000, "x"), agreement, code);
    BOOST_CHECK_MESSAGE(!issued, "provider signed an agreement under an offer it did not issue");
    BOOST_CHECK(issued || code == "COMPUTE_RECORD_INVALID");

    // What the attacker reaches when it is signed: settle on its own node, hand
    // the job and receipt to the provider, and get a provider-signed grant.
    bool grant_valid = false;
    if (issued) {
        UniValue out, receipt, job;
        if (TryCall(att, "importcomputeagreement", Envelope(agreement), out, code) &&
            TrySettleByJob(att, agreement["agreement_id"].get_str(), A, 1'000'000, "free", 1100, receipt, &job) &&
            TryCall(prov, "importcomputejob", Envelope(job, 1150), out, code) &&
            TryCall(prov, "importcomputereceipt", Envelope(receipt), out, code)) {
            UniValue g(UniValue::VOBJ);
            g.pushKV("agreement_id", agreement["agreement_id"]);
            g.pushKV("now_ms", 1500);
            UniValue grant;
            if (TryCall(prov, "issuecomputeaccessgrant", g, grant, code)) {
                UniValue v(UniValue::VOBJ);
                v.pushKV("envelope", grant);
                v.pushKV("trusted_issuer_pubkey", P);
                v.pushKV("subject_pubkey", A);
                v.pushKV("resource_ref", kResource);
                v.pushKV("now_ms", 2000);
                grant_valid = TryCall(prov, "verifycomputeaccessgrant", v, out, code);
            }
        }
    }
    BOOST_CHECK_MESSAGE(!grant_valid, "attacker holds a provider-signed grant for the provider's resource without provider-scheduled work");
}

// P7. Local create paths validate what the import paths validate.
BOOST_AUTO_TEST_CASE(local_create_validates_periods_and_expiry)
{
    std::vector<unsigned char> pk, sk;
    const fs::path dir = NewDir(m_path_root, "r-input", pk, sk);
    const std::string me = HexStr(pk);
    const std::string offer = CreateOffer(dir, Offer(me, Keys({me}), Keys({me}), "PRO_RATA", 1'000'000, "input"));
    UniValue bad = AgreementReq(offer, me, 1000, 9'000'000, "s");
    bad.pushKV("period_start_ms", "1000");
    BOOST_CHECK(Refused(dir, "issuecomputeagreement", bad, "COMPUTE_RECORD_INVALID"));
    BOOST_CHECK(Refused(dir, "issuecomputeagreement", AgreementReq(offer, me, 9'000'000, 1000, "inv"), "COMPUTE_RECORD_INVALID"));
    const std::string aid = Call(dir, "issuecomputeagreement", AgreementReq(offer, me, 1000, 9'000'000, "ok"))["agreement_id"].get_str();
    UniValue job = JobReq(aid, me, 1, "str", 2000, 8'000'000);
    job.pushKV("expires_at_ms", "8000000");
    BOOST_CHECK(Refused(dir, "createcomputejob", job, "COMPUTE_RECORD_INVALID"));
    BOOST_CHECK(Refused(dir, "createcomputejob", JobReq(aid, me, 1, "past", 2000, 1500), "COMPUTE_JOB_EXPIRED"));
}

UniValue Pad(size_t bytes)
{
    // Strings are capped at 8 KiB by the canonical codec; an array of them is not.
    UniValue arr(UniValue::VARR);
    for (size_t used = 0; used < bytes; used += 8000) arr.push_back(std::string(8000, 'x'));
    return arr;
}

// P8. Stored records are bounded so get/list replies fit the helper reply cap.
BOOST_AUTO_TEST_CASE(record_size_is_bounded)
{
    std::vector<unsigned char> pk, sk, apk, ask;
    const fs::path dir = NewDir(m_path_root, "r-size", pk, sk);
    std::string gen_err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(apk, ask, gen_err));
    const std::string me = HexStr(pk), A = HexStr(apk);
    UniValue big = Offer(A, Keys({A}), Keys({A}), "PREPAID", 1'000'000, "big");
    big.pushKV("note", Pad(200 * 1024));
    BOOST_CHECK(Refused(dir, "importcomputeoffer", Envelope(SignEnvelope("ComputeOffer", apk, ask, big)), "COMPUTE_RECORD_INVALID"));
    UniValue mine = Offer(me, Keys({me}), Keys({me}), "PREPAID", 1'000'000, "big-local");
    mine.pushKV("note", Pad(200 * 1024));
    UniValue req(UniValue::VOBJ);
    req.pushKV("offer", mine);
    req.pushKV("now_ms", 1000);
    BOOST_CHECK(Refused(dir, "createcomputeoffer", req, "COMPUTE_RECORD_INVALID"));
    BOOST_CHECK_EQUAL(Call(dir, "listcomputeoffers", UniValue(UniValue::VOBJ))["records"].size(), 0u);
}

// Properties checked with no defect found (pass before and after the patch).
BOOST_AUTO_TEST_CASE(passport_rate_and_privacy_properties)
{
    uint64_t rate = 0;
    std::string err;
    BOOST_CHECK(!pwc::MicrounitsPerHour(0, 1, rate, err));
    BOOST_CHECK(!pwc::MicrounitsPerHour(1, 0, rate, err));
    BOOST_CHECK(!pwc::MicrounitsPerHour(100000, 1, rate, err));
    BOOST_CHECK_EQUAL(err, "COMPUTE_CREDIT_OVERFLOW");
    BOOST_CHECK(pwc::MicrounitsPerHour(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), rate, err) || err == "COMPUTE_CREDIT_OVERFLOW");
    BOOST_CHECK(pwc::MicrounitsPerHour(3, 7, rate, err));
    BOOST_CHECK_EQUAL(rate, (uint64_t{3} * 3'600'000'000'000'000ull) / 7);
    for (size_t n : {size_t{99}, size_t{100}}) {
        pwc::PassportSamples s;
        s.profile_name = "btx-rc-p1e-toy-v1";
        s.wall_us.assign(n, 1'000'000);
        UniValue p;
        BOOST_REQUIRE(pwc::BuildPassport(s, p, err));
        BOOST_CHECK_EQUAL(p["p99_claimable"].get_bool(), n >= 100);
        BOOST_CHECK_EQUAL(p["p1e_microunits_per_hour"].getInt<uint64_t>(), 3'600'000'000u);
        const std::string text = p.write();
        for (const char* k : {"hostname", "\"host\"", "username", "\"user\"", "serial", "\"path\""}) {
            BOOST_CHECK_MESSAGE(text.find(k) == std::string::npos, "passport carries " << k);
        }
    }
    pwc::PassportSamples zero;
    zero.profile_name = "btx-rc-p1e-toy-v1";
    zero.wall_us = {0};
    UniValue p;
    BOOST_CHECK(!pwc::BuildPassport(zero, p, err));
    pwc::PassportSamples over;
    over.profile_name = "btx-rc-p1e-toy-v1";
    over.wall_us = {std::numeric_limits<uint64_t>::max(), 1};
    BOOST_CHECK(!pwc::BuildPassport(over, p, err));
    BOOST_CHECK_EQUAL(err, "COMPUTE_CREDIT_OVERFLOW");
}

BOOST_AUTO_TEST_SUITE_END()
