// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <test/util/setup_common.h>
#include <pqkey.h>
#include <modelnet/catalog.h>
#include <modelnet/crypto.h>
#include <modelnet/helper.h>
#include <modelnet/transfer.h>
#include <span.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#ifdef ENABLE_WALLET
#include <core_io.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <rpc/util.h>
#include <script/script.h>
#include <uint256.h>
#include <validation.h>
#include <wallet/model_funding.h>
#include <wallet/model_payment.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#endif

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_funding_tests, BasicTestingSetup)

static std::vector<unsigned char> MakePattern(size_t n, unsigned char seed)
{
    std::vector<unsigned char> v(n);
    for (size_t i = 0; i < n; ++i) {
        v[i] = static_cast<unsigned char>(seed + i);
    }
    return v;
}

#ifdef ENABLE_WALLET
static wallet::FrozenFundingQuote SampleQuote()
{
    wallet::FrozenFundingQuote q;
    q.release_id = "aa";
    q.key_hash_hex = HexStr(MakePattern(32, 0x11));
    q.claimant_key = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x21));
    q.refund_key = HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x31));
    q.refund_height = 1024;
    q.amount_atoms = 100000;
    return q;
}
#endif

static modelnet::FrozenModelFunding SampleFrozenFunding()
{
    modelnet::FrozenModelFunding f;
    f.key_hash_hex = HexStr(MakePattern(32, 0x11));
    f.claimant = HexStr(MakePattern(32, 0x21));
    f.refund_pubkey = HexStr(MakePattern(32, 0x31));
    f.refund_height = 1024;
    f.amount_atoms = 100000;
    f.max_atoms = 200000;
    return f;
}

#ifdef ENABLE_WALLET
BOOST_AUTO_TEST_CASE(check_quote_refuses_auto_pay_zero)
{
    wallet::ModelPaymentPolicy policy;
    policy.auto_pay = false;
    policy.budget_atoms = 0;
    modelnet::Quote quote;
    quote.price_atoms = 1;
    quote.fee_cap_atoms = 0;
    std::string err;
    BOOST_CHECK(!policy.CheckQuote(quote, err));
    BOOST_CHECK(err.find("automatic BTX spend is zero") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(check_quote_refuses_auto_pay_true)
{
    wallet::ModelPaymentPolicy policy;
    policy.auto_pay = true;
    policy.budget_atoms = 1'000'000;
    modelnet::Quote quote;
    quote.price_atoms = 1;
    std::string err;
    BOOST_CHECK(!policy.CheckQuote(quote, err));
    BOOST_CHECK(err.find("auto_pay is refused") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(prepare_rejects_negative_amounts)
{
    std::string err;
    BOOST_CHECK(!wallet::ValidateFundingAmount(-1, err));
    BOOST_CHECK(err.find("negative") != std::string::npos);
    BOOST_CHECK(!wallet::ValidateFundingAmount(0, err));
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("amount_atoms", -5);
    wallet::FrozenFundingQuote q;
    BOOST_CHECK(!wallet::ParseFrozenFundingQuote(opts, q, err));
    BOOST_CHECK(err.find("negative") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(auto_pay_option_refused)
{
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("auto_pay", true);
    std::string err;
    BOOST_CHECK(!wallet::RejectAutoPay(opts, err));
    BOOST_CHECK(err.find("auto_pay is refused") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(canonical_atom_inputs_and_fee_ceiling)
{
    std::string err;
    int64_t amount = -1;
    for (const std::string& text : {"0", "1", "10000000"}) {
        BOOST_REQUIRE(wallet::ParseFundingAtoms(UniValue(text), amount, err));
        BOOST_CHECK_EQUAL(std::to_string(amount), text);
    }
    for (const std::string& text : {"", "01", "+1", "-1", "1.0", "1e3", " 1", "1 ", "9223372036854775808"}) {
        BOOST_CHECK(!wallet::ParseFundingAtoms(UniValue(text), amount, err));
    }
    UniValue options(UniValue::VOBJ);
    options.pushKV("amount_atoms", "10000000");
    options.pushKV("fee_cap_atoms", "0");
    wallet::FrozenFundingQuote q;
    BOOST_REQUIRE(wallet::ParseFrozenFundingQuote(options, q, err));
    BOOST_CHECK_EQUAL(q.amount_atoms, 10000000);
    BOOST_CHECK_EQUAL(q.fee_cap_atoms, 0);
    BOOST_CHECK(q.fee_cap_set);
    options.pushKV("max_atoms", "9999999");
    BOOST_CHECK(!wallet::ParseFrozenFundingQuote(options, q, err));
}

BOOST_AUTO_TEST_CASE(auto_spend_aliases_cannot_hide_each_other)
{
    std::string err;
    for (const std::string& name : {"auto_pay", "autopay", "automatic_spend", "automatic_spend_atoms"}) {
        for (const std::string& value : {"true", "1", "00", "0.0", "-1", "no"}) {
            UniValue options(UniValue::VOBJ);
            options.pushKV("auto_pay", false);
            options.pushKV(name, value);
            BOOST_CHECK(!wallet::RejectAutoPay(options, err));
        }
    }
    UniValue options(UniValue::VOBJ);
    options.pushKV("auto_pay", false);
    options.pushKV("automatic_spend_atoms", "0");
    BOOST_CHECK(wallet::RejectAutoPay(options, err));
    options.pushKV("autopay", true);
    BOOST_CHECK(!wallet::RejectAutoPay(options, err));
}

BOOST_AUTO_TEST_CASE(forbidden_htlc_sha256_tx)
{
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("htlc", "htlc_sha256_tx");
    std::string err;
    BOOST_CHECK(!wallet::RejectForbiddenHtlc(opts, err));
    opts = UniValue(UniValue::VOBJ);
    opts.pushKV("descriptor", "mr(htlc_tx(00112233445566778899aabbccddeeff00112233,aa))");
    BOOST_CHECK(!wallet::RejectForbiddenHtlc(opts, err));
}

BOOST_AUTO_TEST_CASE(build_htlc_sha256_descriptor)
{
    wallet::FrozenFundingQuote q = SampleQuote();
    std::string err;
    BOOST_REQUIRE(wallet::BuildHtlcSha256Descriptor(q, err));
    BOOST_CHECK(q.descriptor.find("htlc_sha256(") != std::string::npos);
    BOOST_CHECK(q.descriptor.find("htlc_tx(") == std::string::npos);
    BOOST_CHECK(q.descriptor.find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(!q.output_script.empty());

    q.refund_height = LOCKTIME_THRESHOLD;
    BOOST_CHECK(!wallet::BuildHtlcSha256Descriptor(q, err));
    BOOST_CHECK(err.find("block height") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(freeze_model_funding_rejects_timestamp_refund)
{
    modelnet::FrozenModelFunding in = SampleFrozenFunding();
    in.refund_height = LOCKTIME_THRESHOLD;
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("block height") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(expand_rejects_an_extra_spend_leaf)
{
    const wallet::FrozenFundingQuote q = SampleQuote();
    const std::string extra = "mr(" + q.claimant_key + ",{htlc_sha256(" + q.key_hash_hex + "," + q.claimant_key +
                              "),refund(" + std::to_string(q.refund_height) + "," + q.refund_key + ")})";
    CScript script;
    std::string canonical, err;
    BOOST_CHECK(!wallet::ExpandHtlcSha256Descriptor(extra, script, canonical, err));
    BOOST_CHECK(err.find("exactly one") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(expand_rejects_pk_leaf_whose_key_bytes_contain_cltv_drop)
{
    // The refund-leaf check scanned bytes for OP_CHECKLOCKTIMEVERIFY OP_DROP,
    // so a plain key leaf (no timelock) whose key bytes contain 0xb1 0x75 counted as a refund leaf.
    const wallet::FrozenFundingQuote q = SampleQuote();
    std::vector<unsigned char> key = MakePattern(MLDSA44_PUBKEY_SIZE, 0x41);
    key[100] = 0xb1;
    key[101] = 0x75;
    const std::string pk_leaf = "mr(htlc_sha256(" + q.key_hash_hex + "," + q.claimant_key + ")," + HexStr(key) + ")";
    CScript script;
    std::string canonical, err;
    BOOST_CHECK(!wallet::ExpandHtlcSha256Descriptor(pk_leaf, script, canonical, err));
    BOOST_CHECK_MESSAGE(err.find("exactly one") != std::string::npos, err);
    // The real two-leaf lock still expands.
    const std::string good = "mr(htlc_sha256(" + q.key_hash_hex + "," + q.claimant_key + "),refund(" +
                             std::to_string(q.refund_height) + "," + q.refund_key + "))";
    err.clear();
    BOOST_CHECK_MESSAGE(wallet::ExpandHtlcSha256Descriptor(good, script, canonical, err), err);
    // A refund leaf whose key bytes contain b175 is still a refund leaf.
    const std::string good_b175 = "mr(htlc_sha256(" + q.key_hash_hex + "," + q.claimant_key + "),refund(" +
                                  std::to_string(q.refund_height) + "," + HexStr(key) + "))";
    err.clear();
    BOOST_CHECK_MESSAGE(wallet::ExpandHtlcSha256Descriptor(good_b175, script, canonical, err), err);
}

BOOST_AUTO_TEST_CASE(quote_mutation_requires_fresh_prepare)
{
    wallet::FrozenFundingQuote q = SampleQuote();
    std::string err;
    BOOST_REQUIRE(wallet::BuildHtlcSha256Descriptor(q, err));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(q.amount_atoms, q.output_script);
    q.unsigned_hex = EncodeHexTx(CTransaction(mtx));
    q.unsigned_txid = mtx.GetHash().ToUint256();

    BOOST_CHECK(wallet::MatchFrozenTemplate(q, mtx, err));

    CMutableTransaction signed_same = mtx;
    signed_same.vin[0].scriptSig << OP_TRUE;
    BOOST_CHECK(wallet::MatchFrozenTemplate(q, signed_same, err));

    CMutableTransaction mutated = mtx;
    mutated.vin[0].prevout.n = 1;
    BOOST_CHECK(!wallet::MatchFrozenTemplate(q, mutated, err));
    BOOST_CHECK(err.find("txid mutated") != std::string::npos);

    CMutableTransaction script_changed = mtx;
    script_changed.vout[0].scriptPubKey.clear();
    script_changed.vout[0].scriptPubKey << OP_TRUE;
    BOOST_CHECK(!wallet::MatchFrozenTemplate(q, script_changed, err));

    wallet::FrozenFundingQuote script_mismatch = q;
    script_mismatch.output_script.clear();
    script_mismatch.output_script << OP_TRUE;
    BOOST_CHECK(!wallet::MatchFrozenTemplate(script_mismatch, mtx, err));
    BOOST_CHECK(err.find("output script") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(sign_rebuilds_htlc_and_ignores_caller_script)
{
    wallet::FrozenFundingQuote terms = SampleQuote();
    std::string err;
    BOOST_REQUIRE(wallet::BuildHtlcSha256Descriptor(terms, err));
    const CScript real = terms.output_script;

    CMutableTransaction good;
    good.vout.emplace_back(terms.amount_atoms, real);
    wallet::FrozenFundingQuote echoed = SampleQuote();
    echoed.output_script.clear();
    echoed.output_script << OP_TRUE;
    echoed.unsigned_txid = uint256::ONE;
    BOOST_CHECK_MESSAGE(wallet::MatchRebuiltHtlc(echoed, good, /*change_wallet=*/nullptr, err), err);
    BOOST_CHECK(echoed.output_script == real);

    CMutableTransaction attacker;
    attacker.vout.emplace_back(terms.amount_atoms, CScript() << OP_TRUE);
    wallet::FrozenFundingQuote attacker_quote = SampleQuote();
    attacker_quote.output_script.clear();
    attacker_quote.output_script << OP_TRUE;
    attacker_quote.unsigned_txid = attacker.GetHash().ToUint256();
    // MatchFrozenTemplate only echoes the caller script and txid.
    BOOST_CHECK(wallet::MatchFrozenTemplate(attacker_quote, attacker, err));
    BOOST_CHECK(!wallet::MatchRebuiltHtlc(attacker_quote, attacker, /*change_wallet=*/nullptr, err));
    BOOST_CHECK(err.find("missing") != std::string::npos || err.find("changed") != std::string::npos ||
                err.find("unauthorized") != std::string::npos);

    CMutableTransaction extra = good;
    extra.vout.emplace_back(1, CScript() << OP_RETURN << std::vector<unsigned char>{0x01});
    wallet::FrozenFundingQuote extra_quote = SampleQuote();
    BOOST_CHECK(!wallet::MatchRebuiltHtlc(extra_quote, extra, /*change_wallet=*/nullptr, err));
    BOOST_CHECK(err.find("unauthorized") != std::string::npos);

    CMutableTransaction low = good;
    low.vout[0].nValue = terms.amount_atoms - 1;
    wallet::FrozenFundingQuote low_quote = SampleQuote();
    BOOST_CHECK(!wallet::MatchRebuiltHtlc(low_quote, low, /*change_wallet=*/nullptr, err));
    BOOST_CHECK(err.find("amount") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(export_recovery_is_public_only)
{
    wallet::FrozenFundingQuote q = SampleQuote();
    std::string err;
    BOOST_REQUIRE(wallet::BuildHtlcSha256Descriptor(q, err));
    const UniValue out = wallet::ExportModelRecoveryJson(q);
    BOOST_CHECK_EQUAL(out["schema_version"].getInt<int>(), 2);
    BOOST_CHECK(out.exists("descriptor"));
    BOOST_CHECK(out.exists("key_hash"));
    BOOST_CHECK(out.exists("refund_height"));
    BOOST_CHECK_EQUAL(out["secrets"].get_bool(), false);
    BOOST_CHECK_EQUAL(out["wallet_seed"].get_bool(), false);
    BOOST_CHECK_EQUAL(out["service_sk"].get_bool(), false);
    BOOST_CHECK(!out.exists("seed"));
    BOOST_CHECK(!out.exists("secret32"));
    BOOST_CHECK(!out.exists("mnemonic"));
    BOOST_CHECK_EQUAL(out["use_claim"].get_str(), "buildhtlcclaim");
}

BOOST_AUTO_TEST_CASE(rpcarg_obj_has_inner_vector)
{
    const RPCArg options{"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "opts", {
        {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte SHA-256 hex"},
        {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "atoms"},
    }};
    BOOST_CHECK_EQUAL(options.m_inner.size(), 2U);
}
#endif // ENABLE_WALLET

BOOST_AUTO_TEST_CASE(htlc_sha256_descriptor_contains_mr_and_refund)
{
    const std::string desc = modelnet::HtlcSha256Descriptor(
        HexStr(MakePattern(32, 0x11)), "claimant_hex", 1024, "refund_hex");
    BOOST_CHECK(desc.find("mr(htlc_sha256(") != std::string::npos);
    BOOST_CHECK(desc.find("refund(") != std::string::npos);
    BOOST_CHECK(desc.find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(desc.find("buildmodelhtlcclaim") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(freeze_model_funding_descriptor_mr_htlc_sha256)
{
    const modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(out.descriptor.find("mr(htlc_sha256(") != std::string::npos);
    BOOST_CHECK(out.descriptor.find("refund(") != std::string::npos);
    BOOST_CHECK(out.descriptor.find("htlc_sha256(") != std::string::npos);
    BOOST_CHECK(!out.fingerprint.empty());
}

BOOST_AUTO_TEST_CASE(freeze_model_funding_never_htlc_sha256_tx_or_buildmodelhtlcclaim)
{
    const modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(out.descriptor.find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(out.descriptor.find("buildmodelhtlcclaim") == std::string::npos);
    BOOST_CHECK(out.fingerprint.find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(out.fingerprint.find("buildmodelhtlcclaim") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(freeze_model_funding_rejects_zero_or_negative_amount)
{
    modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    in.amount_atoms = 0;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("amount") != std::string::npos);
    in.amount_atoms = -1;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("amount") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(freeze_model_funding_rejects_amount_over_max_atoms)
{
    modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding out;
    std::string err;
    in.amount_atoms = 100000;
    in.max_atoms = 99999;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(err.find("max_atoms") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(funding_unchanged_false_on_fingerprint_change)
{
    const modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding frozen;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, frozen, err));

    modelnet::FrozenModelFunding now = frozen;
    now.fingerprint = frozen.fingerprint + "ff";
    BOOST_CHECK(!modelnet::FundingUnchanged(frozen, now, err));

    modelnet::FrozenModelFunding mutated = in;
    mutated.amount_atoms = in.amount_atoms + 1;
    modelnet::FrozenModelFunding other;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(mutated, other, err));
    BOOST_CHECK(other.fingerprint != frozen.fingerprint);
    BOOST_CHECK(!modelnet::FundingUnchanged(frozen, other, err));
}

BOOST_AUTO_TEST_CASE(funding_unchanged_true_on_same_freeze)
{
    const modelnet::FrozenModelFunding in = SampleFrozenFunding();
    modelnet::FrozenModelFunding first;
    modelnet::FrozenModelFunding second;
    std::string err;
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, first, err));
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, second, err));
    BOOST_CHECK_EQUAL(first.fingerprint, second.fingerprint);
    BOOST_CHECK(modelnet::FundingUnchanged(first, second, err));
    BOOST_CHECK(modelnet::FundingUnchanged(first, first, err));
}

BOOST_AUTO_TEST_CASE(helper_prepare_sign_submit_claim_refund_implemented)
{
    const fs::path tmp = m_args.GetDataDirBase() / "helper-funding";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    modelnet::FrozenModelFunding sample = SampleFrozenFunding();
    sample.claimant = HexStr(std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0x21));
    sample.refund_pubkey = HexStr(std::vector<unsigned char>(MLDSA44_PUBKEY_SIZE, 0x31));
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("key_hash", sample.key_hash_hex);
    opts.pushKV("claimant", sample.claimant);
    opts.pushKV("refund_pubkey", sample.refund_pubkey);
    opts.pushKV("refund_height", static_cast<int>(sample.refund_height));
    opts.pushKV("amount_atoms", sample.amount_atoms);
    opts.pushKV("max_atoms", sample.max_atoms);
    UniValue in0(UniValue::VOBJ);
    in0.pushKV("txid", uint256::ONE.GetHex());
    in0.pushKV("vout", 0);
    in0.pushKV("amount_atoms", sample.amount_atoms + 1000);
    UniValue inputs(UniValue::VARR);
    inputs.push_back(in0);
    opts.pushKV("inputs", inputs);
    UniValue req(UniValue::VOBJ);
    UniValue params(UniValue::VARR);
    params.push_back(opts);
    req.pushKV("method", "preparemodelfunding");
    req.pushKV("params", params);
    UniValue prepared;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, prepared, code, err), err);
    BOOST_CHECK(prepared["implemented"].get_bool());
    BOOST_CHECK_EQUAL(prepared["htlc"].get_str(), "htlc_sha256");
    BOOST_CHECK(prepared["descriptor"].get_str().find("htlc_sha256(") != std::string::npos);
    BOOST_CHECK(prepared["descriptor"].get_str().find("htlc_sha256_tx") == std::string::npos);
    BOOST_CHECK(prepared.exists("unsigned_hex"));
    BOOST_CHECK_EQUAL(prepared["automatic_spend"].getInt<int64_t>(), 0);

    UniValue auto_pay(opts);
    auto_pay.pushKV("auto_pay", true);
    UniValue bad(UniValue::VOBJ);
    UniValue badp(UniValue::VARR);
    badp.push_back(auto_pay);
    bad.pushKV("method", "preparemodelfunding");
    bad.pushKV("params", badp);
    UniValue badres;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, bad, badres, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue forbidden(opts);
    forbidden.pushKV("htlc", "htlc_sha256_tx");
    UniValue fp(UniValue::VARR);
    fp.push_back(forbidden);
    UniValue fr(UniValue::VOBJ);
    fr.pushKV("method", "preparemodelfunding");
    fr.pushKV("params", fp);
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, fr, badres, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue sign(UniValue::VOBJ);
    UniValue sp(UniValue::VARR);
    sp.push_back(prepared["unsigned_hex"].get_str());
    UniValue sopt(UniValue::VOBJ);
    sopt.pushKV("unsigned_txid", prepared["unsigned_txid"].get_str());
    sopt.pushKV("output_script", prepared["output_script"].get_str());
    sopt.pushKV("amount_atoms", sample.amount_atoms);
    sp.push_back(sopt);
    sign.pushKV("method", "signmodelfunding");
    sign.pushKV("params", sp);
    UniValue signed_res;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, sign, signed_res, code, err), err);
    BOOST_CHECK_EQUAL(signed_res["complete"].get_bool(), false);
    BOOST_CHECK(signed_res["implemented"].get_bool());

    UniValue submit(UniValue::VOBJ);
    UniValue up(UniValue::VARR);
    up.push_back(signed_res["hex"].get_str());
    submit.pushKV("method", "submitmodelfunding");
    submit.pushKV("params", up);
    UniValue submitted;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, submit, submitted, code, err), err);
    BOOST_CHECK(submitted["submitted"].get_bool());
    BOOST_CHECK(!submitted["duplicate"].get_bool());
    BOOST_CHECK(!submitted["broadcast"].get_bool());
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, submit, submitted, code, err), err);
    BOOST_CHECK(submitted["duplicate"].get_bool());

    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 3);
    const modelnet::Hash32 kh = modelnet::Sha256(Span<const unsigned char>{secret, 32});
    UniValue claim_opts(UniValue::VOBJ);
    claim_opts.pushKV("key_hash", kh.Hex());
    claim_opts.pushKV("claimant", sample.claimant);
    claim_opts.pushKV("refund_pubkey", sample.refund_pubkey);
    claim_opts.pushKV("refund_height", static_cast<int>(sample.refund_height));
    claim_opts.pushKV("preimage", HexStr(Span{secret, 32}));
    UniValue prev(UniValue::VOBJ);
    prev.pushKV("txid", uint256::ONE.GetHex());
    prev.pushKV("vout", 0);
    claim_opts.pushKV("prevout", prev);
    claim_opts.pushKV("destination_script", "51");
    claim_opts.pushKV("amount_atoms", 50000);
    claim_opts.pushKV("fee_atoms", 1000);
    UniValue claim(UniValue::VOBJ);
    UniValue cp(UniValue::VARR);
    cp.push_back(claim_opts);
    claim.pushKV("method", "buildmodelhtlcclaim");
    claim.pushKV("params", cp);
    UniValue claimed;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, claim, claimed, code, err), err);
    BOOST_CHECK(claimed["implemented"].get_bool());
    BOOST_CHECK_EQUAL(claimed["complete"].get_bool(), false);
    BOOST_CHECK_EQUAL(claimed["selected_path"].get_str(), "claim");
    BOOST_CHECK(claimed.exists("hex"));

    UniValue wrong = claim_opts;
    wrong.pushKV("preimage", std::string(64, '0'));
    UniValue wp(UniValue::VARR);
    wp.push_back(wrong);
    UniValue wreq(UniValue::VOBJ);
    wreq.pushKV("method", "buildmodelhtlcclaim");
    wreq.pushKV("params", wp);
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, wreq, badres, code, err));
    BOOST_CHECK_EQUAL(code, "PREIMAGE_MISMATCH");

    UniValue refund_opts(UniValue::VOBJ);
    refund_opts.pushKV("key_hash", sample.key_hash_hex);
    refund_opts.pushKV("claimant", sample.claimant);
    refund_opts.pushKV("refund_pubkey", sample.refund_pubkey);
    refund_opts.pushKV("refund_height", static_cast<int>(sample.refund_height));
    refund_opts.pushKV("prevout", prev);
    refund_opts.pushKV("destination_script", "51");
    refund_opts.pushKV("amount_atoms", 50000);
    UniValue refund(UniValue::VOBJ);
    UniValue rp(UniValue::VARR);
    rp.push_back(refund_opts);
    refund.pushKV("method", "buildmodelhtlcrefund");
    refund.pushKV("params", rp);
    UniValue refunded;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, refund, refunded, code, err), err);
    BOOST_CHECK(refunded["implemented"].get_bool());
    BOOST_CHECK_EQUAL(refunded["selected_path"].get_str(), "refund");

    UniValue exp(UniValue::VOBJ);
    UniValue ep(UniValue::VARR);
    ep.push_back(opts);
    exp.pushKV("method", "exportmodelrecovery");
    exp.pushKV("params", ep);
    UniValue exported;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, exp, exported, code, err), err);
    BOOST_CHECK_EQUAL(exported["secrets"].get_bool(), false);
    BOOST_CHECK_EQUAL(exported["use_claim"].get_str(), "buildmodelhtlcclaim");
}

#ifdef ENABLE_WALLET
// With no prepare record in this process (restart, or a template built
// elsewhere), CompareStoredSkeleton accepts and CheckFundingInputsAndFee is
// the only input and fee guard before signing or broadcast.
static wallet::FrozenFundingQuote WalletQuote(wallet::CWallet& wallet)
{
    wallet::FrozenFundingQuote q = SampleQuote();
    q.refund_key.clear();
    std::string err;
    BOOST_REQUIRE_MESSAGE(wallet::EnsureModelRefundKey(wallet, q, err), err);
    BOOST_REQUIRE_MESSAGE(wallet::BuildHtlcSha256Descriptor(q, err), err);
    q.fee_cap_set = true;
    return q;
}

static CMutableTransaction FundingSpend(const COutPoint& prevout, const wallet::FrozenFundingQuote& q)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(q.amount_atoms, q.output_script);
    return tx;
}

BOOST_FIXTURE_TEST_CASE(submission_refuses_fee_above_frozen_cap, TestChain100Setup)
{
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    wallet::FrozenFundingQuote q = WalletQuote(*wallet);
    const CTransactionRef& coin = m_coinbase_txns.at(0);
    const CMutableTransaction tx = FundingSpend(COutPoint{coin->GetHash(), 0}, q);
    const CAmount fee = coin->vout[0].nValue - q.amount_atoms;
    std::string err;

    q.fee_cap_atoms = fee;
    BOOST_CHECK_MESSAGE(wallet::ValidateFrozenFundingSubmission(*wallet, q, tx, /*already_known=*/false, err), err);

    q.fee_cap_atoms = fee - 1;
    BOOST_CHECK(!wallet::ValidateFrozenFundingSubmission(*wallet, q, tx, /*already_known=*/false, err));
    BOOST_CHECK_EQUAL(err, "funding fee exceeds the frozen fee_cap_atoms");
}

BOOST_FIXTURE_TEST_CASE(submission_refuses_input_not_owned_by_wallet, TestChain100Setup)
{
    const CBlock foreign = CreateAndProcessBlock({}, CScript() << OP_TRUE);
    auto wallet = wallet::CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    wallet::FrozenFundingQuote q = WalletQuote(*wallet);
    q.fee_cap_atoms = MAX_MONEY;
    std::string err;

    const CTransactionRef& own = m_coinbase_txns.at(0);
    BOOST_CHECK_MESSAGE(wallet::ValidateFrozenFundingSubmission(*wallet, q, FundingSpend(COutPoint{own->GetHash(), 0}, q), /*already_known=*/false, err), err);

    const CTransactionRef& other = foreign.vtx.at(0);
    BOOST_CHECK(!wallet::ValidateFrozenFundingSubmission(*wallet, q, FundingSpend(COutPoint{other->GetHash(), 0}, q), /*already_known=*/false, err));
    BOOST_CHECK_EQUAL(err, "funding input is not owned by this wallet");
}
#endif // ENABLE_WALLET

BOOST_AUTO_TEST_SUITE_END()
