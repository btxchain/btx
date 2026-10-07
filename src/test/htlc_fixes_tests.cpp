// HTLC hardening review, second pass: regression tests for the proposed fixes.
//
// Every case here FAILS on an unpatched v0.34.13 tree and PASSES with
// htlc-fixes.patch, except the two randomized parser runs at the end, which
// check invariants that must hold on both.
//
// Signatures are real ML-DSA-44 signatures checked through VerifyScript with a
// MutableTransactionSignatureChecker, as block validation does.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <core_io.h>
#include <hash.h>
#include <modelnet/catalog.h>
#include <modelnet/funding.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <univalue.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <addresstype.h>
#ifdef ENABLE_WALLET
#include <wallet/walletutil.h>
#endif

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

// Block flags before the HTLC preimage rule activates: what v0.34.12 enforced.
constexpr unsigned int PRE_ACTIVATION_BLOCK_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_CHECKTEMPLATEVERIFY | SCRIPT_VERIFY_CHECKSIGFROMSTACK |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY;

Bytes Sha256Bytes(Span<const unsigned char> data)
{
    uint256 h;
    CSHA256().Write(data.data(), data.size()).Finalize(h.begin());
    return {h.begin(), h.end()};
}

Bytes Hash160Bytes(Span<const unsigned char> data)
{
    const uint160 h = Hash160(data);
    return {h.begin(), h.end()};
}

CPQKey NewKey()
{
    CPQKey k;
    k.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(k.IsValid());
    return k;
}

struct HtlcTree {
    Bytes claim_leaf;
    Bytes refund_leaf;
    Bytes claim_control;
    CScript spk;
};

HtlcTree MakeTree(Bytes claim_leaf, Bytes refund_leaf)
{
    HtlcTree t;
    t.claim_leaf = std::move(claim_leaf);
    t.refund_leaf = std::move(refund_leaf);
    BOOST_REQUIRE(!t.claim_leaf.empty() && !t.refund_leaf.empty());
    const uint256 ch = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.claim_leaf);
    const uint256 rh = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.refund_leaf);
    const uint256 root = ComputeP2MRMerkleRoot({ch, rh});
    t.claim_control.assign(1, P2MR_LEAF_VERSION);
    t.claim_control.insert(t.claim_control.end(), rh.begin(), rh.end());
    t.spk << OP_2 << ToByteVector(root);
    return t;
}

//! Sign the claim leaf of `t` with `key` and verify a witness carrying `preimage`.
bool VerifyClaim(const HtlcTree& t, const CPQKey& key, const Bytes& preimage, unsigned int flags, ScriptError& err)
{
    CMutableTransaction credit = BuildCreditingTransaction(t.spk, /*nValue=*/100000);
    CMutableTransaction tx = BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{credit});
    tx.vin.at(0).nSequence = MAX_BIP125_RBF_SEQUENCE;
    tx.vout.at(0).nValue = 90000;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {credit.vout.at(0)}, /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.claim_leaf);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, tx, 0, SIGHASH_DEFAULT, SigVersion::P2MR, txdata, MissingDataBehavior::ASSERT_FAIL));
    Bytes sig;
    BOOST_REQUIRE(key.Sign(sighash, sig));

    tx.vin.at(0).scriptWitness.stack = {sig, preimage, t.claim_leaf, t.claim_control};
    PrecomputedTransactionData txdata2;
    txdata2.Init(tx, {credit.vout.at(0)}, /*force=*/true);
    err = SCRIPT_ERR_UNKNOWN_ERROR;
    return VerifyScript(CScript{}, credit.vout.at(0).scriptPubKey, &tx.vin.at(0).scriptWitness, flags,
                        MutableTransactionSignatureChecker(&tx, 0, credit.vout.at(0).nValue, txdata2, MissingDataBehavior::ASSERT_FAIL),
                        &err);
}

std::string Pattern(size_t n, unsigned char seed)
{
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<unsigned char>(seed + i);
    return HexStr(b);
}

std::string PQHDExpr(unsigned char seed)
{
    std::array<unsigned char, 32> s{};
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<unsigned char>(seed + i);
    const std::string coin_type = Params().IsTestChain() ? "1h" : "0h";
    return "pqhd(" + HexStr(s) + "/" + coin_type + "/0h/0/*)";
}

bool ParseOk(const std::string& desc, std::string& error)
{
    FlatSigningProvider provider;
    error.clear();
    return !Parse(desc, provider, error, /*require_checksum=*/false).empty();
}

//! Refund leaf: <minimal push of n> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG_*.
bool ParseRefundLeafPubkey(Span<const unsigned char> leaf, Bytes& pubkey)
{
    if (leaf.size() < 4) return false;
    size_t i{0};
    if (leaf[0] == OP_0 || (leaf[0] >= OP_1 && leaf[0] <= OP_16)) {
        i = 1;
    } else if (leaf[0] >= 0x01 && leaf[0] <= 0x4b) {
        i = 1 + leaf[0];
    } else {
        return false;
    }
    if (i + 2 > leaf.size() || leaf[i] != OP_CHECKLOCKTIMEVERIFY || leaf[i + 1] != OP_DROP) return false;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    Span<const unsigned char> pk;
    size_t used{0};
    if (!ParseP2MRAnyPubkeyPush(leaf, i + 2, algo, pk, used)) return false;
    if (leaf.size() != i + 2 + used + 1 || leaf[i + 2 + used] != GetP2MRChecksigOpcode(algo)) return false;
    pubkey.assign(pk.begin(), pk.end());
    return true;
}

bool ParseAnyClaimLeafPubkey(Span<const unsigned char> leaf, Bytes& pubkey)
{
    Bytes hash;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    return ParseP2MRHTLCSha256Leaf(leaf, hash, algo, pubkey) ||
           ParseP2MRHTLCSha256LegacyLeaf(leaf, hash, algo, pubkey) ||
           ParseP2MRHTLCTxLeaf(leaf, hash, algo, pubkey);
}

//! Expand a parsed P2MR descriptor at `pos` and return its leaf scripts.
bool ExpandLeaves(const Descriptor& desc, const FlatSigningProvider& keys, int pos, CScript& spk, std::vector<Bytes>& leaves)
{
    std::vector<CScript> scripts;
    FlatSigningProvider out;
    if (!desc.Expand(pos, keys, scripts, out) || scripts.empty()) return false;
    spk = scripts[0];
    int wv{-1};
    Bytes prog;
    if (!spk.IsWitnessProgram(wv, prog) || wv != 2 || prog.size() != 32) return false;
    P2MRSpendData spend;
    if (!out.GetP2MRSpendData(WitnessV2P2MR{uint256{prog}}, spend)) return false;
    for (const auto& [leaf, controls] : spend.scripts) leaves.push_back(leaf);
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(htlc_fixes_tests, BasicTestingSetup)

// F1: the 32-byte preimage rule on the legacy SHA-256 leaf and the HASH160
// htlc_tx leaf must be standard policy only until its activation height, so a
// fixed node keeps v0.34.12 consensus for those spends before activation.
BOOST_AUTO_TEST_CASE(fix_f1_preimage_rule_is_policy_until_activation)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const Bytes refund_leaf = BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey());

    struct Case { const char* name; Bytes preimage; bool sha256; };
    const std::vector<Case> cases{
        {"legacy sha256, 33-byte", Bytes(33, 0x42), true},
        {"legacy sha256, 16-byte", Bytes(16, 0x43), true},
        {"htlc_tx hash160, 20-byte", Bytes(20, 0x44), false},
        {"htlc_tx hash160, 64-byte", Bytes(64, 0x45), false},
    };
    for (const Case& c : cases) {
        const Bytes leaf = c.sha256
            ? BuildP2MRHTLCSha256LegacyLeaf(Sha256Bytes(c.preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey())
            : BuildP2MRHTLCTxLeaf(Hash160Bytes(c.preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey());
        const HtlcTree t = MakeTree(leaf, refund_leaf);
        ScriptError err;
        BOOST_CHECK_MESSAGE(VerifyClaim(t, claimer, c.preimage, PRE_ACTIVATION_BLOCK_FLAGS, err),
                            c.name << ": pre-activation block flags must accept (v0.34.12 consensus), got " << ScriptErrorString(err));
        BOOST_CHECK_MESSAGE(!VerifyClaim(t, claimer, c.preimage, STANDARD_SCRIPT_VERIFY_FLAGS, err) &&
                                err == SCRIPT_ERR_P2MR_HTLC_PREIMAGE_SIZE,
                            c.name << ": standard policy must reject, got " << ScriptErrorString(err));
    }

    // 32-byte preimages pass under both flag sets.
    const Bytes good(32, 0x46);
    const HtlcTree legacy32 = MakeTree(
        BuildP2MRHTLCSha256LegacyLeaf(Sha256Bytes(good), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()), refund_leaf);
    ScriptError err;
    BOOST_CHECK(VerifyClaim(legacy32, claimer, good, PRE_ACTIVATION_BLOCK_FLAGS, err));
    BOOST_CHECK(VerifyClaim(legacy32, claimer, good, STANDARD_SCRIPT_VERIFY_FLAGS, err));

    // The new leaf's own OP_SIZE check is ordinary script: it rejects a
    // 33-byte preimage under any flags, activation or not.
    const Bytes long_pre(33, 0x47);
    const HtlcTree current = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(long_pre), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()), refund_leaf);
    BOOST_CHECK(!VerifyClaim(current, claimer, long_pre, PRE_ACTIVATION_BLOCK_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EQUALVERIFY);
}

// F2: the claim and refund keys must differ for every claim/refund pair, and a
// repeated key expression is rejected even when it is not a fixed hex key.
BOOST_AUTO_TEST_CASE(fix_f2_distinct_keys_every_pair_and_key_expression)
{
    const std::string H = Pattern(32, 0x11);
    const std::string H20 = Pattern(20, 0x12);
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x13);
    const std::string S = Pattern(MLDSA44_PUBKEY_SIZE, 0x14);
    const std::string K = PQHDExpr(0x21);
    const std::string K2 = PQHDExpr(0x41);
    std::string error;

    BOOST_CHECK_MESSAGE(!ParseOk("mr(htlc_sha256(" + H + "," + K + "),refund(10," + K + "))", error),
                        "same pqhd() key in claim and refund must be rejected");
    BOOST_CHECK(error.find("distinct") != std::string::npos);

    BOOST_CHECK_MESSAGE(!ParseOk("mr(htlc_sha256(" + H + "," + C + "),{refund(10," + C + "),refund(20," + S + ")})", error),
                        "a claim key reused by any refund leaf must be rejected, not only the last one");
    BOOST_CHECK(error.find("distinct") != std::string::npos);

    BOOST_CHECK_MESSAGE(!ParseOk("mr(refund(10," + C + "),{htlc_tx(" + H20 + "," + C + "),htlc_sha256(" + H + "," + S + ")})", error),
                        "every claim leaf must be compared, not only the last one");

    // Distinct keys keep working.
    BOOST_CHECK_MESSAGE(ParseOk("mr(htlc_sha256(" + H + "," + K + "),refund(10," + K2 + "))", error), error);
    BOOST_CHECK_MESSAGE(ParseOk("mr(htlc_sha256(" + H + "," + C + "),refund(10," + S + "))", error), error);
}

// F3: htlc_sha256_legacy() names the pre-0.34.13 claim leaf, so a wallet can
// import, watch and spend a lock funded before 0.34.13. It is recovery-only.
BOOST_AUTO_TEST_CASE(fix_f3_legacy_sha256_descriptor)
{
    const std::string H = Pattern(32, 0x51);
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const std::string C = HexStr(claimer.GetPubKey());
    const std::string S = HexStr(sender.GetPubKey());

    const std::string legacy = "mr(htlc_sha256_legacy(" + H + "," + C + "),refund(700," + S + "))";
    FlatSigningProvider keys;
    std::string error;
    const auto parsed = Parse(legacy, keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), "htlc_sha256_legacy() must parse: " << error);
    CScript spk;
    std::vector<Bytes> leaves;
    BOOST_REQUIRE(ExpandLeaves(*parsed[0], keys, 0, spk, leaves));
    const HtlcTree expect = MakeTree(
        BuildP2MRHTLCSha256LegacyLeaf(ParseHex(H), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(700, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    BOOST_CHECK(spk == expect.spk);
    BOOST_CHECK(parsed[0]->ToString().find("htlc_sha256_legacy(") != std::string::npos);
    BOOST_CHECK(DescriptorIsRecoveryOnlyHtlc(legacy));

    // htlc_sha256() itself is unchanged: it still expands to the length-checked leaf.
    const std::string current = "mr(htlc_sha256(" + H + "," + C + "),refund(700," + S + "))";
    FlatSigningProvider keys2;
    const auto parsed2 = Parse(current, keys2, error, false);
    BOOST_REQUIRE(!parsed2.empty());
    CScript spk2;
    std::vector<Bytes> leaves2;
    BOOST_REQUIRE(ExpandLeaves(*parsed2[0], keys2, 0, spk2, leaves2));
    BOOST_CHECK(spk2 != expect.spk);
    BOOST_CHECK(!DescriptorIsRecoveryOnlyHtlc(current));

    // Same distinct-key rule as the other claim leaves.
    BOOST_CHECK(!ParseOk("mr(htlc_sha256_legacy(" + H + "," + C + "),refund(700," + C + "))", error));
}

// A wallet last written by 0.34.12 stored htlc_sha256() for the length-unchecked
// claim leaf. Loading that string with the pre-0.34.13 flag watches the same
// script, and the stored descriptor id still matches after the name is rewritten.
BOOST_AUTO_TEST_CASE(pre_03413_htlc_sha256_loads_as_legacy_leaf)
{
    const std::string H = Pattern(32, 0x51);
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const CPQKey extra = NewKey();
    const std::string C = HexStr(claimer.GetPubKey());
    const std::string S = HexStr(sender.GetPubKey());
    const std::string E = HexStr(extra.GetPubKey());
    const std::string body = "mr(htlc_sha256(" + H + "," + C + "),refund(700," + S + "))";
    const std::string checksummed = AddChecksum(body);

    FlatSigningProvider keys;
    std::string error;
    DescriptorParseOptions legacy_options;
    legacy_options.new_descriptor_rules = false;
    legacy_options.pre_03413_htlc_sha256 = true;
    const auto legacy = Parse(checksummed, keys, error, /*require_checksum=*/true, legacy_options);
    BOOST_REQUIRE_MESSAGE(!legacy.empty(), error);
    CScript legacy_spk;
    std::vector<Bytes> legacy_leaves;
    BOOST_REQUIRE(ExpandLeaves(*legacy[0], keys, 0, legacy_spk, legacy_leaves));
    const HtlcTree expect = MakeTree(
        BuildP2MRHTLCSha256LegacyLeaf(ParseHex(H), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(700, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    BOOST_CHECK(legacy_spk == expect.spk);
    BOOST_CHECK(legacy[0]->ToString().find("htlc_sha256_legacy(") != std::string::npos);

    FlatSigningProvider keys_now;
    const auto current = Parse(checksummed, keys_now, error, true);
    BOOST_REQUIRE(!current.empty());
    BOOST_CHECK(DescriptorMatchesStoredPre03413HtlcID(*legacy[0], DescriptorID(*current[0])));
    CScript current_spk;
    std::vector<Bytes> current_leaves;
    BOOST_REQUIRE(ExpandLeaves(*current[0], keys_now, 0, current_spk, current_leaves));
    BOOST_CHECK(current_spk != legacy_spk);

    const std::string flat = "mr(htlc_sha256(" + H + "," + C + "),refund(700," + S + ")," + E + ")";
    BOOST_CHECK(!ParseOk(flat, error));
    DescriptorParseOptions flat_options;
    flat_options.new_descriptor_rules = false;
    flat_options.pre_03413_htlc_sha256 = true;
    FlatSigningProvider flat_keys;
    const auto flat_legacy = Parse(AddChecksum(flat), flat_keys, error, true, flat_options);
    BOOST_REQUIRE_MESSAGE(!flat_legacy.empty(), error);
    uint256 flat_id;
    const std::string flat_checksummed = AddChecksum(flat);
    CSHA256().Write(reinterpret_cast<const unsigned char*>(flat_checksummed.data()), flat_checksummed.size()).Finalize(flat_id.begin());
    BOOST_CHECK(DescriptorMatchesStoredPre03413HtlcID(*flat_legacy[0], flat_id));
}

// F4: the modelnet claim/refund templates follow the 0.34.13 wallet rules.
BOOST_AUTO_TEST_CASE(fix_f4_modelnet_claim_and_refund_templates)
{
    const fs::path tmp = m_args.GetDataDirBase() / "htlc_fixes_modelnet";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x61);
    const std::string S = Pattern(MLDSA44_PUBKEY_SIZE, 0x62);
    const Bytes pre33(33, 0x63);
    const Bytes pre32(32, 0x64);
    auto descriptor = [&](const Bytes& pre) {
        return "mr(htlc_sha256(" + HexStr(Sha256Bytes(pre)) + "," + C + "),refund(500," + S + "))";
    };
    auto base = [&](const std::string& desc) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("descriptor", desc);
        UniValue prevout(UniValue::VOBJ);
        prevout.pushKV("txid", std::string(64, 'a'));
        prevout.pushKV("vout", 0);
        o.pushKV("prevout", prevout);
        o.pushKV("destination_script", "5220" + std::string(64, 'b'));
        o.pushKV("amount_atoms", 100000);
        o.pushKV("fee", 1000);
        return o;
    };
    auto call = [&](const std::string& method, const UniValue& o, UniValue& result, std::string& err) {
        UniValue params(UniValue::VARR);
        params.push_back(o);
        std::string code;
        result = UniValue{UniValue::VOBJ};
        err.clear();
        return modelnet::DispatchFundingRpc(cat, method, params, result, code, err);
    };

    UniValue result;
    std::string err;
    UniValue o33 = base(descriptor(pre33));
    o33.pushKV("preimage", HexStr(pre33));
    BOOST_CHECK_MESSAGE(!call("buildmodelhtlcclaim", o33, result, err), "a 33-byte preimage must be refused");
    BOOST_CHECK_MESSAGE(err.find("32 bytes") != std::string::npos, err);

    UniValue o32 = base(descriptor(pre32));
    o32.pushKV("preimage", HexStr(pre32));
    BOOST_REQUIRE_MESSAGE(call("buildmodelhtlcclaim", o32, result, err), err);
    CMutableTransaction mtx;
    BOOST_REQUIRE(DecodeHexTx(mtx, result["hex"].get_str()));
    BOOST_CHECK_EQUAL(mtx.vin.at(0).nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK_EQUAL(mtx.nLockTime, 0U);

    // Refund: nLockTime must satisfy the descriptor CLTV, and defaults to it.
    UniValue r_low = base(descriptor(pre32));
    r_low.pushKV("refund_height", 400);
    BOOST_CHECK_MESSAGE(!call("buildmodelhtlcrefund", r_low, result, err), "refund_height below the descriptor CLTV must be refused");
    UniValue r_def = base(descriptor(pre32));
    BOOST_REQUIRE_MESSAGE(call("buildmodelhtlcrefund", r_def, result, err), err);
    BOOST_REQUIRE(DecodeHexTx(mtx, result["hex"].get_str()));
    BOOST_CHECK_EQUAL(mtx.nLockTime, 500U);
    BOOST_CHECK_EQUAL(mtx.vin.at(0).nSequence, MAX_BIP125_RBF_SEQUENCE);
}

#ifdef ENABLE_WALLET
// Wallet compatibility: a wallet that imported an HTLC descriptor which
// v0.34.12 accepted (refund(0), or the same key in the claim and refund
// leaves) must still load. The stricter rules apply to new descriptors only.
BOOST_AUTO_TEST_CASE(fix_wallet_loads_descriptors_imported_by_older_versions)
{
    const std::string H = Pattern(32, 0x71);
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x72);
    const std::string S = Pattern(MLDSA44_PUBKEY_SIZE, 0x73);
    for (const std::string& body : {
             "mr(htlc_sha256(" + H + "," + C + "),refund(0," + S + "))",
             "mr(htlc_sha256(" + H + "," + C + "),refund(10," + C + "))"}) {
        const std::string with_checksum = body + "#" + GetDescriptorChecksum(body);
        wallet::WalletDescriptor w;
        BOOST_CHECK_NO_THROW(w.DeserializeDescriptor(with_checksum));
        std::string error;
        BOOST_CHECK_MESSAGE(!ParseOk(body, error), "a NEW descriptor like this must still be rejected: " << body.substr(0, 40));
    }
}
#endif

// Randomized mutation run over the HTLC leaf parsers (not coverage guided).
// Invariants, on both trees: a parser accepts only the exact canonical script it
// would build; no script is accepted by two claim parsers; the interpreter's
// pre-check matches the parsers exactly.
BOOST_AUTO_TEST_CASE(randomized_htlc_leaf_parser_mutations)
{
    const char* env = std::getenv("HTLC_FUZZ_ITERS");
    const int iters = env ? std::atoi(env) : 20000;
    FastRandomContext rng{uint256{0x5a}};
    int accepted_mutants{0};
    for (int i = 0; i < iters; ++i) {
        const PQAlgorithm algo = rng.randbool() ? PQAlgorithm::ML_DSA_44 : PQAlgorithm::SLH_DSA_128S;
        const Bytes pk = rng.randbytes(algo == PQAlgorithm::ML_DSA_44 ? MLDSA44_PUBKEY_SIZE : SLHDSA128S_PUBKEY_SIZE);
        Bytes script;
        switch (rng.randrange(4)) {
        case 0: script = BuildP2MRHTLCSha256Leaf(rng.randbytes(32), algo, pk); break;
        case 1: script = BuildP2MRHTLCSha256LegacyLeaf(rng.randbytes(32), algo, pk); break;
        case 2: script = BuildP2MRHTLCTxLeaf(rng.randbytes(20), algo, pk); break;
        default: script = BuildP2MRHTLCLeaf(rng.randbytes(20), algo, pk); break;
        }
        BOOST_REQUIRE(!script.empty());
        const int n_mut = rng.randrange(3);  // 0 = the valid leaf itself
        for (int m = 0; m < n_mut && !script.empty(); ++m) {
            const size_t pos = rng.randrange(script.size());
            switch (rng.randrange(6)) {
            case 0: script[pos] ^= static_cast<unsigned char>(1 << rng.randrange(8)); break;
            case 1: script.erase(script.begin() + pos); break;
            case 2: script.insert(script.begin() + pos, static_cast<unsigned char>(rng.randrange(256))); break;
            case 3: script.resize(pos); break;
            case 4: script.push_back(static_cast<unsigned char>(rng.randrange(256))); break;
            default: script[pos] = std::array<unsigned char, 8>{OP_SIZE, OP_SHA256, OP_HASH160, OP_EQUALVERIFY, OP_OVER, OP_DROP, 0x20, 0x14}[rng.randrange(8)]; break;
            }
        }
        Bytes h1, h2, h3, h4, k1, k2, k3, k4;
        PQAlgorithm a1{}, a2{}, a3{}, a4{};
        const bool p_new = ParseP2MRHTLCSha256Leaf(script, h1, a1, k1);
        const bool p_old = ParseP2MRHTLCSha256LegacyLeaf(script, h2, a2, k2);
        const bool p_tx = ParseP2MRHTLCTxLeaf(script, h3, a3, k3);
        const bool p_csfs = ParseP2MRLegacyHTLCLeaf(script, h4, a4, k4);
        BOOST_REQUIRE_LE(int{p_new} + int{p_old} + int{p_tx} + int{p_csfs}, 1);
        if (p_new) BOOST_REQUIRE(BuildP2MRHTLCSha256Leaf(h1, a1, k1) == script);
        if (p_old) BOOST_REQUIRE(BuildP2MRHTLCSha256LegacyLeaf(h2, a2, k2) == script);
        if (p_tx) BOOST_REQUIRE(BuildP2MRHTLCTxLeaf(h3, a3, k3) == script);
        if (p_csfs) BOOST_REQUIRE(BuildP2MRHTLCLeaf(h4, a4, k4) == script);
        BOOST_REQUIRE_EQUAL(P2MRClaimLeafPinsPreimageLength(script), p_new || p_old || p_tx);
        if (n_mut > 0 && (p_new || p_old || p_tx || p_csfs)) ++accepted_mutants;
    }
    BOOST_TEST_MESSAGE("leaf mutations: " << iters << " iterations, " << accepted_mutants << " mutants still parsed (all canonical)");
}

// Randomized mutation run over HTLC descriptor strings (not coverage guided).
// Invariants: no crash; a descriptor that parses round-trips through ToString()
// with a valid checksum to the same scriptPubKey; and (with the fix) no parsed
// descriptor expands to a claim leaf and a refund leaf with the same key.
BOOST_AUTO_TEST_CASE(randomized_htlc_descriptor_mutations)
{
    const char* env = std::getenv("HTLC_FUZZ_DESC_ITERS");
    const int iters = env ? std::atoi(env) : 20000;
    FastRandomContext rng{uint256{0xa5}};
    const std::string H = Pattern(32, 0x81);
    const std::string H20 = Pattern(20, 0x82);
    const std::string K1 = "pk_slh(" + Pattern(32, 0x83) + ")";
    const std::string K2 = "pk_slh(" + Pattern(32, 0x84) + ")";
    const std::string K3 = "pk_slh(" + Pattern(32, 0x85) + ")";
    const std::vector<std::string> seeds{
        "mr(htlc_sha256(" + H + "," + K1 + "),refund(700," + K2 + "))",
        "mr(model_htlc_sha256(" + H + "," + K1 + "),refund(500000001," + K2 + "))",
        "mr(htlc_tx(" + H20 + "," + K1 + "),refund(1," + K2 + "))",
        "mr(htlc(" + H20 + "," + K1 + "),refund(4294967295," + K2 + "))",
        "mr(htlc_sha256_legacy(" + H + "," + K1 + "),refund(700," + K2 + "))",
        "mr(htlc_sha256(" + H + "," + K1 + "),{refund(700," + K2 + ")," + K3 + "})",
    };
    const std::vector<std::string> tokens{
        "htlc_sha256(", "htlc_sha256_legacy(", "htlc_tx(", "htlc(", "refund(", "model_htlc_sha256(",
        "pk_slh(", K1, K2, K3, H, H20, ",", "(", ")", "{", "}", "0", "1", "500000000", "4294967296", "-1", "#", "/*",
    };
    int parsed_count{0};
    for (int i = 0; i < iters; ++i) {
        std::string d = seeds[rng.randrange(seeds.size())];
        const int n_mut = 1 + rng.randrange(3);
        for (int m = 0; m < n_mut; ++m) {
            const size_t pos = d.empty() ? 0 : rng.randrange(d.size());
            switch (rng.randrange(5)) {
            case 0: if (!d.empty()) d.erase(pos, 1 + rng.randrange(4)); break;
            case 1: d.insert(pos, tokens[rng.randrange(tokens.size())]); break;
            case 2: if (!d.empty()) d[pos] = "0123456789abcdef(),{}#"[rng.randrange(22)]; break;
            case 3: { // duplicate a substring
                if (d.empty()) break;
                const size_t a = rng.randrange(d.size());
                const size_t len = 1 + rng.randrange(std::min<size_t>(80, d.size() - a));
                d.insert(rng.randrange(d.size()), d.substr(a, len));
                break;
            }
            default: { // swap two key expressions
                const size_t p1 = d.find(K1), p2 = d.find(K2);
                if (p1 != std::string::npos && p2 != std::string::npos) {
                    d.replace(p2, K2.size(), K1);
                }
                break;
            }
            }
        }
        FlatSigningProvider keys;
        std::string error;
        const auto parsed = Parse(d, keys, error, /*require_checksum=*/false);
        if (parsed.empty()) continue;
        ++parsed_count;
        const std::string canon = parsed[0]->ToString();
        FlatSigningProvider keys2;
        const auto reparsed = Parse(canon, keys2, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!reparsed.empty(), "ToString() output does not reparse: " << canon << " :: " << error);
        if (parsed[0]->IsRange()) continue;
        CScript spk1, spk2;
        std::vector<Bytes> leaves1, leaves2;
        const bool e1 = ExpandLeaves(*parsed[0], keys, 0, spk1, leaves1);
        const bool e2 = ExpandLeaves(*reparsed[0], keys2, 0, spk2, leaves2);
        BOOST_REQUIRE_EQUAL(e1, e2);
        if (!e1) continue;
        BOOST_REQUIRE(spk1 == spk2);
        std::set<Bytes> claim_keys, refund_keys;
        for (const Bytes& leaf : leaves1) {
            Bytes pk;
            if (ParseAnyClaimLeafPubkey(leaf, pk)) claim_keys.insert(pk);
            else if (ParseRefundLeafPubkey(leaf, pk)) refund_keys.insert(pk);
        }
        for (const Bytes& pk : claim_keys) {
            BOOST_REQUIRE_MESSAGE(refund_keys.count(pk) == 0, "claim and refund share a key: " << d);
        }
    }
    BOOST_TEST_MESSAGE("descriptor mutations: " << iters << " iterations, " << parsed_count << " parsed");
}

BOOST_AUTO_TEST_SUITE_END()
