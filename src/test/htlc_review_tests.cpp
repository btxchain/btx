// HTLC hardening review tests (local review only, not for upstream as-is).
//
// Every test signs with real ML-DSA-44 / SLH-DSA keys and verifies through the
// full VerifyScript() witness path with a real MutableTransactionSignatureChecker,
// so key binding, transaction binding, CLTV and the 0.34.13 interpreter
// pre-check are all exercised exactly as block validation does.

#include <consensus/tx_verify.h>
#include <hash.h>
#include <key_io.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <addresstype.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace {

// Same script flags block validation uses once every deployment is active
// (GetBlockScriptFlags: P2SH|WITNESS|TAPROOT|CTV|CSFS + DERSIG|CLTV|CSV|NULLDUMMY).
// With htlc-fixes.patch the 32-byte rule is SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32,
// set by GetBlockScriptFlags from its activation height; these are the
// post-activation block flags.
constexpr unsigned int BLOCK_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT |
    SCRIPT_VERIFY_CHECKTEMPLATEVERIFY | SCRIPT_VERIFY_CHECKSIGFROMSTACK |
    SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32;

using Bytes = std::vector<unsigned char>;

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

CPQKey NewKey(PQAlgorithm algo = PQAlgorithm::ML_DSA_44)
{
    CPQKey k;
    k.MakeNewKey(algo);
    BOOST_REQUIRE(k.IsValid());
    return k;
}

//! Two-leaf P2MR tree {claim, refund} with control blocks, as the wallet builds it.
struct HtlcTree {
    Bytes claim_leaf;
    Bytes refund_leaf;
    uint256 root;
    Bytes claim_control;
    Bytes refund_control;
    CScript spk;
};

HtlcTree MakeTree(Bytes claim_leaf, Bytes refund_leaf)
{
    HtlcTree t;
    t.claim_leaf = std::move(claim_leaf);
    t.refund_leaf = std::move(refund_leaf);
    BOOST_REQUIRE(!t.claim_leaf.empty());
    BOOST_REQUIRE(!t.refund_leaf.empty());
    const uint256 ch = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.claim_leaf);
    const uint256 rh = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.refund_leaf);
    t.root = ComputeP2MRMerkleRoot({ch, rh});
    t.claim_control.assign(1, P2MR_LEAF_VERSION);
    t.claim_control.insert(t.claim_control.end(), rh.begin(), rh.end());
    t.refund_control.assign(1, P2MR_LEAF_VERSION);
    t.refund_control.insert(t.refund_control.end(), ch.begin(), ch.end());
    t.spk << OP_2 << ToByteVector(t.root);
    return t;
}

//! A spend of a single P2MR output. Set tx fields first, then call Sign/Verify.
struct Spend {
    CMutableTransaction credit;
    CMutableTransaction tx;

    explicit Spend(const CScript& spk, uint32_t locktime = 0, uint32_t sequence = CTxIn::MAX_SEQUENCE_NONFINAL)
        : credit(BuildCreditingTransaction(spk, /*nValue=*/100000)),
          tx(BuildSpendingTransaction(CScript{}, CScriptWitness{}, CTransaction{credit}))
    {
        tx.nLockTime = locktime;
        tx.vin.at(0).nSequence = sequence;
        tx.vout.at(0).nValue = 90000;
    }

    Bytes SignLeaf(const CPQKey& key, const Bytes& leaf, uint8_t hash_type = SIGHASH_DEFAULT) const
    {
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {credit.vout.at(0)}, /*force=*/true);
        ScriptExecutionData execdata;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf);
        execdata.m_tapleaf_hash_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFFU;
        execdata.m_codeseparator_pos_init = true;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, tx, 0, hash_type, SigVersion::P2MR, txdata, MissingDataBehavior::ASSERT_FAIL));
        Bytes sig;
        BOOST_REQUIRE(key.Sign(sighash, sig));
        if (hash_type != SIGHASH_DEFAULT) sig.push_back(hash_type);
        return sig;
    }

    bool Verify(const std::vector<Bytes>& stack, ScriptError& err, unsigned int flags = BLOCK_FLAGS)
    {
        tx.vin.at(0).scriptWitness.stack = stack;
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {credit.vout.at(0)}, /*force=*/true);
        err = SCRIPT_ERR_UNKNOWN_ERROR;
        return VerifyScript(tx.vin.at(0).scriptSig, credit.vout.at(0).scriptPubKey, &tx.vin.at(0).scriptWitness,
                            flags,
                            MutableTransactionSignatureChecker(&tx, 0, credit.vout.at(0).nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
                            &err);
    }
};

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

} // namespace

BOOST_FIXTURE_TEST_SUITE(htlc_review_tests, BasicTestingSetup)

// A1/A2: new SHA-256 claim leaf. Only an exact 32-byte preimage with the right
// hash and the claimer's signature spends it.
BOOST_AUTO_TEST_CASE(review_claim_preimage_length_matrix)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    for (const size_t len : {size_t{0}, size_t{1}, size_t{20}, size_t{31}, size_t{32}, size_t{33}, size_t{64}, size_t{520}}) {
        const Bytes preimage(len, 0x42);
        const HtlcTree t = MakeTree(
            BuildP2MRHTLCSha256Leaf(Sha256Bytes(preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
            BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
        Spend s{t.spk};
        const Bytes sig = s.SignLeaf(claimer, t.claim_leaf);
        ScriptError err;
        const bool ok = s.Verify({sig, preimage, t.claim_leaf, t.claim_control}, err);
        BOOST_TEST_MESSAGE("preimage len " << len << " -> " << ScriptErrorString(err));
        if (len == 32) {
            BOOST_CHECK(ok);
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        } else {
            BOOST_CHECK(!ok);
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_HTLC_PREIMAGE_SIZE);
        }
    }
}

BOOST_AUTO_TEST_CASE(review_claim_wrong_preimage_and_wrong_key)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const CPQKey stranger = NewKey();
    const Bytes preimage(32, 0x11);
    const HtlcTree t = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    Spend s{t.spk};
    ScriptError err;

    // Wrong 32-byte preimage.
    BOOST_CHECK(!s.Verify({s.SignLeaf(claimer, t.claim_leaf), Bytes(32, 0x12), t.claim_leaf, t.claim_control}, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EQUALVERIFY);

    // Right preimage, refund (sender) key and a stranger's key on the claim leaf.
    for (const CPQKey* k : {&sender, &stranger}) {
        BOOST_CHECK(!s.Verify({s.SignLeaf(*k, t.claim_leaf), preimage, t.claim_leaf, t.claim_control}, err));
        BOOST_TEST_MESSAGE("wrong key on claim -> " << ScriptErrorString(err));
    }

    // Empty signature: must fail (NULLFAIL-style result 0, not an abort we can bypass).
    BOOST_CHECK(!s.Verify({Bytes{}, preimage, t.claim_leaf, t.claim_control}, err));

    // Transaction binding: a valid witness moved onto a tx paying elsewhere fails.
    const Bytes good_sig = s.SignLeaf(claimer, t.claim_leaf);
    BOOST_CHECK(s.Verify({good_sig, preimage, t.claim_leaf, t.claim_control}, err));
    s.tx.vout.at(0).scriptPubKey = CScript() << OP_TRUE;
    BOOST_CHECK(!s.Verify({good_sig, preimage, t.claim_leaf, t.claim_control}, err));
    // ...and onto the same tx with a higher fee (lower output) fails too.
    Spend s2{t.spk};
    const Bytes sig2 = s2.SignLeaf(claimer, t.claim_leaf);
    s2.tx.vout.at(0).nValue -= 1;
    BOOST_CHECK(!s2.Verify({sig2, preimage, t.claim_leaf, t.claim_control}, err));
}

// Both branches: a claim witness with the refund leaf's control block (or vice
// versa), the wrong leaf version, or an extra witness element must all fail.
BOOST_AUTO_TEST_CASE(review_branch_confusion)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const Bytes preimage(32, 0x21);
    const HtlcTree t = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    Spend s{t.spk, /*locktime=*/2000};
    ScriptError err;
    const Bytes csig = s.SignLeaf(claimer, t.claim_leaf);
    const Bytes rsig = s.SignLeaf(sender, t.refund_leaf);

    BOOST_CHECK(!s.Verify({csig, preimage, t.claim_leaf, t.refund_control}, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    BOOST_CHECK(!s.Verify({rsig, t.refund_leaf, t.claim_control}, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    Bytes bad_version = t.claim_control;
    bad_version[0] = P2MR_LEAF_VERSION | 1;
    BOOST_CHECK(!s.Verify({csig, preimage, t.claim_leaf, bad_version}, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_WRONG_LEAF_VERSION);

    // Extra element under the signature: cleanstack must reject.
    BOOST_CHECK(!s.Verify({Bytes{0x01}, csig, preimage, t.claim_leaf, t.claim_control}, err));
    BOOST_TEST_MESSAGE("extra element -> " << ScriptErrorString(err));

    // Refund leaf satisfied with the claimer's key: rejected.
    BOOST_CHECK(!s.Verify({s.SignLeaf(claimer, t.refund_leaf), t.refund_leaf, t.refund_control}, err));
    // Honest refund at locktime 2000 > 1000: accepted.
    BOOST_CHECK(s.Verify({rsig, t.refund_leaf, t.refund_control}, err));
}

// Annex: an annex is popped before the pre-check, so it can not be used to
// push the preimage out of stack.back().
BOOST_AUTO_TEST_CASE(review_annex_does_not_bypass_size_check)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    const Bytes preimage(33, 0x31);
    const HtlcTree t = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    Spend s{t.spk};
    ScriptError err;
    const Bytes annex{ANNEX_TAG, 0x00};
    BOOST_CHECK(!s.Verify({s.SignLeaf(claimer, t.claim_leaf), preimage, t.claim_leaf, t.claim_control, annex}, err));
    BOOST_TEST_MESSAGE("annex + 33-byte preimage -> " << ScriptErrorString(err));
}

// FINDING F1: the 0.34.13 interpreter pre-check is an unconditional consensus
// rule. It also applies to the LEGACY SHA-256 leaf and the HASH160 htlc_tx leaf,
// which a v0.34.12 node accepts with a preimage of any length.
BOOST_AUTO_TEST_CASE(review_legacy_leaves_tightened_without_flag_gate)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();

    struct Case { const char* name; Bytes preimage; bool sha; };
    for (const Case& c : {Case{"legacy sha256, 33-byte", Bytes(33, 0x41), true},
                          Case{"legacy sha256, 16-byte", Bytes(16, 0x42), true},
                          Case{"htlc_tx hash160, 20-byte", Bytes(20, 0x43), false},
                          Case{"htlc_tx hash160, 64-byte", Bytes(64, 0x44), false}}) {
        const Bytes leaf = c.sha
            ? BuildP2MRHTLCSha256LegacyLeaf(Sha256Bytes(c.preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey())
            : BuildP2MRHTLCTxLeaf(Hash160Bytes(c.preimage), PQAlgorithm::ML_DSA_44, claimer.GetPubKey());
        const HtlcTree t = MakeTree(leaf, BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
        Spend s{t.spk};
        const Bytes sig = s.SignLeaf(claimer, t.claim_leaf);

        // (a) The leaf script itself is satisfied: executing it the way
        //     ExecuteWitnessScript did before 0.34.13 leaves exactly one true item.
        {
            std::vector<Bytes> stack{sig, c.preimage};
            PrecomputedTransactionData txdata;
            txdata.Init(s.tx, {s.credit.vout.at(0)}, true);
            ScriptExecutionData execdata;
            execdata.m_annex_present = false;
            execdata.m_annex_init = true;
            execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, t.claim_leaf);
            execdata.m_tapleaf_hash_init = true;
            execdata.m_codeseparator_pos = 0xFFFFFFFFU;
            execdata.m_codeseparator_pos_init = true;
            execdata.m_validation_weight_left = 100000;
            execdata.m_validation_weight_left_init = true;
            ScriptError e2;
            const bool exec_ok = EvalScript(stack, CScript(t.claim_leaf.begin(), t.claim_leaf.end()), BLOCK_FLAGS,
                                            MutableTransactionSignatureChecker(&s.tx, 0, s.credit.vout.at(0).nValue, txdata, MissingDataBehavior::ASSERT_FAIL),
                                            SigVersion::P2MR, execdata, &e2);
            BOOST_CHECK_MESSAGE(exec_ok && stack.size() == 1 && (CScriptNum(stack.back(), true).GetInt64() == 1),
                                c.name << ": leaf script should be satisfied, got " << ScriptErrorString(e2));
        }
        // (b) Full witness verification at 0.34.13 with block flags: rejected.
        ScriptError err;
        BOOST_CHECK(!s.Verify({sig, c.preimage, t.claim_leaf, t.claim_control}, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_P2MR_HTLC_PREIMAGE_SIZE);
        // (c) Without the new flag (before its activation height) the spend
        //     is valid again, exactly as in v0.34.12. On unpatched v0.34.13
        //     this was rejected: that was finding F1.
        BOOST_CHECK(s.Verify({sig, c.preimage, t.claim_leaf, t.claim_control}, err, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS));
        BOOST_TEST_MESSAGE(c.name << ": leaf satisfied; rejected only with SCRIPT_VERIFY_P2MR_HTLC_PREIMAGE32");
    }
}

// A3: refund CLTV boundaries with the real checker, plus IsFinalTx at the block boundary.
BOOST_AUTO_TEST_CASE(review_refund_locktime_boundaries)
{
    const CPQKey claimer = NewKey();
    const CPQKey sender = NewKey();
    constexpr uint32_t L = 1000;
    const HtlcTree t = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(Bytes(32, 0x51)), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(L, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));

    auto try_refund = [&](uint32_t locktime, uint32_t sequence, ScriptError& err) {
        Spend s{t.spk, locktime, sequence};
        return s.Verify({s.SignLeaf(sender, t.refund_leaf), t.refund_leaf, t.refund_control}, err);
    };
    ScriptError err;
    BOOST_CHECK(!try_refund(L - 1, CTxIn::MAX_SEQUENCE_NONFINAL, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    BOOST_CHECK(try_refund(L, CTxIn::MAX_SEQUENCE_NONFINAL, err));
    BOOST_CHECK(try_refund(L + 1, CTxIn::MAX_SEQUENCE_NONFINAL, err));
    BOOST_CHECK(try_refund(L, MAX_BIP125_RBF_SEQUENCE, err));
    // A final sequence disables nLockTime, so CLTV must fail.
    BOOST_CHECK(!try_refund(L, CTxIn::SEQUENCE_FINAL, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
    // Time-type nLockTime against a height-type CLTV: must fail.
    BOOST_CHECK(!try_refund(LOCKTIME_THRESHOLD + 1, CTxIn::MAX_SEQUENCE_NONFINAL, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

    // Block boundary: nLockTime L is final only in block L+1.
    Spend s{t.spk, L, CTxIn::MAX_SEQUENCE_NONFINAL};
    const CTransaction ctx{s.tx};
    BOOST_CHECK(!IsFinalTx(ctx, /*nBlockHeight=*/L, /*nBlockTime=*/0));
    BOOST_CHECK(IsFinalTx(ctx, /*nBlockHeight=*/L + 1, /*nBlockTime=*/0));

    // Time-type refund.
    constexpr uint32_t T = 1800000000;
    const HtlcTree tt = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(Bytes(32, 0x52)), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(T, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    auto try_time = [&](uint32_t locktime, ScriptError& e) {
        Spend sp{tt.spk, locktime};
        return sp.Verify({sp.SignLeaf(sender, tt.refund_leaf), tt.refund_leaf, tt.refund_control}, e);
    };
    BOOST_CHECK(!try_time(T - 1, err));
    BOOST_CHECK(try_time(T, err));
    BOOST_CHECK(!try_time(L, err)); // height-type nLockTime vs time-type CLTV
}

// SLH-DSA claimer: the new leaf parses and spends; the pre-check applies too.
BOOST_AUTO_TEST_CASE(review_slhdsa_claim)
{
    const CPQKey claimer = NewKey(PQAlgorithm::SLH_DSA_128S);
    const CPQKey sender = NewKey();
    const Bytes preimage(32, 0x61);
    const HtlcTree t = MakeTree(
        BuildP2MRHTLCSha256Leaf(Sha256Bytes(preimage), PQAlgorithm::SLH_DSA_128S, claimer.GetPubKey()),
        BuildP2MRRefundLeaf(1000, PQAlgorithm::ML_DSA_44, sender.GetPubKey()));
    Bytes h;
    Bytes pk;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    BOOST_CHECK(ParseP2MRHTLCSha256Leaf(t.claim_leaf, h, algo, pk));
    BOOST_CHECK(algo == PQAlgorithm::SLH_DSA_128S);
    Spend s{t.spk};
    ScriptError err;
    BOOST_CHECK(s.Verify({s.SignLeaf(claimer, t.claim_leaf), preimage, t.claim_leaf, t.claim_control}, err));
    BOOST_CHECK(!s.Verify({s.SignLeaf(claimer, t.claim_leaf), Bytes(31, 0x61), t.claim_leaf, t.claim_control}, err));
}

// Template parsers: exact-match only.
BOOST_AUTO_TEST_CASE(review_parser_strictness)
{
    const CPQKey claimer = NewKey();
    const Bytes hash = Sha256Bytes(Bytes(32, 0x71));
    const Bytes cur = BuildP2MRHTLCSha256Leaf(hash, PQAlgorithm::ML_DSA_44, claimer.GetPubKey());
    const Bytes leg = BuildP2MRHTLCSha256LegacyLeaf(hash, PQAlgorithm::ML_DSA_44, claimer.GetPubKey());
    Bytes h;
    Bytes pk;
    PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
    BOOST_CHECK(ParseP2MRHTLCSha256Leaf(cur, h, algo, pk));
    BOOST_CHECK(!ParseP2MRHTLCSha256LegacyLeaf(cur, h, algo, pk));
    BOOST_CHECK(ParseP2MRHTLCSha256LegacyLeaf(leg, h, algo, pk));
    BOOST_CHECK(!ParseP2MRHTLCSha256Leaf(leg, h, algo, pk));

    Bytes extra = cur;
    extra.push_back(OP_NOP);
    BOOST_CHECK(!ParseP2MRHTLCSha256Leaf(extra, h, algo, pk));
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(extra));
    Bytes trunc(cur.begin(), cur.end() - 1);
    BOOST_CHECK(!ParseP2MRHTLCSha256Leaf(trunc, h, algo, pk));
    Bytes size33 = cur;
    size33[2] = 33; // OP_SIZE 33 OP_EQUALVERIFY ...
    BOOST_CHECK(!ParseP2MRHTLCSha256Leaf(size33, h, algo, pk));
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(size33));

    BOOST_CHECK(BuildP2MRHTLCSha256Leaf(Bytes(31, 0), PQAlgorithm::ML_DSA_44, claimer.GetPubKey()).empty());
    BOOST_CHECK(BuildP2MRHTLCSha256Leaf(hash, PQAlgorithm::ML_DSA_44, Bytes(10, 0)).empty());
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(BuildP2MRRefundLeaf(5, PQAlgorithm::ML_DSA_44, claimer.GetPubKey())));
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(BuildP2MRScript(PQAlgorithm::ML_DSA_44, claimer.GetPubKey())));
    // Legacy CSFS htlc() is NOT covered by the pre-check (its stack is <sig> <preimage> too).
    BOOST_CHECK(!P2MRClaimLeafPinsPreimageLength(BuildP2MRHTLCLeaf(Bytes(20, 1), PQAlgorithm::ML_DSA_44, claimer.GetPubKey())));
}

// A6: descriptor refund timeout bounds.
BOOST_AUTO_TEST_CASE(review_descriptor_refund_timeout_bounds)
{
    const std::string H = Pattern(32, 0x01);
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x02);
    const std::string S = Pattern(MLDSA44_PUBKEY_SIZE, 0x03);
    auto desc = [&](const std::string& t) { return "mr(htlc_sha256(" + H + "," + C + "),refund(" + t + "," + S + "))"; };
    std::string error;
    for (const char* bad : {"0", "-1", "4294967296", "1e3", " 10", "0x10", ""}) {
        BOOST_CHECK_MESSAGE(!ParseOk(desc(bad), error), "timeout '" << bad << "' should be rejected");
    }
    for (const char* good : {"1", "499999999", "500000000", "4294967295"}) {
        BOOST_CHECK_MESSAGE(ParseOk(desc(good), error), "timeout '" << good << "' should parse: " << error);
    }
}

// FINDING F2: the claim/refund distinct-key rule only compares identical hex
// keys. Two textually identical pqhd() expressions get different provider
// indexes, so the "same_provider" branch can never fire.
BOOST_AUTO_TEST_CASE(review_descriptor_distinct_key_rule_bypass)
{
    const std::string H = Pattern(32, 0x11);
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x12);
    std::string error;

    // Enforced: identical hex keys.
    BOOST_CHECK(!ParseOk("mr(htlc_sha256(" + H + "," + C + "),refund(10," + C + "))", error));
    BOOST_CHECK(error.find("distinct") != std::string::npos);

    // With htlc-fixes.patch: the same pqhd() key expression in both leaves is rejected.
    const std::string K = PQHDExpr(0x21);
    const std::string same_pqhd = "mr(htlc_sha256(" + H + "," + K + "),refund(10," + K + "))";
    BOOST_CHECK_MESSAGE(!ParseOk(same_pqhd, error), "same-pqhd descriptor must be rejected after the fix");
    BOOST_CHECK(error.find("distinct") != std::string::npos);

    // Same key, hex in one leaf and pqhd in the other: also not caught. Derive
    // the pqhd index-0 key first, then write it as hex in the refund leaf.
    {
        FlatSigningProvider k2;
        error.clear();
        auto single = Parse("mr(" + K + ")", k2, error, false);
        BOOST_REQUIRE_MESSAGE(!single.empty(), error);
        std::vector<CScript> scripts;
        FlatSigningProvider out;
        BOOST_REQUIRE(single[0]->Expand(0, k2, scripts, out));
        P2MRSpendData spend;
        int wv;
        Bytes prog;
        BOOST_REQUIRE(scripts.at(0).IsWitnessProgram(wv, prog));
        BOOST_REQUIRE(out.GetP2MRSpendData(WitnessV2P2MR{uint256{prog}}, spend));
        BOOST_REQUIRE(!spend.scripts.empty());
        const Bytes& leaf = spend.scripts.begin()->first;
        Span<const unsigned char> p;
        size_t used{0};
        PQAlgorithm a{PQAlgorithm::ML_DSA_44};
        BOOST_REQUIRE(ParseP2MRAnyPubkeyPush(leaf, 0, a, p, used));
        const std::string hex_same = HexStr(p);
        const std::string mixed = "mr(htlc_sha256(" + H + "," + K + "),refund(10," + hex_same + "))";
        // Residual by design: the parser cannot see that a ranged pqhd() and a hex
        // key are the same key. buildhtlcclaim/buildhtlcrefund compare the
        // expanded keys (wallet_htlc_fixes.py F2.3).
        BOOST_CHECK_MESSAGE(ParseOk(mixed, error), "mixed hex/pqhd same-key descriptor: " << error);
    }
}

// Recovery-only guard is a substring match.
BOOST_AUTO_TEST_CASE(review_recovery_only_guard)
{
    const std::string H20 = Pattern(20, 0x31);
    const std::string H32 = Pattern(32, 0x32);
    const std::string C = Pattern(MLDSA44_PUBKEY_SIZE, 0x33);
    BOOST_CHECK(DescriptorIsRecoveryOnlyHtlc("mr(htlc_tx(" + H20 + "," + C + "))"));
    BOOST_CHECK(DescriptorIsRecoveryOnlyHtlc("mr(htlc(" + H20 + "," + C + "))"));
    BOOST_CHECK(!DescriptorIsRecoveryOnlyHtlc("mr(htlc_sha256(" + H32 + "," + C + "))"));
    BOOST_CHECK(!DescriptorIsRecoveryOnlyHtlc("mr(model_htlc_sha256(" + H32 + "," + C + "))"));
}

BOOST_AUTO_TEST_CASE(review_refund_timestamp_past)
{
    std::string error;
    constexpr int64_t now = 1790000000;
    BOOST_CHECK(HtlcRefundTimestampIsPast("refund(500000000)", now, error));
    BOOST_CHECK_EQUAL(error, "HTLC refund timestamp is already in the past and cannot be used for a new address or an active descriptor");
    BOOST_CHECK(!HtlcRefundTimestampIsPast("refund(2000000000)", now, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!HtlcRefundTimestampIsPast("refund(144)", now, error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_SUITE_END()
