// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// RECOVERY_EXIT mined-block end-to-end test: with the fork enabled via regtest overrides, a real
// V2_RECOVERY_EXIT transaction is mined through ConnectBlock and asserted to (a) debit the shielded pool
// by the recovered value, and (b) atomically retire BOTH the revealed commitment and the derived
// canonical nullifier. Uses a DETERMINISTIC note + ML-DSA-44 key so the consensus-pinned frozen membership
// root can be supplied as a regtest override that matches the note the transaction reveals.

#include <consensus/amount.h>
#include <hash.h>
#include <key_io.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/nullifier.h>
#include <shielded/recovery_exit.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

using namespace shielded::recovery;

namespace {

constexpr int kSunsetHeight = 101;          // chain is at 100 after TestChain100Setup; recovery mined at 101
constexpr CAmount kRecoverValue = 50 * COIN;
constexpr CAmount kRecoverFee = 1000;

uint256 Sha256Of(const std::vector<unsigned char>& b)
{
    HashWriter hw; hw.write(AsBytes(Span<const unsigned char>{b.data(), b.size()})); return hw.GetSHA256();
}

// Deterministic test vectors: same note/key/witness every run, so the frozen root passed as a regtest
// override (fixed before the chain is built) is exactly the root the recovery transaction proves against.
struct ReVectors {
    CPQKey key;
    std::vector<unsigned char> pubkey;
    ShieldedNote note;
    uint256 cm;
    uint256 nullifier;
    uint256 frozen_root;
    shielded::ShieldedMerkleWitness witness;
};

const ReVectors& Vectors()
{
    static const ReVectors v = [] {
        ReVectors r;
        const std::array<unsigned char, 32> seed{{'B','T','X','-','R','E','C','O','V','E','R','Y','-','E','X','I','T',
                                                  '-','E','2','E','-','S','E','E','D','-','v','1','!','!','!'}};
        const bool ok = r.key.MakeDeterministicKey(PQAlgorithm::ML_DSA_44,
                            Span<const unsigned char>{seed.data(), seed.size()});
        assert(ok);
        r.pubkey = r.key.GetPubKey();
        r.note.value = kRecoverValue;
        r.note.recipient_pk_hash = Sha256Of(r.pubkey);
        // Deterministically pick SMILE2-eligible rho/rcm from the fixed seed.
        FastRandomContext rng(uint256{Sha256Of(r.pubkey)});
        for (int i = 0; i < 16; ++i) {
            r.note.rho = rng.rand256();
            r.note.rcm = rng.rand256();
            const auto nf = smile2::wallet::ComputeSmileNullifierFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED, r.note);
            if (nf.has_value() && !nf->IsNull()) { r.nullifier = *nf; break; }
        }
        assert(!r.nullifier.IsNull());
        r.cm = r.note.GetCommitment();
        // Frozen tree: one fixed decoy then the note appended last so Witness() targets the note.
        shielded::ShieldedMerkleTree tree;
        tree.Append(uint256::ONE);
        tree.Append(r.cm);
        r.witness = tree.Witness();
        r.frozen_root = tree.Root();
        return r;
    }();
    return v;
}

// Fork-enabling regtest args. The frozen-root hex is stored in a function-static string so its c_str()
// stays valid for the lifetime of the chain setup.
TestOpts MakeRecoveryOpts()
{
    static const std::string sunset_arg = "-regtestshieldedsunsetheight=" + std::to_string(kSunsetHeight);
    static const std::string credit_arg = "-regtestshieldedpoolcreditdisableheight=" + std::to_string(kSunsetHeight);
    static const std::string activ_arg = "-regtestshieldedrecoveryexitactivationheight=" + std::to_string(kSunsetHeight);
    static const std::string root_arg = "-regtestshieldedrecoveryexitfrozenroot=" + Vectors().frozen_root.GetHex();
    TestOpts opts;
    opts.extra_args = {sunset_arg.c_str(), credit_arg.c_str(), activ_arg.c_str(), root_arg.c_str()};
    return opts;
}

struct RecoveryExitChainSetup : public TestChain100Setup {
    RecoveryExitChainSetup() : TestChain100Setup(ChainType::REGTEST, MakeRecoveryOpts()) {}
};

// Build a fully-valid V2_RECOVERY_EXIT transaction (empty vin; one transparent output = value - fee).
CMutableTransaction BuildRecoveryExitTx()
{
    using namespace shielded::v2;
    const ReVectors& v = Vectors();

    RecoveryExitPayload payload;
    payload.value = v.note.value;
    payload.recipient_pk_hash = v.note.recipient_pk_hash;
    payload.rho = v.note.rho;
    payload.rcm = v.note.rcm;
    payload.spend_pubkey = v.pubkey;
    { DataStream ws; ws << v.witness; const auto sp = MakeUCharSpan(ws); payload.membership_proof.assign(sp.begin(), sp.end()); }

    CMutableTransaction mtx;
    mtx.vout.emplace_back(v.note.value - kRecoverFee, CScript() << OP_TRUE);

    const uint256 tx_binding = ComputeRecoveryExitTransparentBinding(Span<const CTxOut>{mtx.vout});
    const uint256 binding = ComputeRecoveryExitBindingHash(v.cm, v.nullifier, payload.value, tx_binding);
    BOOST_REQUIRE(v.key.Sign(binding, payload.ownership_sig));

    TransactionBundle bundle;
    bundle.header.family_id = TransactionFamily::V2_RECOVERY_EXIT;
    bundle.header.proof_envelope.proof_kind = ProofKind::NONE;
    bundle.header.proof_envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    bundle.header.proof_envelope.statement_digest = uint256::ZERO;
    bundle.header.payload_digest = ComputeRecoveryExitPayloadDigest(payload);
    bundle.payload = payload;
    mtx.shielded_bundle.v2_bundle = bundle;
    return mtx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(recovery_exit_chain_tests)

BOOST_FIXTURE_TEST_CASE(recovery_exit_mined_block_debits_pool_and_retires_identifiers, RecoveryExitChainSetup)
{
    const ReVectors& v = Vectors();
    ChainstateManager& chainman = *Assert(m_node.chainman);

    // Seed the frozen pool with twice the recovered value, so the debit leaves a positive remainder.
    const CAmount initial_pool = 2 * v.note.value;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainman.SetShieldedPoolBalanceForTest(initial_pool));
        BOOST_CHECK(!chainman.IsShieldedNullifierSpent(v.nullifier));
        BOOST_CHECK(!chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));
    }

    // Mine a block (height 101 == sunset + recovery activation) containing the recovery transaction.
    const CMutableTransaction rtx = BuildRecoveryExitTx();
    CreateAndProcessBlock({rtx}, CScript() << OP_TRUE, /*chainstate=*/nullptr, /*use_mempool=*/false);

    LOCK(cs_main);
    // The block connected and advanced the tip past the activation height.
    BOOST_CHECK_GE(chainman.ActiveChain().Height(), kSunsetHeight);
    // The pool was debited by exactly the recovered value.
    BOOST_CHECK_EQUAL(chainman.GetShieldedPoolBalance(), initial_pool - v.note.value);
    // BOTH identifiers retired: the nullifier (shared set) and the commitment (spent-commitment set).
    BOOST_CHECK(chainman.IsShieldedNullifierSpent(v.nullifier));
    BOOST_CHECK(chainman.IsShieldedRecoveryExitCommitmentRetired(v.cm));
}

BOOST_AUTO_TEST_SUITE_END()
