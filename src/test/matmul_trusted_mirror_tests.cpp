// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <common/args.h>
#include <init.h>
#include <key_io.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/interface_ui.h>
#include <node/matmul_trusted_attestations.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <string>
#include <vector>

namespace {

CKey NewKey()
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return key;
}

uint256 Hex256(char digit)
{
    return uint256::FromHex(
               std::string(64, digit))
        .value();
}

struct RuntimeReset {
    ~RuntimeReset()
    {
        node::matmul_trusted::ResetForTest();
    }
};

//! Capture the message text passed to the last InitError() so a startup
//! refusal can be asserted on its reason, not merely on the false return.
class InitErrorCapture
{
public:
    InitErrorCapture()
        : m_connection{uiInterface.ThreadSafeMessageBox_connect(
              [this](const bilingual_str& message, const std::string&,
                     unsigned int style) {
                  if ((style & CClientUIInterface::MSG_ERROR) ==
                      CClientUIInterface::MSG_ERROR) {
                      m_last_error = message.original;
                  }
                  return true; // Handled: keep the message off the test log.
              })}
    {
    }
    const std::string& LastError() const { return m_last_error; }

private:
    std::string m_last_error;
    boost::signals2::scoped_connection m_connection;
};

std::string HexPubKey(const CKey& key)
{
    const CPubKey pubkey{key.GetPubKey()};
    return HexStr(pubkey);
}

//! Run the real startup parameter interaction with a trusted-mirror signer
//! configuration, on whatever chain the enclosing fixture selected.
//! Restores every argument this helper forces, on every exit path.
//!
//! Without it these cases leaked -matmultrustedpubkey into the shared
//! ArgsManager, so any LATER test in the same test_btx process hit parameter
//! interaction with a stale (and, across two cases, duplicated) signer set.
//! matmul_v4_rc_production_canary_tests then failed when run after this suite
//! while passing in isolation -- order-dependent global state, which is the
//! hardest kind of failure to diagnose from a combined run.
class ScopedForcedArgs
{
public:
    explicit ScopedForcedArgs(ArgsManager& args) : m_args{args} {}
    ~ScopedForcedArgs()
    {
        // Restore VALID defaults, not empty strings: an empty
        // -matmulvalidation is not a recognised mode, so clearing it that way
        // made every later AppInitParameterInteraction in the process fail.
        m_args.ForceSetArgV("-matmultrustedpubkey", UniValue{UniValue::VARR});
        m_args.ForceSetArg("-matmultrustedthreshold", int64_t{1});
        m_args.ForceSetArg("-matmulvalidation", "consensus");
        // Deliberately does NOT reset the trusted-mirror runtime: the accept
        // cases inspect the installed quorum after this helper returns.
    }
private:
    ArgsManager& m_args;
};

bool TrustedMirrorStartupAccepted(ArgsManager& args,
                                  const std::vector<std::string>& pubkeys,
                                  int64_t threshold,
                                  std::string& error)
{
    node::matmul_trusted::ResetForTest();
    ScopedForcedArgs restore{args};
    args.ForceSetArg("-matmulvalidation", "trusted");
    UniValue keys{UniValue::VARR};
    for (const auto& hex : pubkeys) keys.push_back(hex);
    args.ForceSetArgV("-matmultrustedpubkey", keys);
    args.ForceSetArg("-matmultrustedthreshold", threshold);
    InitErrorCapture capture;
    const bool ok{AppInitParameterInteraction(args)};
    error = capture.LastError();
    return ok;
}

//! AppInitParameterInteraction only STAGES the signer configuration; the store
//! is built later in AppInitMain. Complete that step the same way and report
//! whether a live trusted-mirror quorum was actually installed.
bool FinalizedTrustedMirrorInstalled(std::string& error)
{
    if (!node::matmul_trusted::FinalizeConfiguration(error)) return false;
    return node::matmul_trusted::IsTrustedMirror();
}

struct RegtestParamSetup : public BasicTestingSetup {
    RegtestParamSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_trusted_mirror_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valid_quorum_and_config_rotation_fail_closed)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const CKey c{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 block{Hex256('2')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('a');
    config.trusted_signers = {
        a.GetPubKey(), b.GetPubKey(), c.GetPubKey()};
    config.threshold = 2;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{20},
        error));
    BOOST_CHECK(node::matmul_trusted::IsTrustedMirror());
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 2U);
    BOOST_REQUIRE(node::matmul_trusted::ReplayAuthorityContext());
    BOOST_CHECK(*node::matmul_trusted::ReplayAuthorityContext() == Hex256('a'));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 77;
    statement.replay_authority_context = Hex256('a');
    const auto att_a{
        matmul::trusted::SignStatement(statement, a)};
    const auto att_b{
        matmul::trusted::SignStatement(statement, b)};
    BOOST_REQUIRE(att_a);
    BOOST_REQUIRE(att_b);
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 77));
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::Duplicate);
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_b, block, 77) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 77));

    // A restart/key rotation creates a new empty authority store. A persisted
    // BLOCK_TRUSTED_REPLAY_ATTESTED bit cannot recreate quorum for new or
    // explicitly revalidated blocks under the changed configuration. Already
    // connected chainstate needs an operator-requested reindex for retroactive
    // application of that policy.
    node::matmul_trusted::ResetForTest();
    matmul::trusted::StoreConfig rotated;
    rotated.chain_id = chain;
    rotated.replay_authority_context = Hex256('a');
    rotated.trusted_signers = {c.GetPubKey()};
    rotated.threshold = 1;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(rotated), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{1},
        error));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 77));
    BOOST_CHECK(node::matmul_trusted::Add(
                    *att_a, block, 77) ==
                matmul::trusted::AddResult::UntrustedSigner);
    BOOST_CHECK(node::matmul_trusted::WaitForQuorum(
                    block, 77, [] { return false; }) ==
                matmul::trusted::WaitResult::Timeout);
}

BOOST_AUTO_TEST_CASE(local_signer_and_expected_context)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('3')};
    const uint256 block{Hex256('4')};
    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('b');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    config.local_signer = signer;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/false,
        /*serve=*/true, std::chrono::milliseconds{10},
        error));
    matmul::trusted::ExactReplayAttestation produced;
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                    block, 9, &produced) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(produced.statement.replay_authority_context == Hex256('b'));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 9));
    BOOST_CHECK(node::matmul_trusted::Add(
                    produced, block, 10) ==
                matmul::trusted::AddResult::WrongHeight);
    BOOST_CHECK(node::matmul_trusted::Add(
                    produced, Hex256('5'), 9) ==
                matmul::trusted::AddResult::WrongBlock);
}

BOOST_AUTO_TEST_CASE(staged_signer_finalizes_after_ecc_and_resets_cleanly)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('6');
    config.replay_authority_context = Hex256('c');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;

    BOOST_REQUIRE(node::matmul_trusted::StageConfiguration(
        std::move(config), EncodeSecret(signer),
        /*trusted_mirror=*/false, /*serve=*/true,
        std::chrono::milliseconds{10}, error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
    BOOST_REQUIRE(node::matmul_trusted::FinalizeConfiguration(error));
    BOOST_CHECK(node::matmul_trusted::IsConfigured());
    BOOST_CHECK(node::matmul_trusted::HasLocalSigner());
    BOOST_CHECK(node::matmul_trusted::ServesAttestations());

    node::matmul_trusted::ResetForTest();
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
    BOOST_CHECK(!node::matmul_trusted::ReplayAuthorityContext());
}

// A trusted mirror does not merely accelerate the Profile-1 MatMul check, it
// replaces it: above the Profile-1 height the local ExactReplay is skipped and
// the attestation quorum is the node's only MatMul proof-of-work authority. A
// 1-of-1 quorum therefore hands one key the power to make the node accept
// MatMul-invalid blocks. Mainnet supports this topology with a loud warning;
// 2 distinct signers with M >= 2 remain the recommended production minimum.
BOOST_AUTO_TEST_CASE(mainnet_trusted_mirror_allows_but_warns_on_single_key_quorum)
{
    // A single-key mainnet mirror is a real exposure -- above the Profile-1
    // height the quorum REPLACES the MatMul proof-of-work check -- but it is a
    // supported, already-deployed configuration. Refusing to start would break
    // existing operators on upgrade, so this must WARN and continue. This case
    // pins that it starts; the warning text is asserted by the functional test,
    // which can read the node's actual stderr.
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN);
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;

    // 1-of-1 starts.
    BOOST_CHECK_MESSAGE(TrustedMirrorStartupAccepted(
        *m_node.args, {key_a}, /*threshold=*/1, error), error);

    // 2-of-N with M == 1 is the same single-key authority, and also starts.
    RuntimeReset reset_again;
    BOOST_CHECK_MESSAGE(TrustedMirrorStartupAccepted(
        *m_node.args, {key_a, key_b}, /*threshold=*/1, error), error);

    // What must STILL be refused is a threshold that cannot be met, and
    // duplicate keys inflating the signer count -- neither is a deployed
    // configuration and both are simply invalid.
    RuntimeReset reset_third;
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        *m_node.args, {key_a}, /*threshold=*/2, error));
}

BOOST_AUTO_TEST_CASE(mainnet_trusted_mirror_accepts_two_of_two)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::MAIN);
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;

    BOOST_CHECK_MESSAGE(
        TrustedMirrorStartupAccepted(
            *m_node.args, {key_a, key_b}, /*threshold=*/2, error),
        error);
    std::string finalize_error;
    BOOST_CHECK_MESSAGE(FinalizedTrustedMirrorInstalled(finalize_error),
                        finalize_error);
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 2U);
    BOOST_CHECK_EQUAL(node::matmul_trusted::TrustedSigners().size(), 2U);
    BOOST_CHECK_EQUAL(node::matmul_trusted::WaitTimeout().count(), 60'000);
}

// Without this, "-matmultrustedpubkey=X -matmultrustedpubkey=X
// -matmultrustedthreshold=2" would falsely claim two independent authorities
// while the quorum still rests on one private key.
BOOST_AUTO_TEST_CASE(duplicate_trusted_pubkeys_are_refused)
{
    RuntimeReset reset;
    const std::string key_a{HexPubKey(NewKey())};
    const std::string key_b{HexPubKey(NewKey())};
    std::string error;
    std::string finalize_error;

    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        *m_node.args, {key_a, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());

    // Also refused when the duplicate is not adjacent and N would otherwise be
    // large enough on its own.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        *m_node.args, {key_a, key_b, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
}

// Functional/rehearsal harnesses use supported single-signer mirrors and must
// keep working without the mainnet warning path.
BOOST_FIXTURE_TEST_CASE(non_mainnet_trusted_mirror_keeps_one_of_one,
                        RegtestParamSetup)
{
    RuntimeReset reset;
    BOOST_REQUIRE(Params().GetChainType() == ChainType::REGTEST);
    const std::string key_a{HexPubKey(NewKey())};
    std::string error;

    BOOST_CHECK_MESSAGE(
        TrustedMirrorStartupAccepted(
            *m_node.args, {key_a}, /*threshold=*/1, error),
        error);
    std::string finalize_error;
    BOOST_CHECK_MESSAGE(FinalizedTrustedMirrorInstalled(finalize_error),
                        finalize_error);
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 1U);

    // The duplicate rejection is chain-independent.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        *m_node.args, {key_a, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());
}

BOOST_AUTO_TEST_CASE(tip_priority_orders_tip_extender_before_backfill)
{
    using node::matmul_trusted::MakeTrustedWorkRank;
    using node::matmul_trusted::PreferTrustedWork;

    const int32_t tip_height{185787};
    const auto tip_child{MakeTrustedWorkRank(
        /*tip_extending=*/true, /*height=*/185788, tip_height,
        /*priority_rank=*/2, /*sequence=*/10)};
    const auto far_above{MakeTrustedWorkRank(
        false, 186093, tip_height, /*priority_rank=*/1, /*sequence=*/1)};
    const auto near_above{MakeTrustedWorkRank(
        false, 185860, tip_height, /*priority_rank=*/1, /*sequence=*/2)};
    const auto below_tip{MakeTrustedWorkRank(
        false, 185589, tip_height, /*priority_rank=*/1, /*sequence=*/0)};

    BOOST_CHECK(PreferTrustedWork(tip_child, far_above));
    BOOST_CHECK(PreferTrustedWork(tip_child, below_tip));
    BOOST_CHECK(PreferTrustedWork(near_above, far_above));
    BOOST_CHECK(PreferTrustedWork(near_above, below_tip));
    BOOST_CHECK(PreferTrustedWork(far_above, below_tip));
    BOOST_CHECK(!PreferTrustedWork(below_tip, tip_child));
}

BOOST_AUTO_TEST_CASE(partial_quorum_is_never_accepted)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const CKey b{NewKey()};
    const uint256 chain{Hex256('c')};
    const uint256 block{Hex256('d')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('e');
    config.trusted_signers = {a.GetPubKey(), b.GetPubKey()};
    config.threshold = 2;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{5},
        error));

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 42;
    statement.replay_authority_context = Hex256('e');
    const auto att_a{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_a);
    BOOST_CHECK(node::matmul_trusted::Add(*att_a, block, 42) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 42));
    BOOST_CHECK(node::matmul_trusted::WaitForQuorum(
                    block, 42, [] { return false; }) ==
                matmul::trusted::WaitResult::Timeout);
}

BOOST_AUTO_TEST_CASE(wait_timeout_clamp_rejects_insane_values)
{
    RuntimeReset reset;
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('f');
    config.replay_authority_context = Hex256('0');
    config.trusted_signers = {NewKey().GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_CHECK(!node::matmul_trusted::Configure(
        config, /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{-1}, error));
    BOOST_CHECK(error.find("600000") != std::string::npos);
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::Configure(
        config, /*trusted_mirror=*/true, /*serve=*/false,
        std::chrono::milliseconds{600'001}, error));
    BOOST_CHECK(error.find("600000") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(above_frontier_and_parked_branch_do_not_admit)
{
    using node::matmul_trusted::EvaluateTrustedAttestationAdmit;
    using node::matmul_trusted::TrustedAttestationAdmit;
    using node::matmul_trusted::TrustedAttestationAdmitView;

    // Competing height above the authority tip must not consume a slot.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 186087,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectAboveFrontier);

    // Parked deep-reorg branch is never attestable by our policy.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = true,
            .height = 186074,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    // Fork that does not extend the active tip is refused even below frontier.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 185950,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectNotForwardOfTip);

    // A better-work branch IS admissible even though it does not extend the
    // active tip -- that is what a reorg looks like. Regression: a mirror lost a
    // same-height race at 186355 and sat on the losing sibling while the
    // authority ran 23 blocks ahead. Nothing on the winning branch extended its
    // tip, so every rescuing block was refused as not-forward-of-tip and the
    // node was stuck until an operator ran invalidateblock.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 186356,
            .authority_frontier = 186383,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Better work does NOT override the park policy: a refused deep reorg stays
    // refused, so this cannot become a back door around deep-reorg finality.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = true,
            .height = 186356,
            .authority_frontier = 186383,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    // Tip-extender is always allowed, including a one-step frontier probe.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = true,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 186012,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);

    // Forward of tip at/under frontier is allowed.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 185944,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Signer-absent backoff blocks re-admission of non-tip work.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = true,
            .on_parked_reorg_branch = false,
            .height = 185944,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::RejectBackoff);
}

BOOST_AUTO_TEST_CASE(tip_extender_capacity_reserved_under_slot_pressure)
{
    using node::matmul_trusted::TrustedAttestationRequestCapacityAllows;

    constexpr size_t kMax{1024};
    constexpr size_t kReserved{1};
    // Backfill cannot fill the last reserved slot.
    BOOST_CHECK(!TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/false, /*outstanding=*/kMax - kReserved, kMax,
        kReserved));
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/false, /*outstanding=*/kMax - kReserved - 1, kMax,
        kReserved));
    // Tip-extender may always attempt admission (displace path handles full).
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/true, /*outstanding=*/kMax, kMax, kReserved));
    BOOST_CHECK(TrustedAttestationRequestCapacityAllows(
        /*tip_extending=*/true, /*outstanding=*/kMax - 1, kMax, kReserved));
}

BOOST_AUTO_TEST_CASE(authority_frontier_tracks_accepted_attestations)
{
    RuntimeReset reset;
    const CKey a{NewKey()};
    const uint256 chain{Hex256('1')};
    const uint256 block_lo{Hex256('2')};
    const uint256 block_hi{Hex256('3')};

    matmul::trusted::StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = Hex256('4');
    config.trusted_signers = {a.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/false, std::chrono::milliseconds{50},
        error));

    BOOST_CHECK(!node::matmul_trusted::AuthorityAttestedFrontier().has_value());

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block_lo;
    statement.block_height = 100;
    statement.replay_authority_context = Hex256('4');
    const auto att_lo{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_lo);
    BOOST_CHECK(node::matmul_trusted::Add(*att_lo, block_lo, 100) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::AuthorityAttestedFrontier().has_value());
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 100);

    statement.block_hash = block_hi;
    statement.block_height = 250;
    const auto att_hi{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_hi);
    BOOST_CHECK(node::matmul_trusted::Add(*att_hi, block_hi, 250) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 250);

    // Soft peer-tip hint can raise the effective frontier further.
    node::matmul_trusted::NoteAuthorityPeerTipHint(300);
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 300);
}

BOOST_AUTO_TEST_CASE(tip_chain_header_preference_ignores_competing_fork)
{
    using node::matmul_trusted::PreferTrustedMirrorTipChainHeader;
    using node::matmul_trusted::TrustedMirrorTipChainHeaderView;

    // Tip-chain extension past the authenticated tip must become best-header.
    BOOST_CHECK(PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186051,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = true,
    }));

    // Competing fork (not a tip-chain extension) must never displace.
    BOOST_CHECK(!PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = false,
        .on_parked_reorg_branch = false,
        .candidate_height = 186291,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Parked deep-reorg branch is excluded even if heights look ahead.
    BOOST_CHECK(!PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = true,
        .candidate_height = 186060,
        .tip_height = 186050,
        .current_best_height = 186050,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = true,
    }));

    // A tip-chain header may displace a stale best-header that is not on tip.
    BOOST_CHECK(PreferTrustedMirrorTipChainHeader(TrustedMirrorTipChainHeaderView{
        .extends_active_tip_chain = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186051,
        .tip_height = 186050,
        .current_best_height = 186200,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));
}

BOOST_AUTO_TEST_CASE(unattestable_reject_counter_is_distinct_not_hot_loop)
{
    using node::matmul_trusted::CountTrustedRejectAsDistinct;
    using node::matmul_trusted::TrustedRejectStickyView;

    // First sighting of a hash counts.
    BOOST_CHECK(CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = false,
        .window_active = false,
    }));
    // Repeats inside the sticky window must not count again.
    BOOST_CHECK(!CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = true,
        .window_active = true,
    }));
    // After the window expires, a re-arm may count once more.
    BOOST_CHECK(CountTrustedRejectAsDistinct(TrustedRejectStickyView{
        .already_cached = true,
        .window_active = false,
    }));
}

BOOST_AUTO_TEST_CASE(attestations_survive_simulated_restart)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('a')};
    const uint256 block{Hex256('b')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_test.dat"};

    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = Hex256('c');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
        BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
        BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 42) ==
                    matmul::trusted::AddResult::Accepted);
        BOOST_REQUIRE(!node::matmul_trusted::Get(block, 42).empty());
        BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    }

    // Simulate process restart: drop the in-memory store, then reload.
    node::matmul_trusted::ResetForTest();
    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = Hex256('c');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
        BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
        const auto restored{node::matmul_trusted::Get(block, 42)};
        BOOST_REQUIRE_EQUAL(restored.size(), 1U);
        BOOST_CHECK(restored[0].statement.block_hash == block);
        BOOST_CHECK_EQUAL(restored[0].statement.block_height, 42);
        BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 42));
    }
}

BOOST_AUTO_TEST_CASE(historical_reverify_is_rate_limited)
{
    RuntimeReset reset;
    node::matmul_trusted::ResetHistoricalReverifyBudgetForTest();

    const uint256 a{Hex256('1')};
    const uint256 b{Hex256('2')};
    const uint256 c{Hex256('3')};
    const uint256 d{Hex256('4')};

    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(a) ==
        node::matmul_trusted::HistoricalReverifyAdmit::Allow);
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(a) ==
        node::matmul_trusted::HistoricalReverifyAdmit::AlreadyQueued);
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(b) ==
        node::matmul_trusted::HistoricalReverifyAdmit::Allow);
    // Burst exhausted (2 tokens); further distinct hashes are rate-limited
    // until refill, independent of queue room.
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(c) ==
        node::matmul_trusted::HistoricalReverifyAdmit::RateLimited);

    node::matmul_trusted::NoteHistoricalReverifyStarted(a);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyInflightForTest(), 1U);
    // Inflight cap is checked before spending another token, so a fresh hash
    // is refused as InflightFull while one ExactReplay is already running.
    BOOST_CHECK(
        node::matmul_trusted::TryAdmitHistoricalReverify(d) ==
        node::matmul_trusted::HistoricalReverifyAdmit::InflightFull);

    node::matmul_trusted::NoteHistoricalReverifyFinished(a);
    node::matmul_trusted::NoteHistoricalReverifyFinished(b);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyQueuedForTest(), 0U);
    BOOST_CHECK_EQUAL(
        node::matmul_trusted::HistoricalReverifyInflightForTest(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
