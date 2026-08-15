// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <common/args.h>
#include <hash.h>
#include <init.h>
#include <key_io.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/interface_ui.h>
#include <node/matmul_trusted_attestations.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <array>
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

//! Each simulated startup gets a private argument value store. Registration is
//! intentionally unnecessary here: AppInitParameterInteraction reads these
//! values but parsing/help is not under test. Reusing the fixture's global
//! manager would leak ForceSet values into later fixtures, while registering a
//! second complete server option table recursively constructs chain params.
bool TrustedMirrorStartupAccepted(const std::vector<std::string>& pubkeys,
                                  int64_t threshold,
                                  std::string& error)
{
    node::matmul_trusted::ResetForTest();
    ArgsManager args;
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
    BOOST_CHECK(!node::matmul_trusted::ServesAttestations());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
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

BOOST_AUTO_TEST_CASE(trusted_mirror_may_serve_cached_attestations)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    matmul::trusted::StoreConfig config;
    config.chain_id = Hex256('1');
    config.replay_authority_context = Hex256('a');
    config.trusted_signers = {signer.GetPubKey()};
    config.threshold = 1;
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::Configure(
        std::move(config), /*trusted_mirror=*/true,
        /*serve=*/true, std::chrono::milliseconds{20},
        error));
    BOOST_CHECK(node::matmul_trusted::IsTrustedMirror());
    BOOST_CHECK(node::matmul_trusted::ServesAttestations());
    BOOST_CHECK(!node::matmul_trusted::HasLocalSigner());
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
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(Hex256('5'), 9) ==
                matmul::trusted::AddResult::HeightOccupied);
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
        {key_a}, /*threshold=*/1, error), error);

    // 2-of-N with M == 1 is the same single-key authority, and also starts.
    RuntimeReset reset_again;
    BOOST_CHECK_MESSAGE(TrustedMirrorStartupAccepted(
        {key_a, key_b}, /*threshold=*/1, error), error);

    // What must STILL be refused is a threshold that cannot be met, and
    // duplicate keys inflating the signer count -- neither is a deployed
    // configuration and both are simply invalid.
    RuntimeReset reset_third;
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a}, /*threshold=*/2, error));
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
            {key_a, key_b}, /*threshold=*/2, error),
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
        {key_a, key_a}, /*threshold=*/2, error));
    BOOST_CHECK_MESSAGE(
        error.find("Duplicate -matmultrustedpubkey") != std::string::npos,
        error);
    BOOST_CHECK(!FinalizedTrustedMirrorInstalled(finalize_error));
    BOOST_CHECK(!node::matmul_trusted::IsConfigured());

    // Also refused when the duplicate is not adjacent and N would otherwise be
    // large enough on its own.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_b, key_a}, /*threshold=*/2, error));
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
            {key_a}, /*threshold=*/1, error),
        error);
    std::string finalize_error;
    BOOST_CHECK_MESSAGE(FinalizedTrustedMirrorInstalled(finalize_error),
                        finalize_error);
    BOOST_CHECK_EQUAL(node::matmul_trusted::Threshold(), 1U);

    // The duplicate rejection is chain-independent.
    BOOST_CHECK(!TrustedMirrorStartupAccepted(
        {key_a, key_a}, /*threshold=*/2, error));
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

    // The lower roots of an explicitly selected shallow recovery branch can
    // have less work than the losing active tip. They remain admissible so the
    // already-followed/authenticated upper branch can connect. This does not
    // bypass PARK, which is evaluated first.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = false,
            .on_recovery_branch = true,
            .on_parked_reorg_branch = false,
            .height = 186350,
            .authority_frontier = 186390,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);

    // Equal-work sibling must also be admissible. This is the exact production
    // stall: a mirror connected one side of a same-height race, so the winning
    // side carried EQUAL work, not greater. With a strict > test it never
    // fetched the branch that could rescue it, and it could not wait for the
    // authority to extend because being stranded froze its header sync.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 186335,
            .authority_frontier = 186390,
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

    // Active tip / last few ancestors: populate getmatmulattestedtip on a
    // linear chain (signer typically attests ~1 behind).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_recent_active_ancestor = true,
            .on_parked_reorg_branch = false,
            .height = 186010,
            .authority_frontier = 186011,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .extends_active_tip_chain = false,
            .on_recent_active_ancestor = true,
            .on_parked_reorg_branch = true,
            .height = 186010,
            .authority_frontier = 186011,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

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

    // Short tip-race reorg is first-class: admit even when it does not
    // extend the losing tip and would otherwise sit above a stale frontier
    // or in signer-absent backoff. Live: 187773 sibling vs 250c7e53.
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .better_work_reorg_candidate = true,
            .on_parked_reorg_branch = false,
            .height = 187774,
            .authority_frontier = 187773,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::Allow);
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 187773,
            .authority_frontier = 187859,
            .in_backoff = true,
        }) == TrustedAttestationAdmit::Allow);
    // Competing miner fork hundreds ahead is not a short reorg (live ~187975).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = false,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = false,
            .height = 187975,
            .authority_frontier = 187859,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectNotForwardOfTip);
    // Park still wins over a short-reorg flag (must not be a back door).
    BOOST_CHECK(
        EvaluateTrustedAttestationAdmit(TrustedAttestationAdmitView{
            .tip_extending = false,
            .short_tip_reorg = true,
            .extends_active_tip_chain = false,
            .on_parked_reorg_branch = true,
            .height = 187774,
            .authority_frontier = 187773,
            .in_backoff = false,
        }) == TrustedAttestationAdmit::RejectParkedReorg);

    using node::matmul_trusted::TrustedMirrorIsShortTipReorg;
    using node::matmul_trusted::TrustedMirrorPreferGetMmAttest;
    using node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH;
    BOOST_CHECK_EQUAL(TRUSTED_MIRROR_SHORT_REORG_DEPTH, 6);
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(0));
    BOOST_CHECK(TrustedMirrorIsShortTipReorg(1));
    BOOST_CHECK(TrustedMirrorIsShortTipReorg(6));
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(7));
    BOOST_CHECK(!TrustedMirrorIsShortTipReorg(187975 - 187773));
    using node::matmul_trusted::TrustedMirrorIndexExtendsActiveTip;
    using node::matmul_trusted::TrustedMirrorIndexIsCatchUpSuffix;
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        /*has_tip=*/false, /*has_index=*/true, 2, 1, true));
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        true, true, /*index_height=*/100, /*tip_height=*/100, true));
    BOOST_CHECK(!TrustedMirrorIndexExtendsActiveTip(
        true, true, 101, 100, /*index_ancestor_at_tip_is_tip=*/false));
    BOOST_CHECK(TrustedMirrorIndexExtendsActiveTip(true, true, 101, 100, true));
    BOOST_CHECK(TrustedMirrorIndexExtendsActiveTip(true, true, 102, 100, true));
    BOOST_CHECK(!TrustedMirrorIndexIsCatchUpSuffix(true, true, 101, 100, true));
    BOOST_CHECK(TrustedMirrorIndexIsCatchUpSuffix(true, true, 102, 100, true));
    BOOST_CHECK(!TrustedMirrorIndexIsCatchUpSuffix(true, true, 102, 100, false));
    using node::matmul_trusted::TrustedMirrorMaySelectMostWorkCandidate;
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/false,
        /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/false,
        /*has_quorum=*/false));
    // Signed tip must not be abandoned for a heavier attested short fork.
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/false, /*short_tip_reorg=*/true,
        /*has_quorum=*/true, /*active_tip_has_quorum=*/true));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/false));
    BOOST_CHECK(TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/true, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/false));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/true));
    BOOST_CHECK(!TrustedMirrorMaySelectMostWorkCandidate(
        /*extends_active_tip_chain=*/true, /*short_tip_reorg=*/false,
        /*has_quorum=*/false, /*active_tip_has_quorum=*/true,
        /*immediate_tip_child=*/true, /*would_abandon_attested=*/false,
        /*competing_attested_height=*/true));
    using node::matmul_trusted::TrustedMirrorMustDeferUnattestedConnect;
    BOOST_CHECK(TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/false, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorMustDeferUnattestedConnect(
        /*trusted_mirror_profile1=*/false, /*has_quorum=*/true));
    using node::matmul_trusted::MustDeferConflictingAttestedHeight;
    BOOST_CHECK(MustDeferConflictingAttestedHeight(
        /*configured=*/true, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*configured=*/true, /*candidate_has_quorum=*/true,
        /*competing_attested_height=*/true));
    BOOST_CHECK(!MustDeferConflictingAttestedHeight(
        /*configured=*/true, /*candidate_has_quorum=*/false,
        /*competing_attested_height=*/false));
    using node::matmul_trusted::TrustedMirrorAttestedSiblingIsActionable;
    // Qualifier 3ed2619c: the attested tip / self candidate must not defer
    // a sole linear tip-child.
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/false, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/false,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/false, /*has_quorum=*/true));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/false));
    BOOST_CHECK(!TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true,
        /*failed=*/true));
    BOOST_CHECK(TrustedMirrorAttestedSiblingIsActionable(
        /*distinct_from_candidate=*/true, /*same_parent=*/true,
        /*same_height_as_tip_child=*/true, /*has_quorum=*/true));
    using node::matmul_trusted::TrustedMirrorDeferUnattestedMostWorkForAttestedSibling;
    BOOST_CHECK(TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/false));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/true, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/false, /*candidate_extends_tip=*/true,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    BOOST_CHECK(!TrustedMirrorDeferUnattestedMostWorkForAttestedSibling(
        /*configured_profile1=*/true, /*candidate_extends_tip=*/false,
        /*candidate_has_quorum=*/false, /*attested_tip_child_exists=*/true));
    using node::matmul_trusted::BlocksBehindSignedFrontier;
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(188160, 187947), 213);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(187947, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(187946, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(-1, 187947), 0);
    BOOST_CHECK_EQUAL(BlocksBehindSignedFrontier(188160, -1), 0);
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/false));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false));
    BOOST_CHECK(TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/false, /*recent_active_ancestor=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/false,
        /*on_parked_reorg_branch=*/true, /*recent_active_ancestor=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/true, /*short_tip_reorg_missing_root=*/true,
        /*on_parked_reorg_branch=*/true));
    BOOST_CHECK(!TrustedMirrorPreferGetMmAttest(
        /*active_tip_child=*/false, /*short_tip_reorg_missing_root=*/true,
        /*on_parked_reorg_branch=*/true));
    using node::matmul_trusted::PreferGetMmAttestPeer;
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/true, /*recent_valid_mmattest=*/false));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/true, /*recent_valid_mmattest=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/true));
    BOOST_CHECK(PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false, /*recent_valid_mmattest=*/false,
        /*trusted_mirror=*/false, /*consensus_node=*/true));
    BOOST_CHECK(!PreferGetMmAttestPeer(
        /*has_attestation_archive_bit=*/false,
        /*recent_valid_mmattest=*/false));
}

BOOST_AUTO_TEST_CASE(competing_attested_index_rejects_fossil_depth)
{
    using node::matmul_trusted::TrustedMirrorMayAdoptCompetingAttestedIndex;
    using node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH;
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        /*attested_suffix_of_active_tip=*/true, /*lca_depth=*/0));
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(false, 1));
    BOOST_CHECK(TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, TRUSTED_MIRROR_SHORT_REORG_DEPTH));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(
        false, TRUSTED_MIRROR_SHORT_REORG_DEPTH + 1));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(false, 510));
    BOOST_CHECK(!TrustedMirrorMayAdoptCompetingAttestedIndex(false, 0));
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

BOOST_AUTO_TEST_CASE(tip_extending_occupancy_cap_blocks_sibling_flood)
{
    using node::matmul_trusted::EvaluateTipExtendingCapacity;
    using node::matmul_trusted::MakeTrustedWorkRank;
    using node::matmul_trusted::TrustedWorkRank;

    constexpr size_t kTipCapacity{8};
    std::vector<TrustedWorkRank> occupants;
    for (uint64_t sequence{1}; sequence <= kTipCapacity; ++sequence) {
        occupants.push_back(MakeTrustedWorkRank(
            /*tip_extending=*/true, /*height=*/101, /*tip_height=*/100,
            /*priority_rank=*/0, sequence));
    }

    // A ninth free Phase-1 sibling with identical work cannot grow the set.
    auto decision{EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, 0, 9), occupants,
        kTipCapacity)};
    BOOST_CHECK(!decision.allow);
    BOOST_CHECK(!decision.replace_index.has_value());

    // Capacity replacement is permitted only for a strictly better-ranked
    // request; total tip-extending occupancy remains bounded at eight.
    decision = EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, /*priority_rank=*/1, 9),
        occupants, kTipCapacity);
    BOOST_REQUIRE(decision.allow);
    BOOST_REQUIRE(decision.replace_index.has_value());
    BOOST_CHECK_LT(*decision.replace_index, occupants.size());

    occupants.pop_back();
    decision = EvaluateTipExtendingCapacity(
        MakeTrustedWorkRank(true, 101, 100, 0, 10), occupants,
        kTipCapacity);
    BOOST_CHECK(decision.allow);
    BOOST_CHECK(!decision.replace_index.has_value());
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
    const auto hints{node::matmul_trusted::AttestedFrontierHints()};
    BOOST_REQUIRE(!hints.empty());
    BOOST_CHECK_EQUAL(hints.back().height, 250);
    BOOST_CHECK(hints.back().hash == block_hi);

    statement.block_hash = uint256::ONE;
    statement.block_height = 250;
    const auto att_twin{matmul::trusted::SignStatement(statement, a)};
    BOOST_REQUIRE(att_twin);
    BOOST_CHECK(node::matmul_trusted::Add(*att_twin, uint256::ONE, 250) ==
                matmul::trusted::AddResult::Accepted);
    const auto dual{node::matmul_trusted::AttestedFrontierHints()};
    size_t at_250{0};
    bool saw_hi{false};
    bool saw_one{false};
    for (const auto& hint : dual) {
        if (hint.height != 250) continue;
        ++at_250;
        if (hint.hash == block_hi) saw_hi = true;
        if (hint.hash == uint256::ONE) saw_one = true;
    }
    BOOST_CHECK_EQUAL(at_250, 2);
    BOOST_CHECK(saw_hi);
    BOOST_CHECK(saw_one);
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(block_hi, 250));
    BOOST_CHECK(node::matmul_trusted::HasCompetingQuorum(uint256::ONE, 250));
    BOOST_CHECK(!node::matmul_trusted::HasCompetingQuorum(block_lo, 100));

    // Soft peer-tip hint can raise the raw high-water further.
    node::matmul_trusted::NoteAuthorityPeerTipHint(300);
    BOOST_CHECK_EQUAL(*node::matmul_trusted::AuthorityAttestedFrontier(), 300);
    // Production admit/park must not use that raw max when the hint is a
    // competing/unauthenticated height.
    using node::matmul_trusted::SelectAuthorityAttestedFrontier;
    using node::matmul_trusted::AuthorityFrontierCandidateUsable;
    BOOST_CHECK(!AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = false,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = false,
    }));
    BOOST_CHECK(!AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = true,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = true,
    }));
    BOOST_CHECK(AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = true,
        .short_tip_reorg = false,
        .on_parked_reorg_branch = false,
    }));
    BOOST_CHECK(AuthorityFrontierCandidateUsable({
        .on_or_extends_active_tip_chain = false,
        .short_tip_reorg = true,
        .on_parked_reorg_branch = false,
    }));
    // Live: attested 187773 on the losing sibling, peer hint 187859 on the
    // miner fork, signer actually at 187791. Effective frontier must not be
    // 187859.
    const auto capped{SelectAuthorityAttestedFrontier(
        /*attested_height=*/187773, /*attested_usable=*/true,
        /*peer_tip_hint=*/187859, /*hint_usable=*/false)};
    BOOST_REQUIRE(capped.has_value());
    BOOST_CHECK_EQUAL(*capped, 187773);
    const auto signer_short{SelectAuthorityAttestedFrontier(
        /*attested_height=*/187791, /*attested_usable=*/true,
        /*peer_tip_hint=*/187859, /*hint_usable=*/false)};
    BOOST_REQUIRE(signer_short.has_value());
    BOOST_CHECK_EQUAL(*signer_short, 187791);
    BOOST_CHECK(!SelectAuthorityAttestedFrontier(
                     /*attested_height=*/187859, /*attested_usable=*/false,
                     /*peer_tip_hint=*/187859, /*hint_usable=*/false)
                     .has_value());
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

    // Competing fork (not a tip-chain extension) must never displace via the
    // tip-chain-only path (AcceptBlockHeader / ordinary peers).
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

BOOST_AUTO_TEST_CASE(authority_header_preference_rescues_divergent_tip)
{
    using node::matmul_trusted::PreferTrustedMirrorAuthorityHeader;
    using node::matmul_trusted::TrustedMirrorAuthorityHeaderView;
    using node::matmul_trusted::TrustedMirrorMayDownloadCompetingBranch;

    // Non-authority competing fork must still be refused (fra1 regression).
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = false,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186394,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority equal-work sibling (same-height race loser) must displace the
    // tip-pinned best-header so headers can advance off the stranded tip.
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186393,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority heavier extension past the fork must become best-header.
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .candidate_height = 186674,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Parked deep-reorg branch stays refused even from an authority peer —
    // EMERGENCY park_depth must not be bypassable via header follow.
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = true,
        .candidate_height = 186674,
        .tip_height = 186393,
        .current_best_height = 186393,
        .current_best_extends_tip = true,
        .candidate_extends_current_best = false,
    }));

    // Authority short-reorg must displace a taller claimed-heaviest miner
    // fork that is not on the active tip (live: m_best_header 187978 vs
    // signer sibling 187791 while tip is 187773).
    BOOST_CHECK(PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .short_tip_reorg = true,
        .candidate_height = 187791,
        .tip_height = 187773,
        .current_best_height = 187978,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));
    // Without the short-reorg bit, a shorter authority header must not
    // displace the taller competing best-header (deep fork stays parked).
    BOOST_CHECK(!PreferTrustedMirrorAuthorityHeader(TrustedMirrorAuthorityHeaderView{
        .from_authority_peer = true,
        .extends_active_tip_chain = false,
        .better_work_reorg_candidate = true,
        .on_parked_reorg_branch = false,
        .short_tip_reorg = false,
        .candidate_height = 187791,
        .tip_height = 187773,
        .current_best_height = 187978,
        .current_best_extends_tip = false,
        .candidate_extends_current_best = false,
    }));

    // Download gate mirrors the same authority / park / followed-chain split.
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true));
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/true,
        /*better_or_equal_work=*/false, /*on_parked_reorg_branch=*/false));
    // Ordinary peer on the claimed-heaviest best-header chain must NOT open
    // the download gate: that header is the competing miner fork. Only a
    // short tip-race reorg (or an authority peer) may fetch a non-extending
    // branch.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/false,
        /*short_tip_reorg=*/true));
    // Equal-work short reorg is the consensus-miner race-loss fetch:
    // IsConfigured (not only IsTrustedMirror) callers use this helper.
    // Followed-chain does not bypass park-depth finality.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true,
        /*on_followed_best_header_chain=*/true));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/true,
        /*on_followed_best_header_chain=*/false,
        /*short_tip_reorg=*/true));
    // Less-work competing branch stays refused even when followed.
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/false, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    // Claimed-heavier must pass even when trust-adjusted work would lose
    // (headers-only suffix deeper than TRUST_ADJUSTED_WORK_ALLOWANCE_BLOCKS
    // while the active tip holds more authenticated work than fork+allowance).
    // Callers pass better_or_equal_work from nChainWork, never TrustAdjustedWork.
    BOOST_CHECK(TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/true, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false));
    BOOST_CHECK(!TrustedMirrorMayDownloadCompetingBranch(
        /*is_authority_peer=*/false, /*best_known_extends_tip=*/false,
        /*better_or_equal_work=*/true, /*on_parked_reorg_branch=*/false,
        /*on_followed_best_header_chain=*/true));
    using node::matmul_trusted::TrustedMirrorOnFollowedHeaderChain;
    BOOST_CHECK(TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/true,
        /*peer_best_is_ancestor_of_best_header=*/true,
        /*peer_best_extends_best_header=*/false));
    BOOST_CHECK(TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/true,
        /*peer_best_is_ancestor_of_best_header=*/false,
        /*peer_best_extends_best_header=*/true));
    BOOST_CHECK(!TrustedMirrorOnFollowedHeaderChain(
        /*best_header_known=*/false,
        /*peer_best_is_ancestor_of_best_header=*/true,
        /*peer_best_extends_best_header=*/true));
}

BOOST_AUTO_TEST_CASE(authority_peer_proof_is_branch_bound)
{
    using node::matmul_trusted::AuthorityProofCoversCandidate;

    BOOST_CHECK(AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true));

    // An old valid signature relayed by a peer is not authority for an
    // unrelated equal/heavier fork, and expiry closes even the certified
    // branch's temporary routing preference.
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/false));
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/false, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true));
    // A replayed signature below the current tip is a common-ancestor token,
    // not a branch certificate; accepting it would authorize either sibling.
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true,
        /*proof_not_behind_active_tip=*/false));
    BOOST_CHECK(!AuthorityProofCoversCandidate(
        /*proof_recent=*/true, /*proof_index_known=*/true,
        /*proof_height=*/100, /*candidate_height=*/120,
        /*candidate_descends_proof=*/true,
        /*proof_not_behind_active_tip=*/true,
        /*authority_context_matches=*/false));
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

BOOST_AUTO_TEST_CASE(durable_history_outlives_bounded_hot_cache)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('7')};
    const uint256 context{Hex256('8')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_long_history.dat"};
    constexpr size_t BLOCK_COUNT{4097};
    const uint256 first_block{(HashWriter{} << uint64_t{0}).GetHash()};
    const uint256 last_block{
        (HashWriter{} << uint64_t{BLOCK_COUNT - 1}).GetHash()};

    // Build a legacy flat archive one entry beyond the default 4096-block hot
    // cache. OpenPersistence migrates it to disk-backed authority history.
    constexpr char magic[16] = "BTX_MMATTEST_V1";
    DataStream encoded;
    encoded.write(AsBytes(Span{magic, sizeof(magic)}));
    encoded << uint64_t{BLOCK_COUNT};
    for (size_t i{0}; i < BLOCK_COUNT; ++i) {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = (HashWriter{} << uint64_t{i}).GetHash();
        statement.block_height = static_cast<int32_t>(i);
        statement.replay_authority_context = context;
        const auto attestation{matmul::trusted::SignStatement(statement, signer)};
        BOOST_REQUIRE(attestation.has_value());
        encoded << *attestation;
    }
    BOOST_REQUIRE(WriteBinaryFile(
        archive,
        std::string{reinterpret_cast<const char*>(encoded.data()),
                    encoded.size()}));

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    const auto stats{node::matmul_trusted::Stats()};
    BOOST_CHECK_LE(stats.stored_blocks, 4096U);
    BOOST_CHECK_LE(stats.stored_attestations, 16384U);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first_block, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last_block, static_cast<int32_t>(BLOCK_COUNT - 1)));
    BOOST_REQUIRE_EQUAL(node::matmul_trusted::Get(first_block, 0).size(), 1U);
    node::matmul_trusted::ClosePersistence();

    // Prove the LevelDB, rather than a rewritten bounded archive, owns the
    // full history after restart.
    std::error_code remove_ec;
    fs::remove(archive, remove_ec);
    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first_block, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last_block, static_cast<int32_t>(BLOCK_COUNT - 1)));
    const auto restart_stats{node::matmul_trusted::Stats()};
    BOOST_CHECK_EQUAL(restart_stats.stored_blocks, 4096U);
    // Startup verifies all 4097 database records but hydrates only the bounded
    // tail. An accepted count of 4097 would prove the old O(history*cache)
    // add/evict loop was still running.
    BOOST_CHECK_EQUAL(restart_stats.accepted, 4096U);
    BOOST_CHECK_EQUAL(restart_stats.evicted_blocks, 0U);
}

BOOST_AUTO_TEST_CASE(durable_history_is_namespaced_across_signer_rotation)
{
    RuntimeReset reset;
    const CKey old_signer{NewKey()};
    const CKey new_signer{NewKey()};
    const uint256 chain{Hex256('9')};
    const uint256 context{Hex256('a')};
    const uint256 block{Hex256('b')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_rotation_test.dat"};

    auto configure = [&](const CKey& signer) {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure(old_signer);
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 51) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    node::matmul_trusted::ResetForTest();

    // An intentional authority change must neither trust the old quorum nor
    // make startup fatal. It gets a separate durable namespace.
    configure(new_signer);
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(!node::matmul_trusted::HasQuorum(block, 51));
    BOOST_CHECK(node::matmul_trusted::SignAuthoritative(block, 51) ==
                matmul::trusted::AddResult::Accepted);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(block, 51));
}

BOOST_AUTO_TEST_CASE(durable_worker_checkpoints_wal_under_sustained_history)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('c')};
    const uint256 context{Hex256('d')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_wal_checkpoint.dat"};
    const fs::path wal{archive + ".wal"};
    constexpr size_t BLOCK_COUNT{4097};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        config.local_signer = signer;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/false,
            /*serve=*/true, std::chrono::milliseconds{50}, error));
    };

    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    for (size_t i{0}; i < BLOCK_COUNT; ++i) {
        const uint256 block{(HashWriter{} << uint64_t{i}).GetHash()};
        BOOST_CHECK(node::matmul_trusted::SignAuthoritative(
                        block, static_cast<int32_t>(i)) ==
                    matmul::trusted::AddResult::Accepted);
    }
    BOOST_REQUIRE(node::matmul_trusted::FlushPersistence(error));
    // Header-only is the steady checkpoint. This proves the worker did not
    // retain one legacy WAL record per historical block.
    BOOST_REQUIRE(fs::exists(wal));
    BOOST_CHECK_LE(fs::file_size(wal), 16U);
    node::matmul_trusted::ResetForTest();

    configure();
    error.clear();
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    const uint256 first{(HashWriter{} << uint64_t{0}).GetHash()};
    const uint256 last{
        (HashWriter{} << uint64_t{BLOCK_COUNT - 1}).GetHash()};
    BOOST_CHECK(node::matmul_trusted::HasQuorum(first, 0));
    BOOST_CHECK(node::matmul_trusted::HasQuorum(
        last, static_cast<int32_t>(BLOCK_COUNT - 1)));
    BOOST_CHECK_LE(node::matmul_trusted::Stats().stored_blocks, 4096U);
}

BOOST_AUTO_TEST_CASE(truncated_attestation_wal_fails_closed_and_is_preserved)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_truncated_test.dat"};
    const fs::path wal{archive + ".wal"};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = Hex256('d');
        config.replay_authority_context = Hex256('e');
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/false, std::chrono::milliseconds{50}, error));
    };
    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    node::matmul_trusted::ClosePersistence();

    // Simulate a torn record after the durable WAL header. Startup must not
    // discard or truncate it while reporting the failure.
    {
        FILE* file{fsbridge::fopen(wal, "ab")};
        BOOST_REQUIRE(file);
        const std::array<unsigned char, 3> torn{0x7f, 0x01, 0x02};
        BOOST_REQUIRE_EQUAL(fwrite(torn.data(), 1, torn.size(), file),
                            torn.size());
        BOOST_REQUIRE_EQUAL(fclose(file), 0);
    }
    const auto size_before{fs::file_size(wal)};

    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(fs::exists(wal));
    BOOST_CHECK_EQUAL(fs::file_size(wal), size_before);
}

BOOST_AUTO_TEST_CASE(invalid_signed_wal_record_fails_closed_and_is_preserved)
{
    RuntimeReset reset;
    const CKey signer{NewKey()};
    const uint256 chain{Hex256('4')};
    const uint256 context{Hex256('5')};
    const uint256 block{Hex256('6')};
    const fs::path archive{
        m_args.GetDataDirNet() / "matmul_attestations_invalid_sig_test.dat"};
    const fs::path wal{archive + ".wal"};

    auto configure = [&] {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {signer.GetPubKey()};
        config.threshold = 1;
        std::string error;
        BOOST_REQUIRE(node::matmul_trusted::Configure(
            std::move(config), /*trusted_mirror=*/true,
            /*serve=*/false, std::chrono::milliseconds{50}, error));
    };
    configure();
    std::string error;
    BOOST_REQUIRE(node::matmul_trusted::OpenPersistence(archive, error));
    node::matmul_trusted::ClosePersistence();

    matmul::trusted::ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = 73;
    statement.replay_authority_context = context;
    auto invalid{matmul::trusted::SignStatement(statement, signer)};
    BOOST_REQUIRE(invalid);
    BOOST_REQUIRE(!invalid->signature.empty());
    invalid->signature.front() = 0; // Valid encoding, invalid ECDSA payload.

    DataStream record;
    record << *invalid;
    DataStream prefix;
    prefix << static_cast<uint32_t>(record.size());
    {
        FILE* file{fsbridge::fopen(wal, "ab")};
        BOOST_REQUIRE(file);
        BOOST_REQUIRE_EQUAL(
            fwrite(prefix.data(), 1, prefix.size(), file), prefix.size());
        BOOST_REQUIRE_EQUAL(
            fwrite(record.data(), 1, record.size(), file), record.size());
        BOOST_REQUIRE_EQUAL(fclose(file), 0);
    }
    const auto [read_before, bytes_before]{ReadBinaryFile(wal)};
    BOOST_REQUIRE(read_before);

    node::matmul_trusted::ResetForTest();
    configure();
    error.clear();
    BOOST_CHECK(!node::matmul_trusted::OpenPersistence(archive, error));
    BOOST_CHECK(error.find("invalid-signature") != std::string::npos);
    const auto [read_after, bytes_after]{ReadBinaryFile(wal)};
    BOOST_REQUIRE(read_after);
    BOOST_CHECK(bytes_after == bytes_before);
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
