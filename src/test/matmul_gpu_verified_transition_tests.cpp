// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <kernel/chainstatemanager_opts.h>
#include <node/matmul_trusted_attestations.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_gpu_verified_transition_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_dump_floor_is_191714)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nMatMulPowLimitUpgradeHeight, 191714);
    BOOST_CHECK_EQUAL(c.nMatMulAsertHalfLifeUpgradeHeight, 191715);
    BOOST_CHECK_EQUAL(c.nMatMulAsertHalfLifeUpgrade, 14400);
    BOOST_CHECK_EQUAL(UintToArith256(c.powLimitUpgrade).GetCompact(), 0x1f0a3d70U);
    BOOST_CHECK_EQUAL(UintToArith256(c.powLimit).GetCompact(), 0x2066c154U);
    BOOST_CHECK(UintToArith256(c.powLimitUpgrade) < UintToArith256(c.powLimit));
    BOOST_CHECK(MatMulAsertPowLimitForNextHeight(c, 191713) == UintToArith256(c.powLimit));
    BOOST_CHECK(MatMulAsertPowLimitForNextHeight(c, 191714) == UintToArith256(c.powLimitUpgrade));
    BOOST_CHECK(MatMulAsertPowLimitForNextHeight(c, 191715) == UintToArith256(c.powLimitUpgrade));
}

BOOST_AUTO_TEST_CASE(mainnet_stall_recovery_is_inherit_not_dump)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& c = params->GetConsensus();

    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryHeight, 199299);
    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryAsertNum, 1U);
    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryAsertDen, 1U);
    BOOST_CHECK_EQUAL(c.nMatMulMaxBlockTimeAdvance, 1080);
    BOOST_CHECK_EQUAL(c.nMatMulMaxFutureMtpDriftHeight, 118482);
    BOOST_CHECK_EQUAL(c.nMatMulMaxFutureMtpDrift, 3600);
    BOOST_CHECK_EQUAL(c.nReorgProtectionStartHeight, 61000);
    BOOST_CHECK(!c.IsMatMulStallRecoveryActive(199298));
    BOOST_CHECK(c.IsMatMulStallRecoveryActive(199299));
}

BOOST_AUTO_TEST_CASE(mixed_034_does_not_create_new_encdr_flag_day)
{
    // 0.34 reuses the 0.33.4 EncDr stall-recovery flag day. Mixed
    // 0.33.4.2 / 0.34 peers must not silently disagree on nBits at 199299.
    // Pre-recovery luckypool nBits is rejected before AddToBlockIndex and
    // warned (DivergentPowForkShouldWarn), not stored. Do not reseal.
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryHeight, 199299);
    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryAsertNum, 1U);
    BOOST_CHECK_EQUAL(c.nMatMulStallRecoveryAsertDen, 1U);
    using node::matmul_trusted::DivergentPowForkShouldWarn;
    BOOST_CHECK(DivergentPowForkShouldWarn(
        /*stall_recovery_configured=*/true, /*stall_recovery_height=*/199299,
        /*header_height=*/199299, "bad-diffbits"));
    BOOST_CHECK(DivergentPowForkShouldWarn(true, 199299, 199300, "bad-diffbits"));
    BOOST_CHECK(!DivergentPowForkShouldWarn(true, 199299, 199298, "bad-diffbits"));
    BOOST_CHECK(!DivergentPowForkShouldWarn(false, 199299, 199299, "bad-diffbits"));
}

BOOST_AUTO_TEST_CASE(emergency_park_closes_dump_and_run_reorg)
{
    using kernel::DeepReorgAction;
    using kernel::DeepReorgShouldPark;
    using kernel::GetReorgProtectionProfileSettings;
    using kernel::ReorgProtectionProfile;
    using kernel::REORG_PROTECTION_DEPTH_DISABLED;

    const auto emergency = GetReorgProtectionProfileSettings(ReorgProtectionProfile::EMERGENCY);
    BOOST_CHECK(emergency.action == DeepReorgAction::PARK);
    BOOST_CHECK_EQUAL(emergency.park_depth, 6U);
    BOOST_CHECK_EQUAL(node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH, 6);
    BOOST_CHECK_EQUAL(static_cast<uint32_t>(node::matmul_trusted::TRUSTED_MIRROR_SHORT_REORG_DEPTH),
                      emergency.park_depth);

    // 2026-08-10/11: 151-block and 8-block rewrites park; 1–5 block races connect.
    BOOST_CHECK(DeepReorgShouldPark(DeepReorgAction::PARK, 6, 151, /*recovery_escape=*/false));
    BOOST_CHECK(DeepReorgShouldPark(DeepReorgAction::PARK, 6, 8, false));
    BOOST_CHECK(DeepReorgShouldPark(DeepReorgAction::PARK, 6, 7, false));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::PARK, 6, 6, false));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::PARK, 6, 5, false));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::PARK, 6, 1, false));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::PARK, 6, 151, /*recovery_escape=*/true));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::WARN, 6, 151, false));
    BOOST_CHECK(!DeepReorgShouldPark(DeepReorgAction::PARK, REORG_PROTECTION_DEPTH_DISABLED, 151, false));

    const auto archive = GetReorgProtectionProfileSettings(ReorgProtectionProfile::ARCHIVE);
    BOOST_CHECK(archive.action == DeepReorgAction::WARN);
    BOOST_CHECK_EQUAL(archive.park_depth, REORG_PROTECTION_DEPTH_DISABLED);
    BOOST_CHECK(!DeepReorgShouldPark(archive.action, archive.park_depth, 151, false));

    using kernel::WorkBasedReorgRecoveryMayArm;
    // Shallow races may arm work-based unpark. Parked depth must not:
    // dump-and-run that ExactReplays itself would auto-connect.
    BOOST_CHECK(WorkBasedReorgRecoveryMayArm(/*reorg_depth=*/1, /*park_depth=*/6));
    BOOST_CHECK(WorkBasedReorgRecoveryMayArm(6, 6));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(7, 6));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(151, 6));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(0, 6));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(-1, 6));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(151, REORG_PROTECTION_DEPTH_DISABLED));
    BOOST_CHECK(DeepReorgShouldPark(DeepReorgAction::PARK, 6, 7, false));
    BOOST_CHECK(!WorkBasedReorgRecoveryMayArm(7, 6));
}

BOOST_AUTO_TEST_CASE(cadence_hold_closes_live_tip_extension_burst)
{
    using kernel::CadenceHoldAllowedHeight;
    using kernel::CadenceHoldOrigin;
    using kernel::CadenceHoldShouldHold;
    using kernel::CadenceFirstSeenLooksLikeDump;
    using kernel::DEFAULT_CADENCE_BURST_MAX;
    using kernel::REORG_PROTECTION_DEPTH_DISABLED;

    constexpr int64_t spacing{90};
    constexpr int64_t live_window{2 * spacing};
    constexpr uint32_t burst{DEFAULT_CADENCE_BURST_MAX};
    constexpr uint32_t park{6};
    constexpr int tip_h{200000};
    constexpr int64_t tip_t{1'700'000'000};

    // Live tip + 4-block extension holds; <=3 does not.
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 3, /*fork_depth=*/0, park, false, false));
    BOOST_CHECK(CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                      tip_h + 4, 0, park, false, false));
    BOOST_CHECK(CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                      tip_h + 40, 0, park, false, false));
    BOOST_CHECK(CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                      tip_h + 80, 0, park, false, false));

    // IBD, stale tip (>180s), burst_max=0, recovery_escape do not hold.
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 40, 0, park, /*in_ibd=*/true, false));
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t + 181, tip_t, tip_h,
                                       tip_h + 40, 0, park, false, false));
    BOOST_CHECK(!CadenceHoldShouldHold(/*burst_max=*/0, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 40, 0, park, false, false));
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 40, 0, park, false, /*recovery_escape=*/true));

    // 3.2: attested abandon escapes cadence on trusted mirrors only.
    using kernel::CadenceHoldQuorumMayEscape;
    BOOST_CHECK(CadenceHoldQuorumMayEscape(/*trusted_mirror=*/true, /*attested_abandon=*/true));
    BOOST_CHECK(!CadenceHoldQuorumMayEscape(/*trusted_mirror=*/false, true));
    BOOST_CHECK(!CadenceHoldQuorumMayEscape(true, /*attested_abandon=*/false));
    BOOST_CHECK(!CadenceHoldQuorumMayEscape(false, false));

    // 2.2 header pre-aging: unknown body span must not inherit header span.
    using kernel::CadenceUsableFirstSeenSpan;
    BOOST_CHECK_EQUAL(CadenceUsableFirstSeenSpan(/*header=*/80 * spacing, /*body=*/0), -1);
    BOOST_CHECK_EQUAL(CadenceUsableFirstSeenSpan(1, /*body=*/80 * spacing), 80 * spacing);
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(
        80, CadenceUsableFirstSeenSpan(1, /*body=*/0), spacing, burst));
    BOOST_CHECK(CadenceFirstSeenLooksLikeDump(
        80, CadenceUsableFirstSeenSpan(80 * spacing, /*body=*/1), spacing, burst));

    // 2.4 restart: empty first-seen + empty last-connect stays armed.
    using kernel::CadenceHoldRestartLeavesHoldArmed;
    BOOST_CHECK(CadenceHoldRestartLeavesHoldArmed(/*ntime_received_unknown=*/true,
                                                 /*last_connect_unknown=*/true));
    BOOST_CHECK(!CadenceHoldRestartLeavesHoldArmed(false, true));
    BOOST_CHECK(!CadenceHoldRestartLeavesHoldArmed(true, false));

    using kernel::CadenceHoldUsesHeaderArrivalAsExtra;
    using kernel::CadenceHoldHonestTrickleIsNakamoto;
    using kernel::CadenceHoldIdleAllowedIsBounded;
    // Constexpr predicate only. Production origin selection is
    // ChainstateManager::GetCadenceHoldAllowedHeight (see
    // validation_chainstate_tests/chainstate_cadence_hold_production_origin_selection).
    BOOST_CHECK(!CadenceHoldUsesHeaderArrivalAsExtra());
    BOOST_CHECK(CadenceHoldHonestTrickleIsNakamoto());
    // Header pre-aging must not manufacture a usable first-seen span.
    BOOST_CHECK_EQUAL(CadenceUsableFirstSeenSpan(/*header=*/80 * spacing, /*body=*/0), -1);
    // Honest 90s trickle: extra = burst + 1 after one spacing, not a freeze.
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + spacing, spacing, burst),
                      tip_h + static_cast<int>(burst) + 1);
    BOOST_CHECK(CadenceHoldIdleAllowedIsBounded(
        CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 2 * spacing, spacing, burst),
        tip_h, burst, /*extra_spacings=*/2));
    BOOST_CHECK(CadenceHoldIdleAllowedIsBounded(
        CadenceHoldAllowedHeight(tip_h, tip_t, tip_t, spacing, burst),
        tip_h, burst, /*extra_spacings=*/0));
    BOOST_CHECK_NE(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 180, spacing, burst),
                   std::numeric_limits<int>::max());

    // 6.3 snapshot catch-up: disk followed headers only. Live gossip does not disarm.
    using kernel::CadenceHoldSnapshotCatchUpDisarms;
    BOOST_CHECK(CadenceHoldSnapshotCatchUpDisarms(
        /*from_snapshot=*/true, /*extends_tip=*/true, /*from_disk=*/true));
    BOOST_CHECK(!CadenceHoldSnapshotCatchUpDisarms(true, true, /*from_disk=*/false));
    BOOST_CHECK(!CadenceHoldSnapshotCatchUpDisarms(
        /*from_snapshot=*/false, true, true));
    BOOST_CHECK(!CadenceHoldSnapshotCatchUpDisarms(true, /*extends_tip=*/false, true));

    using kernel::CadenceHoldFollowedCatchUpDisarms;
    BOOST_CHECK(CadenceHoldFollowedCatchUpDisarms(
        /*extends_tip=*/true, /*followed_ahead=*/423));
    BOOST_CHECK(CadenceHoldFollowedCatchUpDisarms(true, 100));
    BOOST_CHECK(!CadenceHoldFollowedCatchUpDisarms(true, 99));
    BOOST_CHECK(!CadenceHoldFollowedCatchUpDisarms(/*extends_tip=*/false, 423));

    // PARK owns reorg_depth > 6. Shallow-fork dump (fork_depth <= 6) still holds.
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 34, /*fork_depth=*/7, park, false, false));
    BOOST_CHECK(CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                      tip_h + 34, /*fork_depth=*/6, park, false, false));
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 2, /*fork_depth=*/1, park, false, false));

    // Future-stamped origin walk is not the production extra source (attackers
    // stamp nTime <= now). Production freezes a wall-clock anchor.
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t, spacing, burst), tip_h + 3);
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h + 3, tip_t, tip_t, spacing, burst), tip_h + 6);
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 90, spacing, burst), tip_h + 4);
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 180, spacing, burst), tip_h + 5);
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 7200, spacing, burst),
                      tip_h + 3 + 80);
    // Idle 180s after last connect: bounded credit (burst+2), never INT_MAX.
    BOOST_CHECK_NE(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t + 180, spacing, burst),
                   std::numeric_limits<int>::max());

    // Future-stamped drip: origin stays on the last honest tip.
    struct Node {
        int nHeight;
        int64_t nTime;
        Node* pprev;
    };
    Node honest{tip_h, tip_t, nullptr};
    Node fut1{tip_h + 1, tip_t + 90, &honest};
    Node fut2{tip_h + 2, tip_t + 180, &fut1};
    const Node* origin = CadenceHoldOrigin(&fut2, tip_t);
    BOOST_CHECK(origin == &honest);
    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(origin->nHeight, origin->nTime, tip_t, spacing, burst),
                      tip_h + 3);

    BOOST_CHECK_EQUAL(CadenceHoldAllowedHeight(tip_h, tip_t, tip_t, spacing, 0),
                      std::numeric_limits<int>::max());
    BOOST_CHECK(CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                      tip_h + 40, 0, REORG_PROTECTION_DEPTH_DISABLED, false, false));
    BOOST_CHECK(!CadenceHoldShouldHold(burst, live_window, spacing, tip_t, tip_t, tip_h,
                                       tip_h + 40, 0, REORG_PROTECTION_DEPTH_DISABLED, true, false));
}

BOOST_AUTO_TEST_CASE(cadence_first_seen_and_header_lead)
{
    using kernel::CadenceFirstSeenLooksLikeDump;
    using kernel::MAX_UNAUTHENTICATED_HEADER_LEAD;
    using kernel::UnauthenticatedHeaderLeadExceeded;

    constexpr int64_t spacing{90};
    constexpr uint32_t burst{3};

    // Clustered first-seen of a >burst height span is a dump. Disk-loaded
    // headers (span < 0) and spans within burst are not.
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(/*height_span=*/3, /*seen=*/0, spacing, burst));
    BOOST_CHECK(CadenceFirstSeenLooksLikeDump(4, /*seen=*/0, spacing, burst));
    BOOST_CHECK(CadenceFirstSeenLooksLikeDump(80, 1, spacing, burst));
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(80, 80 * spacing, spacing, burst));
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(80, 77 * spacing, spacing, burst));
    BOOST_CHECK(CadenceFirstSeenLooksLikeDump(80, 77 * spacing - 1, spacing, burst));
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(80, /*seen=*/-1, spacing, burst));
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(80, 0, spacing, /*burst_max=*/0));

    // Honest 90s trickle: first-seen span matches claimed cadence.
    BOOST_CHECK(!CadenceFirstSeenLooksLikeDump(10, 7 * spacing, spacing, burst));

    const int tip{200000};
    BOOST_CHECK(!UnauthenticatedHeaderLeadExceeded(
        tip, tip + 1, /*extends_active_tip=*/false, false, false));
    BOOST_CHECK(!UnauthenticatedHeaderLeadExceeded(
        tip, tip + MAX_UNAUTHENTICATED_HEADER_LEAD, false, false, false));
    BOOST_CHECK(UnauthenticatedHeaderLeadExceeded(
        tip, tip + MAX_UNAUTHENTICATED_HEADER_LEAD + 1, false, false, false));
    BOOST_CHECK(kernel::UnauthenticatedHeaderLeadAtCap(
        tip, tip + MAX_UNAUTHENTICATED_HEADER_LEAD, false, false, false));
    BOOST_CHECK(!kernel::UnauthenticatedHeaderLeadAtCap(
        tip, tip + MAX_UNAUTHENTICATED_HEADER_LEAD - 1, false, false, false));
    // Followed chain, IBD, attested/frontier: never cap (cadence hold sees dumps).
    BOOST_CHECK(!UnauthenticatedHeaderLeadExceeded(
        tip, tip + 200, /*extends_active_tip=*/true, false, false));
    BOOST_CHECK(!UnauthenticatedHeaderLeadExceeded(
        tip, tip + 200, false, /*attested_or_frontier=*/true, false));
    BOOST_CHECK(!UnauthenticatedHeaderLeadExceeded(
        tip, tip + 200, false, false, /*in_ibd=*/true));
}

BOOST_AUTO_TEST_CASE(consensus_without_signer_does_not_park_bypass)
{
    using node::matmul_trusted::PinSteersFindUniqueCompetingAttestedIndex;
    using node::matmul_trusted::SkipExactReplayForGpuAttestation;
    using node::matmul_trusted::ShouldAdvanceBestKnownFromMmAttest;
    using matmul::trusted::AddResult;

    BOOST_CHECK(!PinSteersFindUniqueCompetingAttestedIndex(
        /*trusted_mirror=*/false, /*has_local_signer=*/false));
    using node::matmul_trusted::UnprivilegedNodeIgnoresDualQuorumPin;
    using node::matmul_trusted::DualQuorumSameHeightTwinsFailClosed;
    using node::matmul_trusted::DualQuorumIncomparableFailClosed;
    using node::matmul_trusted::MainnetTrustedMirrorRefusesSingleKey;
    BOOST_CHECK(UnprivilegedNodeIgnoresDualQuorumPin(false, false));
    BOOST_CHECK(!UnprivilegedNodeIgnoresDualQuorumPin(/*trusted_mirror=*/true, false));
    BOOST_CHECK(!UnprivilegedNodeIgnoresDualQuorumPin(false, /*has_local_signer=*/true));
    // Predicate only. Production fork choice is
    // validation_chainstate_tests/chainstate_consensus_gold_standard_ignores_cleared_attestations.
    BOOST_CHECK(DualQuorumSameHeightTwinsFailClosed(
        /*tip_has_quorum=*/true, /*competing_same_height_has_quorum=*/true,
        /*signed_frontier_strictly_ahead=*/false));
    BOOST_CHECK(!DualQuorumSameHeightTwinsFailClosed(true, true, true));
    BOOST_CHECK(DualQuorumIncomparableFailClosed(true, true));
    BOOST_CHECK(MainnetTrustedMirrorRefusesSingleKey(
        /*trusted_mirror=*/true, /*mainnet=*/true, /*n_signers=*/2,
        /*threshold=*/1, /*allow_single_key_override=*/false));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        true, true, 2, 2, false));
    BOOST_CHECK(!MainnetTrustedMirrorRefusesSingleKey(
        /*trusted_mirror=*/false, true, 1, 1, false));
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(
        /*has_attestation=*/true, /*trusted_mirror=*/false));
    // Pin quorum on a consensus miner is telemetry, not an ExactReplay skip.
    // AdmitMatMulBlockVerification must call this predicate, not `if (has_quorum)`.
    BOOST_CHECK(SkipExactReplayForGpuAttestation(
        /*has_attestation=*/true, /*trusted_mirror=*/true));
    BOOST_CHECK(!SkipExactReplayForGpuAttestation(false, true));
    BOOST_CHECK(!ShouldAdvanceBestKnownFromMmAttest(
        /*known_profile1=*/true, /*header_failed=*/false, AddResult::Heard));
    using node::matmul_trusted::PinMayVetoUnattestedTipChildGpu;
    using node::matmul_trusted::GetMmAttestIsConnectTipValidityGate;
    using node::matmul_trusted::ArchiveServiceBitIsValidityRequirement;
    using node::matmul_trusted::UnconnectedHaveDataMayKickAbc;
    using node::matmul_trusted::ConsensusMayClaimUnattestedTipChildBody;
    BOOST_CHECK(!PinMayVetoUnattestedTipChildGpu(false));
    BOOST_CHECK(!GetMmAttestIsConnectTipValidityGate(false));
    BOOST_CHECK(!ArchiveServiceBitIsValidityRequirement());
    BOOST_CHECK(UnconnectedHaveDataMayKickAbc(false, false, false));
    BOOST_CHECK(ConsensusMayClaimUnattestedTipChildBody(
        true, false, false, false, false));
    using node::matmul_trusted::PinMayDenyAttestedChainTipChild;
    using node::matmul_trusted::ConsensusMinerMayFetchCompetingShortReorg;
    BOOST_CHECK(!PinMayDenyAttestedChainTipChild(false, false));
    BOOST_CHECK(PinMayDenyAttestedChainTipChild(true, false));
    BOOST_CHECK(ConsensusMinerMayFetchCompetingShortReorg(
        false, true, true, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingShortReorg(
        false, false, true, true));
    using node::matmul_trusted::ConsensusMinerMayFetchCompetingHeavierFork;
    BOOST_CHECK(ConsensusMinerMayFetchCompetingHeavierFork(false, false, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(true, false, true));
    BOOST_CHECK(!ConsensusMinerMayFetchCompetingHeavierFork(false, true, true));
    using node::matmul_trusted::ConsensusMinerMayFollowHeavierDisconnectedHeader;
    BOOST_CHECK(ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, false, false, false, true, true));
    BOOST_CHECK(ConsensusMinerMayFollowHeavierDisconnectedHeader(
        false, /*extends_tip=*/true, false, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayFollowHeavierDisconnectedHeader(
        true, false, false, false, true, true));
    using node::matmul_trusted::ConsensusMinerMayReorgPastParkForStaleHeavierFork;
    BOOST_CHECK(ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        false, false, true, true));
    BOOST_CHECK(!ConsensusMinerMayReorgPastParkForStaleHeavierFork(
        false, false, true, false));
    using node::matmul_trusted::ExactReplayGpuThrottleRequiresPin;
    using node::matmul_trusted::ExactReplayAdmissionThrottleApplies;
    using node::matmul_trusted::MatMulSpeculativeRcPendingLimit;
    BOOST_CHECK(!ExactReplayGpuThrottleRequiresPin());
    BOOST_CHECK(ExactReplayAdmissionThrottleApplies(true, false));
    BOOST_CHECK_EQUAL(MatMulSpeculativeRcPendingLimit(false), 1u);
}

BOOST_AUTO_TEST_CASE(may_serve_getheaders_quorum_or_work_or_download)
{
    using node::matmul_trusted::MayServeGetHeaders;

    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/true, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/false));
    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/true,
        /*chain_work_meets_minimum=*/false));
    BOOST_CHECK(MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/true));
    BOOST_CHECK(!MayServeGetHeaders(
        /*download_permission=*/false, /*tip_has_quorum=*/false,
        /*chain_work_meets_minimum=*/false));
}

BOOST_AUTO_TEST_CASE(authority_headers_keep_polling_gpu_after_version)
{
    using node::matmul_trusted::TrustedMirrorShouldRequestAuthorityHeaders;

    BOOST_CHECK(!TrustedMirrorShouldRequestAuthorityHeaders(false, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(true, 191713, 191713));
    BOOST_CHECK(TrustedMirrorShouldRequestAuthorityHeaders(false, 191690, 191713));
}

BOOST_AUTO_TEST_CASE(attestor_and_mirror_ignore_inbound_miners)
{
    using node::matmul_trusted::TrustedMirrorIgnoreNonAuthorityInboundBlock;
    using node::matmul_trusted::TrustedMirrorMayAcceptPeerBlockBody;

    BOOST_CHECK(TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, true, true, true));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, false));
    BOOST_CHECK(!TrustedMirrorIgnoreNonAuthorityInboundBlock(false, false, true, true));
    // GPU attestors pass trusted_mirror=true into the ignore helper. Unsolicited
    // miner BLOCK is still dropped unless MayAccept (GPU or our outbound
    // archive). INV/HEADERS announcements are a separate predicate.
    const bool ignore_miner{
        TrustedMirrorIgnoreNonAuthorityInboundBlock(true, false, true, true)};
    BOOST_CHECK(ignore_miner);
    BOOST_CHECK(!TrustedMirrorMayAcceptPeerBlockBody(
        /*this_gpu=*/false, /*this_inbound=*/true, /*this_archive_or_mirror=*/false));
    using node::matmul_trusted::AuthorityMayIngestInboundMinerAnnouncement;
    BOOST_CHECK(AuthorityMayIngestInboundMinerAnnouncement(
        true, true, false, false, /*announce_msg=*/true));
    BOOST_CHECK(!AuthorityMayIngestInboundMinerAnnouncement(
        true, true, false, false, /*announce_msg=*/false));
}

BOOST_AUTO_TEST_CASE(asert_ntime_cap_sequence_several_blocks)
{
    // 6.4 / PR #119: consecutive headers at parent-cap, cap-1, and the
    // rejected cap+1 bound. Do not reseal EncDr/ASERT/F.
    auto consensus = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    consensus.fMatMulPOW = true;
    consensus.nMatMulStallRecoveryHeight = 0;
    consensus.nMatMulMaxBlockTimeAdvance = 30;
    consensus.nMatMulAsertClampedMinInterval = 90;
    consensus.nMatMulMaxFutureMtpDriftHeight = std::numeric_limits<int32_t>::max();

    constexpr int kBlocks = 12;
    std::vector<CBlockIndex> blocks(kBlocks);
    const int64_t t0{1'700'000'000};
    const int64_t cap{consensus.nMatMulMaxBlockTimeAdvance};
    for (int i = 0; i < kBlocks; ++i) {
        blocks[i].nHeight = i;
        blocks[i].pprev = (i == 0) ? nullptr : &blocks[i - 1];
        blocks[i].BuildSkip();
        if (i == 0) {
            blocks[i].nTime = static_cast<uint32_t>(t0);
            continue;
        }
        if (i % 3 == 1) {
            blocks[i].nTime = blocks[i - 1].nTime + static_cast<uint32_t>(cap);
        } else if (i % 3 == 2) {
            blocks[i].nTime = blocks[i - 1].nTime + static_cast<uint32_t>(cap - 1);
        } else {
            blocks[i].nTime = blocks[i - 1].nTime + static_cast<uint32_t>(cap);
        }
    }

    for (int i = 1; i < kBlocks; ++i) {
        const auto allowed = consensus.MaxMatMulAllowedBlockTime(
            blocks[i].nHeight, blocks[i - 1].GetBlockTime(),
            blocks[i - 1].GetMedianTimePast());
        BOOST_REQUIRE(allowed.has_value());
        BOOST_CHECK_EQUAL(*allowed, blocks[i - 1].GetBlockTime() + cap);
        BOOST_CHECK_LE(blocks[i].GetBlockTime(), *allowed);
        BOOST_CHECK_GT(blocks[i - 1].GetBlockTime() + cap + 1, *allowed);
    }
    const int64_t cap_plus_one{
        blocks.back().GetBlockTime() + cap + 1};
    const auto next_allowed = consensus.MaxMatMulAllowedBlockTime(
        blocks.back().nHeight + 1, blocks.back().GetBlockTime(),
        blocks.back().GetMedianTimePast());
    BOOST_REQUIRE(next_allowed.has_value());
    BOOST_CHECK_EQUAL(*next_allowed, blocks.back().GetBlockTime() + cap);
    BOOST_CHECK_GT(cap_plus_one, *next_allowed);
}

BOOST_AUTO_TEST_CASE(ibd_age_only_stale_tip_still_announces_and_may_mine)
{
    using kernel::IbdIsAgeOnlyStaleTip;
    using kernel::IbdIsHistoricalCatchUp;
    using kernel::IbdShouldSuppressBlockAnnounce;
    using kernel::MayFastRelayNewTipChild;
    using kernel::MiningTemplateShouldRefuseIbd;

    // Historical catch-up: loading, no tip, or insufficient nMinimumChainWork.
    BOOST_CHECK(IbdIsHistoricalCatchUp(/*loading=*/true, true, true));
    BOOST_CHECK(IbdIsHistoricalCatchUp(false, /*has_tip=*/false, true));
    BOOST_CHECK(IbdIsHistoricalCatchUp(false, true, /*sufficient_work=*/false));
    BOOST_CHECK(!IbdIsHistoricalCatchUp(false, true, true));

    BOOST_CHECK(IbdShouldSuppressBlockAnnounce(true, true, true));
    BOOST_CHECK(IbdShouldSuppressBlockAnnounce(false, false, true));
    BOOST_CHECK(IbdShouldSuppressBlockAnnounce(false, true, false));
    BOOST_CHECK(!IbdShouldSuppressBlockAnnounce(false, true, true));

    BOOST_CHECK(MiningTemplateShouldRefuseIbd(true, true, true));
    BOOST_CHECK(MiningTemplateShouldRefuseIbd(false, false, true));
    BOOST_CHECK(MiningTemplateShouldRefuseIbd(false, true, false));
    BOOST_CHECK(!MiningTemplateShouldRefuseIbd(false, true, true));

    // Age-only: in_ibd solely because tip nTime > -maxtipage (stalled restart).
    BOOST_CHECK(IbdIsAgeOnlyStaleTip(/*in_ibd=*/true, false, true, true));
    BOOST_CHECK(!IbdIsAgeOnlyStaleTip(/*in_ibd=*/false, false, true, true));
    BOOST_CHECK(!IbdIsAgeOnlyStaleTip(true, /*loading=*/true, true, true));
    BOOST_CHECK(!IbdIsAgeOnlyStaleTip(true, false, /*has_tip=*/false, true));
    BOOST_CHECK(!IbdIsAgeOnlyStaleTip(true, false, true, /*work=*/false));

    BOOST_CHECK(MayFastRelayNewTipChild(/*extends=*/true, false, true, true));
    BOOST_CHECK(!MayFastRelayNewTipChild(/*extends=*/false, false, true, true));
    BOOST_CHECK(!MayFastRelayNewTipChild(true, /*loading=*/true, true, true));
    BOOST_CHECK(!MayFastRelayNewTipChild(true, false, true, /*work=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
