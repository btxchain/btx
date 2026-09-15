// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// V11 matrix id -> BOOST_AUTO_TEST_CASE
// V11-RECIP-01  recip_needed_verified_free_only
// V11-RECIP-02  recip_paid_unsolicited_corrupt_no_credit
// V11-RECIP-03  recip_no_duplicate_piece_credit
// V11-RECIP-04  recip_seven_day_decay_28_day_horizon
// V11-RECIP-05  recip_weight_bounded_1_to_4
// V11-RECIP-06  recip_rarity_multiplier_cap_2
// V11-RECIP-07  recip_lane_20_60_20_congestion
// V11-RECIP-08  recip_unused_lanes_lend
// V11-RECIP-09  recip_per_key_churn_within_aggregate
// V11-RECIP-10  recip_nat_newcomer_ordinary_free
// V11-RECIP-11  recip_giveback_stops_no_fake_demand
// V11-RECIP-12  recip_score_never_touches_banman_addrman
// V11-IDENT-01  ident_store_without_wallet
// V11-IDENT-02  ident_spending_address_not_research_id
// V11-IDENT-03  ident_provider_id_byte_identical
// V11-IDENT-04  ident_delegation_bound_to_service_key
// V11-IDENT-05  ident_delegation_depth_expiry_scopes
// V11-IDENT-06  ident_service_key_cannot_spend_or_root
// V11-IDENT-07  ident_revocation_scoped
// V11-IDENT-08  ident_rotation_does_not_clone_credit
// V11-IDENT-09  ident_backup_vs_public_export
// V11-IDENT-10  ident_no_arbitrary_digest_wallet_sign
// V11-ACL-01    acl_invalid_crypto_rejected_despite_allow
// V11-ACL-02    acl_hard_ceiling_despite_preferred
// V11-ACL-03    acl_local_deny_wins
// V11-ACL-04    acl_quarantine_not_cleared_by_trust_bundle
// V11-ACL-05    acl_exact_exception_explained
// V11-ACL-06    acl_subscribed_warning_not_deny
// V11-ACL-07    acl_no_monetary_noban_or_addr
// V11-ACL-08    acl_complaint_never_writes_banman
// V11-ACL-09    acl_corrupt_piece_source_not_relay
// V11-ACL-10    acl_age_balance_not_trust
// V11-ACL-11    acl_expiry_vs_revocation_tombstone
// V11-ACL-12    acl_public_error_hides_private
// V11-COMM-01   comm_collection_sorted_unique_512
// V11-COMM-02   comm_collection_cannot_qualify_or_load_code
// V11-COMM-03   comm_alias_key_from_root_and_slug
// V11-COMM-04   comm_alias_sequence_conflict_freeze
// V11-COMM-05   comm_alias_never_chains

#include <modelnet/acl.h>
#include <modelnet/cores.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/qualification.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_v11_negative_tests, BasicTestingSetup)

static constexpr int64_t kPiece = 64 * static_cast<int64_t>(modelnet::MIB);

static int CountLane(const std::vector<std::string>& lanes, const std::string& name)
{
    return static_cast<int>(std::count(lanes.begin(), lanes.end(), name));
}

static modelnet::Digest48 DigestTag(unsigned char a, unsigned char b = 0)
{
    modelnet::Digest48 d;
    d.data[0] = a;
    d.data[1] = b;
    return d;
}

BOOST_AUTO_TEST_CASE(recip_needed_verified_free_only)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p1", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("p1", 0), kPiece);
    BOOST_CHECK_EQUAL(ledger.Effective("p2", 0), 0);
}

BOOST_AUTO_TEST_CASE(recip_paid_unsolicited_corrupt_no_credit)
{
    modelnet::ReciprocityLedger paid;
    BOOST_CHECK(!paid.Received("p", "art", 0, 0, kPiece, 0, true, true, true, 3));
    BOOST_CHECK_EQUAL(paid.Effective("p", 0), 0);

    modelnet::ReciprocityLedger unsolicited;
    BOOST_CHECK(!unsolicited.Received("p", "art", 0, 1, kPiece, 0, true, true, false, 3, true));
    BOOST_CHECK_EQUAL(unsolicited.Effective("p", 0), 0);

    modelnet::ReciprocityLedger corrupt;
    BOOST_CHECK(!corrupt.Received("p", "art", 0, 2, kPiece, 0, false, true, false, 3));
    BOOST_CHECK_EQUAL(corrupt.Effective("p", 0), 0);

    modelnet::ReciprocityLedger not_needed;
    BOOST_CHECK(!not_needed.Received("p", "art", 0, 3, kPiece, 0, true, false, false, 3));
    BOOST_CHECK_EQUAL(not_needed.Effective("p", 0), 0);

    modelnet::ReciprocityLedger receipt;
    BOOST_CHECK(!receipt.CreditThirdPartyReceipt("p", kPiece, 0));
    BOOST_CHECK_EQUAL(receipt.Effective("p", 0), 0);
}

BOOST_AUTO_TEST_CASE(recip_no_duplicate_piece_credit)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p1", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK(!ledger.Received("p2", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("p1", 0), kPiece);
    BOOST_CHECK_EQUAL(ledger.Effective("p2", 0), 0);
    BOOST_CHECK(ledger.Received("p2", "art", 0, 1, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("p2", 0), kPiece);
}

BOOST_AUTO_TEST_CASE(recip_seven_day_decay_28_day_horizon)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("p", 0), kPiece);
    BOOST_CHECK_EQUAL(ledger.Effective("p", 7 * modelnet::DAY_SECONDS), kPiece / 2);
    BOOST_CHECK_EQUAL(ledger.Effective("p", 14 * modelnet::DAY_SECONDS), kPiece / 4);
    BOOST_CHECK_EQUAL(ledger.Effective("p", 21 * modelnet::DAY_SECONDS), kPiece / 8);
    BOOST_CHECK_EQUAL(ledger.Effective("p", 28 * modelnet::DAY_SECONDS), 0);
}

BOOST_AUTO_TEST_CASE(recip_weight_bounded_1_to_4)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK_EQUAL(ledger.Weight("nobody", 0), 1);
    BOOST_CHECK(ledger.Received("p", "art", 0, 0, int64_t{100} << 30, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Weight("p", 0), 4);
    for (int piece = 0; piece < 8; ++piece) {
        modelnet::ReciprocityLedger stepped;
        BOOST_CHECK(stepped.Received("q", "art", 0, piece, (int64_t{1} << piece) * kPiece, 0, true, true, false, 3));
        const int w = stepped.Weight("q", 0);
        BOOST_CHECK(w >= 1);
        BOOST_CHECK(w <= 4);
    }
}

BOOST_AUTO_TEST_CASE(recip_rarity_multiplier_cap_2)
{
    modelnet::ReciprocityLedger rare;
    BOOST_CHECK(rare.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 1));
    BOOST_CHECK_EQUAL(rare.Effective("p", 0), 2 * kPiece);

    modelnet::ReciprocityLedger rare2;
    BOOST_CHECK(rare2.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 2));
    BOOST_CHECK_EQUAL(rare2.Effective("p", 0), 2 * kPiece);

    modelnet::ReciprocityLedger common;
    BOOST_CHECK(common.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 8));
    BOOST_CHECK_EQUAL(common.Effective("p", 0), kPiece);
    BOOST_CHECK(rare.Effective("p", 0) <= 2 * kPiece);
}

BOOST_AUTO_TEST_CASE(recip_lane_20_60_20_congestion)
{
    const auto lanes = modelnet::LaneSequence({{"bootstrap", 100}, {"reciprocal", 100}, {"preservation", 100}}, 100);
    BOOST_CHECK_EQUAL(lanes.size(), 100U);
    BOOST_CHECK_EQUAL(CountLane(lanes, "bootstrap"), 20);
    BOOST_CHECK_EQUAL(CountLane(lanes, "reciprocal"), 60);
    BOOST_CHECK_EQUAL(CountLane(lanes, "preservation"), 20);
}

BOOST_AUTO_TEST_CASE(recip_unused_lanes_lend)
{
    const auto only_boot = modelnet::LaneSequence({{"bootstrap", 50}, {"reciprocal", 0}, {"preservation", 0}}, 50);
    BOOST_CHECK_EQUAL(only_boot.size(), 50U);
    BOOST_CHECK_EQUAL(CountLane(only_boot, "bootstrap"), 50);
    const auto mixed = modelnet::LaneSequence({{"bootstrap", 5}, {"reciprocal", 5}, {"preservation", 0}}, 10);
    BOOST_CHECK_EQUAL(mixed.size(), 10U);
    BOOST_CHECK_EQUAL(CountLane(mixed, "preservation"), 0);
    BOOST_CHECK(CountLane(mixed, "bootstrap") + CountLane(mixed, "reciprocal") == 10);
}

BOOST_AUTO_TEST_CASE(recip_per_key_churn_within_aggregate)
{
    modelnet::BootstrapLimiter lim(modelnet::BootstrapLimiter::PER_KEY_DAY);
    BOOST_CHECK(lim.Allow("k1", "nat", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(!lim.Allow("k2", "nat", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(!lim.Allow("k1", "nat", 1));
    // Group-hour cap is 1 GiB; per-key/day is 256 MiB, so four keys fill the
    // campus netgroup without any one key exceeding PER_KEY_DAY.
    modelnet::BootstrapLimiter group(4 * modelnet::BootstrapLimiter::PER_KEY_DAY);
    BOOST_CHECK(group.Allow("a", "campus", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(group.Allow("b", "campus", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(group.Allow("c", "campus", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(group.Allow("d", "campus", modelnet::BootstrapLimiter::PER_KEY_DAY));
    BOOST_CHECK(!group.Allow("e", "campus", 1));
}

BOOST_AUTO_TEST_CASE(recip_nat_newcomer_ordinary_free)
{
    BOOST_CHECK(modelnet::ClassifyPeer(0, 0, 0, false, false, false) == modelnet::TrustLabel::NEW);
    BOOST_CHECK(modelnet::ClassifyPeer(0, 0, 0, false, false, false) != modelnet::TrustLabel::BLOCKED);
    const auto lanes = modelnet::LaneSequence({{"bootstrap", 4}, {"reciprocal", 0}, {"preservation", 0}}, 4);
    BOOST_CHECK_EQUAL(CountLane(lanes, "bootstrap"), 4);
    modelnet::BootstrapLimiter lim(modelnet::BootstrapLimiter::PER_KEY_DAY);
    BOOST_CHECK(lim.Allow("nat-newcomer", "shared-nat", 16 * static_cast<int64_t>(modelnet::MIB)));
}

BOOST_AUTO_TEST_CASE(recip_giveback_stops_no_fake_demand)
{
    modelnet::PreservationPolicy p;
    p.giveback_ratio = 1.0;
    p.retain_seconds = 7 * modelnet::DAY_SECONDS;
    BOOST_CHECK(!modelnet::GiveBackComplete(p, 50, 100, 0, 10));
    BOOST_CHECK(modelnet::GiveBackComplete(p, 100, 100, 0, 10));
    BOOST_CHECK(modelnet::GiveBackComplete(p, 10, 100, 0, 7 * modelnet::DAY_SECONDS));
    BOOST_CHECK(modelnet::LaneSequence({}, 100).empty());
    BOOST_CHECK(modelnet::LaneSequence({{"bootstrap", 0}, {"reciprocal", 0}, {"preservation", 0}}, 20).empty());
}

BOOST_AUTO_TEST_CASE(recip_score_never_touches_banman_addrman)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p", "art", 0, 0, kPiece, 0, true, true, false, 1));
    BOOST_CHECK(ledger.Weight("p", 0) >= 1);
    BOOST_CHECK(!ledger.TouchesBanMan());
    BOOST_CHECK(!ledger.TouchesAddrMan());
    BOOST_CHECK(!ledger.TOUCHES_BANMAN);
    BOOST_CHECK(!ledger.TOUCHES_ADDRMAN);
    BOOST_CHECK_EQUAL(ledger.AutomaticSpendAtoms(), 0);
    BOOST_CHECK(!ledger.ClonesCreditOnKeyRotation());
    modelnet::PreservationPolicy p;
    const UniValue json = modelnet::PolicyToJson(p);
    BOOST_CHECK_EQUAL(json["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(modelnet::ClassifyPeer(ledger.Effective("p", 0), 1, 0, false, true, false) == modelnet::TrustLabel::PREFERRED);
    BOOST_CHECK(!ledger.TouchesBanMan());
}

BOOST_AUTO_TEST_CASE(ident_store_without_wallet)
{
    modelnet::IdentityStore store;
    BOOST_CHECK(!store.RequiresWallet());
    BOOST_CHECK_EQUAL(store.AutomaticSpendAtoms(), 0);
    modelnet::ModelIdentity ident;
    ident.cls = modelnet::IdentityClass::RESEARCH_PUBLISHER;
    ident.pubkey.assign(modelnet::MLDSA44_PK, 0x11);
    ident.local_label = "lab";
    std::string err;
    BOOST_CHECK(store.Insert(ident, {}, err));
    BOOST_CHECK_EQUAL(store.Size(), 1U);
    BOOST_CHECK(!store.RequiresWallet());
}

BOOST_AUTO_TEST_CASE(ident_spending_address_not_research_id)
{
    modelnet::IdentityStore store;
    BOOST_CHECK(!store.AdoptSpendingAddress("btx1qexample-spending-address"));
    BOOST_CHECK_EQUAL(store.Size(), 0U);
    BOOST_CHECK(!modelnet::SpendingAddressIsResearchIdentity("btx1qexample-spending-address"));
    modelnet::ModelIdentity wallet;
    wallet.cls = modelnet::IdentityClass::MONETARY_WALLET;
    wallet.pubkey.assign(modelnet::MLDSA44_PK, 0x22);
    std::string err;
    BOOST_CHECK(!store.Insert(wallet, {}, err));
    BOOST_CHECK_EQUAL(store.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(ident_provider_id_byte_identical)
{
    std::vector<unsigned char> pk(modelnet::MLDSA44_PK, 0x12);
    const auto pid = modelnet::ProviderId(pk);
    BOOST_CHECK_EQUAL(pid.Hex(), "2eff6c5f5606ccf716be048b475bd3cd0ce9ccc6f2b6e624429a84b263bc1f2d002cdf2a24b789aaa2ad8a6199f53427");
    BOOST_CHECK(pid == modelnet::ProviderId(pk));
    const auto iid = modelnet::IdentityId(pk);
    BOOST_CHECK(pid != iid);
    BOOST_CHECK(iid != modelnet::PublisherId(pk));
}

BOOST_AUTO_TEST_CASE(ident_delegation_bound_to_service_key)
{
    std::vector<unsigned char> root_pk, root_sk, svc_pk, svc_sk, other_pk, other_sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(root_pk, root_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(svc_pk, svc_sk, err));
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(other_pk, other_sk, err));
    modelnet::ServiceDelegation d;
    d.root_id = modelnet::IdentityId(root_pk);
    d.delegate_pubkey = svc_pk;
    d.scopes = modelnet::DELEGATE_REQUEST | modelnet::DELEGATE_SERVE;
    d.all_models = true;
    d.issued_at = 1'700'000'000;
    d.expires_at = d.issued_at + 2 * modelnet::DAY_SECONDS;
    BOOST_CHECK(modelnet::DelegationNamesKey(d, svc_pk));
    BOOST_CHECK(!modelnet::DelegationNamesKey(d, other_pk));
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(root_sk, svc_pk, sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(root_pk, svc_pk, sig));
    BOOST_CHECK(!modelnet::VerifyMlDsa44(root_pk, other_pk, sig));
    modelnet::DelegationTable table;
    BOOST_CHECK(table.InsertRootSigned(d, d.issued_at + 10, err));
    BOOST_CHECK(table.HasScope(modelnet::ProviderId(svc_pk), modelnet::DELEGATE_SERVE, d.issued_at + 10));
    BOOST_CHECK(!table.HasScope(modelnet::ProviderId(other_pk), modelnet::DELEGATE_SERVE, d.issued_at + 10));
}

BOOST_AUTO_TEST_CASE(ident_delegation_depth_expiry_scopes)
{
    std::vector<unsigned char> pk(modelnet::MLDSA44_PK, 0x33);
    modelnet::ServiceDelegation d;
    d.root_id = DigestTag(1);
    d.delegate_pubkey = pk;
    d.scopes = modelnet::DELEGATE_REQUEST;
    d.all_models = true;
    d.issued_at = 100;
    d.expires_at = 100 + 8 * modelnet::DAY_SECONDS;
    std::string err;
    BOOST_CHECK(!modelnet::ValidDelegation(d, 100, err));
    d.expires_at = 100 + 2 * modelnet::DAY_SECONDS;
    BOOST_CHECK(modelnet::ValidDelegation(d, 100, err));
    BOOST_CHECK(!modelnet::ValidDelegation(d, d.expires_at, err));
    d.scopes = 64;
    BOOST_CHECK(!modelnet::ValidDelegation(d, 100, err));
    d.scopes = 0;
    d.expires_at = 100 + 2 * modelnet::DAY_SECONDS;
    BOOST_CHECK(!modelnet::ValidDelegation(d, 100, err));
    d.scopes = modelnet::DELEGATE_REQUEST;
    d.all_models = false;
    BOOST_CHECK(!modelnet::ValidDelegation(d, 100, err));
    modelnet::DelegationTable table;
    BOOST_CHECK(!table.InsertServiceIssued(d, 100, err));
    BOOST_CHECK(!modelnet::ServiceKeyMayIssueDelegation());
}

BOOST_AUTO_TEST_CASE(ident_service_key_cannot_spend_or_root)
{
    BOOST_CHECK(!modelnet::ServiceKeyMayAuthorizeWalletSpend());
    BOOST_CHECK(!modelnet::ServiceKeyMayPerformRootAction());
    std::vector<unsigned char> pk(modelnet::MLDSA44_PK, 0x44);
    modelnet::ServiceDelegation d;
    d.root_id = DigestTag(2);
    d.delegate_pubkey = pk;
    d.scopes = modelnet::DELEGATE_KNOWN_MASK;
    d.all_models = true;
    d.issued_at = 1;
    d.expires_at = 1 + modelnet::DAY_SECONDS;
    std::string err;
    modelnet::DelegationTable table;
    BOOST_REQUIRE(table.InsertRootSigned(d, 1, err));
    const auto sid = modelnet::ProviderId(pk);
    BOOST_CHECK(table.HasScope(sid, modelnet::DELEGATE_ENDPOINT, 2));
    BOOST_CHECK(!table.MayWalletSpend(sid));
    BOOST_CHECK(!table.MayPerformRootAction(sid));
}

BOOST_AUTO_TEST_CASE(ident_revocation_scoped)
{
    std::vector<unsigned char> a(modelnet::MLDSA44_PK, 0x51);
    std::vector<unsigned char> b(modelnet::MLDSA44_PK, 0x52);
    modelnet::ServiceDelegation da;
    da.root_id = DigestTag(9);
    da.delegate_pubkey = a;
    da.scopes = modelnet::DELEGATE_SERVE;
    da.all_models = true;
    da.issued_at = 10;
    da.expires_at = 10 + modelnet::DAY_SECONDS;
    modelnet::ServiceDelegation db = da;
    db.delegate_pubkey = b;
    std::string err;
    modelnet::DelegationTable table;
    BOOST_REQUIRE(table.InsertRootSigned(da, 10, err));
    BOOST_REQUIRE(table.InsertRootSigned(db, 10, err));
    const auto ida = modelnet::ProviderId(a);
    const auto idb = modelnet::ProviderId(b);
    BOOST_CHECK(table.RevokeByRoot(ida, da.root_id));
    BOOST_CHECK(!table.HasScope(ida, modelnet::DELEGATE_SERVE, 11));
    BOOST_CHECK(table.HasScope(idb, modelnet::DELEGATE_SERVE, 11));
    BOOST_CHECK(table.TombstoneRetained(ida));
    BOOST_CHECK(!table.TombstoneRetained(idb));
}

BOOST_AUTO_TEST_CASE(ident_rotation_does_not_clone_credit)
{
    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("old-key", "art", 0, 0, kPiece, 0, true, true, false, 3));
    BOOST_CHECK_EQUAL(ledger.Effective("old-key", 0), kPiece);
    BOOST_CHECK_EQUAL(ledger.Effective("new-key", 0), 0);
    BOOST_CHECK(!ledger.ClonesCreditOnKeyRotation());
    modelnet::IdentityStore store;
    BOOST_CHECK(!store.RotationCopiesReciprocity());
}

BOOST_AUTO_TEST_CASE(ident_backup_vs_public_export)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    modelnet::IdentityStore store;
    modelnet::ModelIdentity ident;
    ident.cls = modelnet::IdentityClass::RESEARCH_PUBLISHER;
    ident.pubkey = pk;
    ident.local_label = "contact";
    BOOST_REQUIRE(store.Insert(ident, sk, err));
    const auto pub = store.PublicExport();
    BOOST_REQUIRE_EQUAL(pub.size(), 1U);
    BOOST_CHECK_EQUAL(pub[0].local_label, "contact");
    BOOST_CHECK(pub[0].pubkey == pk);
    const auto bak = store.SecretBackup();
    BOOST_REQUIRE_EQUAL(bak.model_secrets.size(), 1U);
    BOOST_CHECK(bak.model_secrets[0] == sk);
    BOOST_CHECK(!bak.contains_wallet_material);
    BOOST_CHECK(!bak.contains_tls_secrets);
    BOOST_CHECK(!bak.contains_release_secrets);
    BOOST_CHECK(!bak.contains_payment_credentials);
}

BOOST_AUTO_TEST_CASE(ident_no_arbitrary_digest_wallet_sign)
{
    BOOST_CHECK(!modelnet::AllowModelSign(modelnet::SignKind::ARBITRARY_DIGEST, modelnet::IdentityClass::RESEARCH_PUBLISHER));
    BOOST_CHECK(!modelnet::AllowModelSign(modelnet::SignKind::ARBITRARY_DIGEST, modelnet::IdentityClass::SERVICE_PROVIDER));
    BOOST_CHECK(!modelnet::AllowModelSign(modelnet::SignKind::ARBITRARY_DIGEST, modelnet::IdentityClass::MONETARY_WALLET));
    BOOST_CHECK(!modelnet::AllowModelSign(modelnet::SignKind::TYPED_MODEL_RECORD, modelnet::IdentityClass::MONETARY_WALLET));
    BOOST_CHECK(modelnet::AllowModelSign(modelnet::SignKind::TYPED_MODEL_RECORD, modelnet::IdentityClass::RESEARCH_PUBLISHER));
    BOOST_CHECK(modelnet::AllowModelSign(modelnet::SignKind::TYPED_MODEL_RECORD, modelnet::IdentityClass::SERVICE_PROVIDER));
}

BOOST_AUTO_TEST_CASE(acl_invalid_crypto_rejected_despite_allow)
{
    BOOST_CHECK(modelnet::DecideAcl(false, true, false, false, true, false, false, false) == modelnet::AclDecision::REJECT_CRYPTO);
    BOOST_CHECK(modelnet::DecideAcl(false, false, true, true, true, true, true, true) == modelnet::AclDecision::REJECT_CRYPTO);
}

BOOST_AUTO_TEST_CASE(acl_hard_ceiling_despite_preferred)
{
    BOOST_CHECK(modelnet::DecideAcl(true, false, false, false, true, false, false, false) == modelnet::AclDecision::RETRY_RESOURCE);
}

BOOST_AUTO_TEST_CASE(acl_local_deny_wins)
{
    BOOST_CHECK(modelnet::DecideAcl(true, true, true, false, true, false, false, false) == modelnet::AclDecision::DENY_LOCAL);
    modelnet::ModelAcl acl;
    acl.allow_prefer.insert("peer");
    acl.deny_service_id.insert("peer");
    BOOST_CHECK(acl.Denied(modelnet::PolicyDim::RETRIEVE, "peer"));
}

BOOST_AUTO_TEST_CASE(acl_quarantine_not_cleared_by_trust_bundle)
{
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, true, true, false, false, false) == modelnet::AclDecision::QUARANTINE);
    modelnet::ModelAcl acl;
    acl.ObserveProtocolFault("src");
    BOOST_CHECK(acl.Quarantined("src"));
    BOOST_CHECK(!acl.ClearQuarantineFromTrustBundle("src"));
    BOOST_CHECK(acl.Quarantined("src"));
    BOOST_CHECK(acl.OperatorClearQuarantine("src"));
    BOOST_CHECK(!acl.Quarantined("src"));
}

BOOST_AUTO_TEST_CASE(acl_exact_exception_explained)
{
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, true, true, false, false) == modelnet::AclDecision::ALLOW);
    const auto expl = modelnet::ExplainExactException("rule-7", "local", "RETRIEVE", 1'800'000'000);
    BOOST_CHECK(expl.decision == modelnet::AclDecision::ALLOW);
    BOOST_CHECK_EQUAL(expl.rule_id, "rule-7");
    BOOST_CHECK_EQUAL(expl.source, "local");
    BOOST_CHECK_EQUAL(expl.operation, "RETRIEVE");
    BOOST_CHECK_EQUAL(expl.expiry, 1'800'000'000);
}

BOOST_AUTO_TEST_CASE(acl_subscribed_warning_not_deny)
{
    BOOST_CHECK(!modelnet::SubscribedWarningIsAutomaticDeny());
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, false, false, false) == modelnet::AclDecision::ALLOW);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, true, false, false) == modelnet::AclDecision::DENY_SUBSCRIBED);
}

BOOST_AUTO_TEST_CASE(acl_no_monetary_noban_or_addr)
{
    modelnet::ModelAcl acl;
    acl.allow_prefer.insert("researcher");
    acl.trust_metadata = true;
    BOOST_CHECK(!acl.AffectsMonetaryBan());
    BOOST_CHECK(!acl.AffectsAddrMan());
    BOOST_CHECK(!acl.WritesBanMan());
    BOOST_CHECK_EQUAL(acl.AutomaticSpendAtoms(), 0);
    acl.auto_pay = true;
    BOOST_CHECK_EQUAL(acl.AutomaticSpendAtoms(), 0);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, true, false, true, false) == modelnet::AclDecision::REQUIRE_SPEND_APPROVAL);
}

BOOST_AUTO_TEST_CASE(acl_complaint_never_writes_banman)
{
    modelnet::ModelAcl acl;
    acl.RecordComplaint("noisy-peer");
    BOOST_CHECK(acl.Denied(modelnet::PolicyDim::CONNECT, "noisy-peer"));
    BOOST_CHECK(!acl.WritesBanMan());
    BOOST_CHECK(!acl.AffectsMonetaryBan());
}

BOOST_AUTO_TEST_CASE(acl_corrupt_piece_source_not_relay)
{
    BOOST_CHECK_EQUAL(modelnet::ResponsibleSource("authenticated", "relay"), "authenticated");
    BOOST_CHECK(modelnet::ResponsibleSource("authenticated", "relay") != "relay");
}

BOOST_AUTO_TEST_CASE(acl_age_balance_not_trust)
{
    BOOST_CHECK(!modelnet::IdentityAgeCreatesTrust(10 * modelnet::DAY_SECONDS * 365));
    BOOST_CHECK(!modelnet::BalanceCreatesTrust(1'000'000'000));
    BOOST_CHECK(modelnet::ClassifyPeer(0, 0, 0, false, false, false) == modelnet::TrustLabel::NEW);
    BOOST_CHECK(modelnet::ClassifyPeer(0, 0, 0, false, false, false) != modelnet::TrustLabel::TRUSTED);
}

BOOST_AUTO_TEST_CASE(acl_expiry_vs_revocation_tombstone)
{
    modelnet::ModelAcl acl;
    BOOST_CHECK(!acl.RecommendationStillOperative(100, 200));
    BOOST_CHECK(acl.RecommendationStillOperative(300, 200));
    acl.AcceptRevocationTombstone("deleg-1");
    BOOST_CHECK(acl.TombstoneRetained("deleg-1"));
    BOOST_CHECK(!acl.RecommendationStillOperative(0, 1));
    BOOST_CHECK(acl.TombstoneRetained("deleg-1"));
}

BOOST_AUTO_TEST_CASE(acl_public_error_hides_private)
{
    const std::string priv = "secret-contact-alice";
    const std::string pub = modelnet::PublicAclError(modelnet::AclDecision::DENY_LOCAL, priv);
    BOOST_CHECK(pub.find(priv) == std::string::npos);
    BOOST_CHECK_EQUAL(pub, "DENY_LOCAL");
}

BOOST_AUTO_TEST_CASE(comm_collection_sorted_unique_512)
{
    std::vector<modelnet::CollectionEntry> ok{{DigestTag(1), 1, 7}, {DigestTag(2), 2, 30}};
    std::string err;
    BOOST_CHECK(modelnet::ValidateCollectionEntries(ok, err));
    std::vector<modelnet::CollectionEntry> unsorted{{DigestTag(2), 1, 1}, {DigestTag(1), 1, 1}};
    BOOST_CHECK(!modelnet::ValidateCollectionEntries(unsorted, err));
    std::vector<modelnet::CollectionEntry> dup{{DigestTag(1), 1, 1}, {DigestTag(1), 2, 1}};
    BOOST_CHECK(!modelnet::ValidateCollectionEntries(dup, err));
    BOOST_CHECK(modelnet::CanonicalizeCollectionEntries(unsorted, err));
    BOOST_CHECK_EQUAL(unsorted.size(), 2U);
    std::vector<modelnet::CollectionEntry> too_many;
    too_many.reserve(513);
    for (int i = 0; i < 513; ++i) {
        too_many.push_back({DigestTag(static_cast<unsigned char>(i & 0xff), static_cast<unsigned char>(i >> 8)), 1, 1});
    }
    BOOST_CHECK(!modelnet::ValidateCollectionEntries(too_many, err));
    std::vector<modelnet::CollectionEntry> empty;
    BOOST_CHECK(!modelnet::ValidateCollectionEntries(empty, err));
}

BOOST_AUTO_TEST_CASE(comm_collection_cannot_qualify_or_load_code)
{
    std::vector<modelnet::CollectionEntry> col{{DigestTag(9), 1, 1}};
    BOOST_CHECK(!modelnet::CollectionGrantsQualification(col, "model.pkl"));
    BOOST_CHECK(!modelnet::CollectionLoadsCode());
    modelnet::QualReport report;
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    BOOST_CHECK(modelnet::QualifyBytes("model.pkl", Span<const unsigned char>{pickle, sizeof(pickle)}, report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    BOOST_CHECK(!modelnet::CollectionGrantsQualification(col, "model.pkl"));
}

BOOST_AUTO_TEST_CASE(comm_alias_key_from_root_and_slug)
{
    std::string err;
    const auto root = DigestTag(7);
    const auto k1 = modelnet::AliasKey(root, "models", err);
    const auto k2 = modelnet::AliasKey(root, "models", err);
    BOOST_CHECK(k1 == k2);
    BOOST_CHECK(!k1.IsNull());
    const auto k3 = modelnet::AliasKey(root, "other", err);
    BOOST_CHECK(k1 != k3);
    const auto k4 = modelnet::AliasKey(DigestTag(8), "models", err);
    BOOST_CHECK(k1 != k4);
    BOOST_CHECK(modelnet::AliasKey(root, "../pay", err).IsNull());
}

BOOST_AUTO_TEST_CASE(comm_alias_sequence_conflict_freeze)
{
    modelnet::AliasIndex idx;
    std::string err;
    const auto key = DigestTag(3);
    const auto t1 = DigestTag(10);
    const auto t2 = DigestTag(11);
    BOOST_CHECK(idx.Apply(key, 1, DigestTag(20), modelnet::ResourceKind::MODEL, t1, err) == modelnet::AliasApply::ACCEPTED);
    BOOST_CHECK(idx.HoldsPrior(key, t1));
    BOOST_CHECK(idx.Apply(key, 1, DigestTag(21), modelnet::ResourceKind::MODEL, t2, err) == modelnet::AliasApply::FROZEN_EQUIVOCATION);
    BOOST_CHECK(idx.Frozen(key));
    BOOST_CHECK(idx.HoldsPrior(key, t1));
    BOOST_CHECK(!idx.HoldsPrior(key, t2));
    BOOST_CHECK(idx.Apply(key, 2, DigestTag(22), modelnet::ResourceKind::MODEL, t2, err) == modelnet::AliasApply::FROZEN_EQUIVOCATION);
    BOOST_CHECK(idx.HoldsPrior(key, t1));
}

BOOST_AUTO_TEST_CASE(comm_alias_never_chains)
{
    modelnet::AliasIndex idx;
    std::string err;
    const auto key = DigestTag(4);
    const auto model = DigestTag(12);
    BOOST_CHECK(idx.Apply(key, 1, DigestTag(30), modelnet::ResourceKind::MODEL, model, err) == modelnet::AliasApply::ACCEPTED);
    BOOST_CHECK(idx.Apply(key, 2, DigestTag(31), modelnet::ResourceKind::ALIAS, DigestTag(13), err) == modelnet::AliasApply::REJECTED_CHAIN);
    BOOST_CHECK(idx.HoldsPrior(key, model));
}

BOOST_AUTO_TEST_SUITE_END()
