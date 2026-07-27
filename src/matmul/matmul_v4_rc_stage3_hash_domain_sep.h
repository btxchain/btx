// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_DOMAIN_SEP_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_DOMAIN_SEP_H

// SHA256d hash-model domain separation (V8 wrapper construction).
//
// Realizes doc/btx-matmul-v4.6-stage3-sha256d-hash-model-split-2026-07-25.md
// section 2 (O-ENC). Every consensus SHA256d call is routed through exactly one
// of two role wrappers so that the ROM-modeled Fiat-Shamir domain D_FS and the
// concrete-CRHF binding domain D_BIND are SYNTACTICALLY disjoint by first byte.
// The T-ALIGN lemma (section 3) depends on this disjointness for model
// coherence.
//
// Status banner (must survive downstream): CONSTRUCTION. Pre-activation only.
// Consensus authority remains ExactReplay; this module promotes ZERO security
// bits and gates no consensus decision. O-EXACT (952-row SHA AIR functional
// exactness) and A-FS-INST remain OPEN.

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3::domain_sep {

// ---------------------------------------------------------------------------
// Role bytes (section 2.2, normative).
// ---------------------------------------------------------------------------

// D_FS: every Fiat-Shamir absorb / challenge draw is prefixed with 0xF5.
inline constexpr uint8_t kRoleFs = 0xF5;

// D_BIND (ASCII-tagged commitments): every ASCII "BTX_..."-tagged *binding*
// commitment is re-issued with a 0xB1 role byte prepended; the tag itself is
// unchanged so the registry diff is mechanical.
inline constexpr uint8_t kRoleBindAscii = 0xB1;

// D_BIND (tile tree): unchanged shipped bytes.
inline constexpr uint8_t kTileLeafTag = 0x00;
inline constexpr uint8_t kTileNodeTag = 0x01;
inline constexpr uint8_t kTilePadLeafTag = 0x02;

// D_BIND (receipt tree): new fixed-length tags.
inline constexpr uint8_t kReceiptLeafTag = 0x03;
inline constexpr uint8_t kReceiptInternalTag = 0x04;

// The receipt-internal fixed encoding per the doc's enumerated field layout:
//   0x04 ‖ u8 level ‖ le64 node_id ‖ u8 arity ‖ u8 live_mask ‖ d_child[0..3]
// = 1 + 1 + 8 + 1 + 1 + 4*32 = 140 bytes. NOTE: the doc labels this "143
// bytes" in prose, which is an arithmetic slip over its OWN enumerated fields
// (the fields sum to 140). We implement the explicit, unambiguous field layout.
// The separation argument is unaffected: 140 (like 143) misses the 182-byte
// header length, which is the only property section 2.2's SHOULD relies on.
inline constexpr size_t kReceiptInternalEncodingLen =
    1 + 1 + 8 + 1 + 1 + 4 * 32;
static_assert(kReceiptInternalEncodingLen == 140,
              "receipt-internal encoding must be the fixed field layout");
static_assert(kReceiptInternalEncodingLen != 182,
              "receipt-internal encoding must not alias the 182-byte header");

// H_HDR: the legacy 182-byte double-SHA block header is untagged (wire
// compatibility). SHOULD: tagged wrappers reject total preimage length 182 so
// no tagged preimage can alias a header. (All fixed BIND encodings already miss
// 182: node 65, pad 11, receipt-internal 143; only the variable tile leaf could
// hit it, hence the guard.)
inline constexpr size_t kLegacyHeaderLen = 182;

// ---------------------------------------------------------------------------
// First-byte partition (section 2.2, the load-bearing MUST).
// ---------------------------------------------------------------------------
//   D_BIND : first byte in {0x00 .. 0x3F} ∪ {0xB1}
//   D_FS   : first byte == 0xF5
constexpr bool InBindFirstByteClass(uint8_t b)
{
    return b <= 0x3F || b == kRoleBindAscii;
}
constexpr bool InFsFirstByteClass(uint8_t b)
{
    return b == kRoleFs;
}

// The disjointness the doc demands, checked at compile time.
static_assert(InFsFirstByteClass(kRoleFs), "FS role byte must be in D_FS class");
static_assert(!InBindFirstByteClass(kRoleFs),
              "FS role byte must NOT land in the D_BIND class");
static_assert(InBindFirstByteClass(kRoleBindAscii),
              "0xB1 ASCII-bind role byte must be in D_BIND class");
static_assert(!InFsFirstByteClass(kRoleBindAscii),
              "0xB1 ASCII-bind role byte must NOT land in the D_FS class");
static_assert(InBindFirstByteClass(kTileLeafTag) &&
                  InBindFirstByteClass(kTileNodeTag) &&
                  InBindFirstByteClass(kTilePadLeafTag) &&
                  InBindFirstByteClass(kReceiptLeafTag) &&
                  InBindFirstByteClass(kReceiptInternalTag),
              "all binary BIND tags must be in the D_BIND class");

enum class RoleClass : uint8_t { kFs = 1, kBind = 2, kHeader = 3, kInvalid = 4 };

constexpr RoleClass ClassifyFirstByte(uint8_t b)
{
    if (InFsFirstByteClass(b)) return RoleClass::kFs;
    if (InBindFirstByteClass(b)) return RoleClass::kBind;
    return RoleClass::kInvalid; // untagged header bytes are handled separately
}

// ---------------------------------------------------------------------------
// Wrappers (section 2.2). Both compute SHA256d over their role-prefixed input.
// ---------------------------------------------------------------------------
//   Sha256dFs(ascii_tag, enc)        := SHA256d( 0xF5 ‖ ascii_tag ‖ enc )
//   Sha256dBindAscii(ascii_tag, enc) := SHA256d( 0xB1 ‖ ascii_tag ‖ enc )
//   Sha256dBindRole(role, enc)       := SHA256d( role ‖ enc )  (role binary,BIND)
[[nodiscard]] uint256 Sha256dFs(const char* ascii_tag,
                                const std::vector<uint8_t>& enc);
[[nodiscard]] uint256 Sha256dBindAscii(const char* ascii_tag,
                                       const std::vector<uint8_t>& enc);
[[nodiscard]] uint256 Sha256dBindRole(uint8_t role,
                                      const std::vector<uint8_t>& enc);

// Build the 143-byte receipt-internal preimage. live_mask bit c set => slot c
// carries d_child[c]; a vacuous slot MUST carry the pad constant, never a
// copied live digest (O-VAC; enforced by the caller, documented here).
[[nodiscard]] std::vector<uint8_t> EncodeReceiptInternal(
    uint8_t level, uint64_t node_id, uint8_t arity, uint8_t live_mask,
    const uint256 d_child[4]);

// ---------------------------------------------------------------------------
// O-ENC production routing: activation-gated transcript selector.
//
// The real consensus SHA256d chokepoints (CommitShaManifest in hash_air.cpp,
// DeriveFSChallenges in matmul_v4_rc.cpp, ... ) call the dispatchers below with
// the model resolved from ActiveHashModel(). The transcript is TRANSCRIPT-
// BREAKING at the V8 boundary (a role byte is prepended to the preimage), so it
// is gated: a proof BUILD/VERIFY session enters kV8 only when the domain-sep
// fork is active for that height. The default is kLegacyV7 and is byte-for-byte
// the shipped transcript, so no un-scoped path (all of mainnet today, every
// existing test) changes. Production never enters the kV8 scope: the only entry
// point sits inside the kRCStage3SuccinctAuthorityReady if-constexpr, which is
// compiled out while that flag is false. Pre-activation only.
//
// ---------------------------------------------------------------------------
// PR-89 re-refutation (lemma-4, residual B.1): WHY V8 stays activation-gated and
// is NOT flipped to the compile-time default.
//
// The re-refutation observed that the DEFAULT (kLegacyV7) transcript still hashes
// the un-role-byted "BTX_RC_FS_V1" FS preimage (DeriveFSChallenges,
// matmul_v4_rc.cpp:756-779; first byte 0x42 'B'). Under legacy, an ASCII binding
// commitment preimage ALSO begins with 'B' (0x42), so a D_FS draw and a D_BIND
// commitment collide on their first byte and are NOT role-separated (0x42 is in
// neither role class; no role byte is applied) — the exact overlap this module
// fixes under kV8 (0xF5 for D_FS, 0xB1 for ASCII D_BIND). Making kV8 the
// unconditional default WOULD close that overlap, but it is REJECTED as a
// compile-time flip for consensus-level (not stylistic) reasons:
//
//  (B1a) TRANSCRIPT-BREAKING HARD FORK. kV8 prepends a role byte to every FS
//        absorb/draw and every ASCII binding commitment, changing DeriveFS-
//        Challenges' sampled indices and every commitment digest. Two nodes on
//        different models compute different digests for the same block => chain
//        split. A change of this class is only deployable as a HEIGHT-GATED
//        activation, never a silent default.
//  (B1b) ZERO REALIZED BENEFIT PRE-ACTIVATION. First-byte disjointness is a
//        NECESSARY hygiene property for T-ALIGN model coherence (lemma 4), but it
//        promotes 0 security bits while O-EXACT (SHA-AIR functional exactness) and
//        A-FS-INST remain OPEN. A default flip would pay the full fork cost for no
//        banked soundness.
//  (B1c) GOLDEN VECTORS ARE PINNED EITHER WAY. The V8 wrapper bytes are pinned by
//        oenc_transcript_golden_vectors (both models), so the future fork's bytes
//        cannot drift; keeping the default kLegacyV7 keeps every deployed node and
//        existing golden byte-for-byte.
//
// DECISION: V8 remains ACTIVATION-GATED. The deployment vehicle is a height-gated
// fork that sets ActiveHashModel()==kV8 at/after the activation height (via
// RCStage3HashModelScope on the proof build/verify session), NOT a change to this
// default. Recorded so a later pass does not re-open it as a default flip.
// ---------------------------------------------------------------------------
inline constexpr bool kV8IsActivationGatedNotDefault = true;
static_assert(kV8IsActivationGatedNotDefault,
              "V8 domain-sep is a height-gated transcript fork, never the "
              "compile-time default (PR-89 residual B.1 rationale above)");

enum class RCStage3HashModel : uint8_t {
    kLegacyV7 = 0, // shipped bytes: SHA256d(tag ‖ payload) / SHA256d(preimage)
    kV8 = 1,       // role-prefixed: 0xB1 ‖ tag ‖ payload  /  0xF5 ‖ preimage
};

// ASCII-tagged BINDING commitment (D_BIND, 0xB1). Legacy reproduces the exact
// Sha256dTagged bytes; V8 prepends kRoleBindAscii. Used by CommitShaManifest et al.
[[nodiscard]] uint256 Sha256dAsciiCommitment(RCStage3HashModel model,
                                             const char* ascii_tag,
                                             const std::vector<uint8_t>& payload);

// Fiat-Shamir absorb/draw (D_FS, 0xF5). `legacy_preimage` is the FULL shipped
// preimage (its own ASCII tag ‖ body). Legacy hashes it unchanged; V8 prepends
// kRoleFs. Used by DeriveFSChallenges et al.
[[nodiscard]] uint256 Sha256dFsPreimage(RCStage3HashModel model,
                                        const uint8_t* legacy_preimage,
                                        size_t len);

// The transcript model active on THIS thread (default kLegacyV7).
[[nodiscard]] RCStage3HashModel ActiveHashModel();

// RAII scope selecting the active model for a proof build/verify session.
// Nestable; restores the prior model on destruction.
class RCStage3HashModelScope {
public:
    explicit RCStage3HashModelScope(RCStage3HashModel model);
    ~RCStage3HashModelScope();
    RCStage3HashModelScope(const RCStage3HashModelScope&) = delete;
    RCStage3HashModelScope& operator=(const RCStage3HashModelScope&) = delete;

private:
    RCStage3HashModel prev_;
};

// ---------------------------------------------------------------------------
// Cross-domain confusion guard (section 2.2). Rejects a preimage whose first
// byte belongs to the wrong role class, and rejects tagged length-182 aliases.
// ---------------------------------------------------------------------------
[[nodiscard]] bool AcceptBindingPreimage(const std::vector<uint8_t>& enc,
                                         std::string* why);
[[nodiscard]] bool AcceptFsPreimage(const std::vector<uint8_t>& enc,
                                    std::string* why);

// ---------------------------------------------------------------------------
// Compile-time SHA-call-site registry (section 2.2 / obligation O-ENC).
// One entry per consensus SHA256d call site with its role class and the first
// byte of its tagged preimage. This is the audit artifact.
// ---------------------------------------------------------------------------
struct CallSite {
    const char* name;
    RoleClass role;
    uint8_t first_byte;
    const char* tag; // ASCII tag or "" for binary/header
};

// V8 (post-fork) registry: role bytes applied. First-byte classes disjoint.
inline constexpr CallSite kRegistryV8[] = {
    // ---- D_FS (0xF5) -----------------------------------------------------
    {"RCGkrFsSeedV7", RoleClass::kFs, kRoleFs, "BTX_RC_GKR_WINNER_V7"},
    {"RCGkrFsSeedV7Coupled", RoleClass::kFs, kRoleFs, "BTX_RC_GKR_WINNER_V7"},
    {"RCFsQueryDraw", RoleClass::kFs, kRoleFs, "BTX_RC_FS_V1"},
    {"RCFriDomain", RoleClass::kFs, kRoleFs, "BTX_RC_FRI_V5"},
    {"RCFriBatchDomain", RoleClass::kFs, kRoleFs, "BTX_RC_FRIB3ALG_V1"},
    {"RCStage3RecursiveRoleSeed", RoleClass::kFs, kRoleFs, "BTX_RC_STAGE3_ROLE"},
    {"RCStage3ChildFsPoint", RoleClass::kFs, kRoleFs, "BTX_RC_STAGE3_CHILD"},
    // ---- D_BIND (binary tags 0x00..0x04) ---------------------------------
    {"TileLeaf", RoleClass::kBind, kTileLeafTag, ""},
    {"TileNode", RoleClass::kBind, kTileNodeTag, ""},
    {"TilePadLeaf", RoleClass::kBind, kTilePadLeafTag, ""},
    {"ReceiptLeaf", RoleClass::kBind, kReceiptLeafTag, ""},
    {"ReceiptInternal", RoleClass::kBind, kReceiptInternalTag, ""},
    // ---- D_BIND (ASCII commitments, now 0xB1-prefixed) -------------------
    {"CommitShaManifest", RoleClass::kBind, kRoleBindAscii,
     "BTX_RC_STAGE3_SHA_MANIFEST_V1"},
    {"CommitDirectSha256dManifest", RoleClass::kBind, kRoleBindAscii,
     "BTX_RC_STAGE3_DIRECT_SHA256D_V1"},
    {"CommitCoupledSubroot", RoleClass::kBind, kRoleBindAscii, "BTX_RC_COUP_SUBROOT"},
    {"AggregationSeed", RoleClass::kBind, kRoleBindAscii, "BTX_RC_AGGREGATION_DOMAIN"},
};
inline constexpr size_t kRegistryV8Size =
    sizeof(kRegistryV8) / sizeof(kRegistryV8[0]);

// Legacy (pre-fork, SHIPPED) registry demonstrating the exact defect the doc
// found: ASCII-tagged FS draws and ASCII-tagged binding commitments BOTH begin
// with the ASCII byte class (0x42 'B' from "BTX_"), so D_FS and D_BIND overlap.
inline constexpr uint8_t kAsciiB = 0x42; // 'B'
inline constexpr CallSite kRegistryLegacyDefect[] = {
    {"RCFsQueryDraw", RoleClass::kFs, kAsciiB, "BTX_RC_FS_V1"},
    {"RCGkrFsSeedV7", RoleClass::kFs, kAsciiB, "BTX_RC_GKR_WINNER_V7"},
    {"CommitShaManifest", RoleClass::kBind, kAsciiB, "BTX_RC_STAGE3_SHA_MANIFEST_V1"},
    {"AggregationSeed", RoleClass::kBind, kAsciiB, "BTX_RC_AGGREGATION_DOMAIN"},
};
inline constexpr size_t kRegistryLegacyDefectSize =
    sizeof(kRegistryLegacyDefect) / sizeof(kRegistryLegacyDefect[0]);

// True iff no FS-class site and no BIND-class site share a first-byte class,
// AND every site's declared first byte actually lands in its role's class.
constexpr bool RegistryFirstByteClassesDisjoint(const CallSite* sites, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (sites[i].role == RoleClass::kFs &&
            !InFsFirstByteClass(sites[i].first_byte)) {
            return false;
        }
        if (sites[i].role == RoleClass::kBind &&
            !InBindFirstByteClass(sites[i].first_byte)) {
            return false;
        }
    }
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (sites[i].role != sites[j].role &&
                sites[i].first_byte == sites[j].first_byte) {
                return false; // an FS tag and a binding tag share a first byte
            }
        }
    }
    return true;
}

// The V8 registry MUST be role-clean; the legacy registry MUST NOT be (it is
// the defect being fixed). Both facts are compile-time enforced.
static_assert(RegistryFirstByteClassesDisjoint(kRegistryV8, kRegistryV8Size),
              "V8 registry: FS and BIND first-byte classes must be disjoint");
static_assert(!RegistryFirstByteClassesDisjoint(kRegistryLegacyDefect,
                                                kRegistryLegacyDefectSize),
              "legacy registry must reproduce the doc's overlap defect");

// ---------------------------------------------------------------------------
// Audit surface. Flips ONLY domain-separation flags a passing test earns.
// ---------------------------------------------------------------------------
struct HashDomainSeparationAudit {
    uint16_t version{8};
    uint64_t registry_sites{kRegistryV8Size};

    // Earned by the wrapper construction + registry + tests below.
    bool role_bytes_assigned{false};
    bool fs_and_bind_first_byte_classes_disjoint{false};
    bool registry_enumerates_call_sites{false};
    bool cross_domain_confusion_rejected{false};
    bool length_182_guard_present{false};
    bool legacy_defect_reproduced{false};

    // Deliberately NOT promoted here (open obligations, gated elsewhere):
    //  - all_binding_nodes_use_injective_encoding (O-ENC full certificate)
    //  - A-EXACT (O-EXACT, 952-row SHA AIR), A-FS-INST (named residual).
    bool pre_activation_only{true};
    uint32_t promoted_security_bits{0};
    std::string note;
};

[[nodiscard]] HashDomainSeparationAudit AssessHashDomainSeparation();

// Consensus authority is NOT changed by this module. Keep composition/global
// authority disabled; O-EXACT and A-FS-INST remain open.
inline constexpr bool kDomainSepPromotesConsensusAuthority = false;
static_assert(!kDomainSepPromotesConsensusAuthority,
              "domain separation is pre-activation; it promotes no consensus "
              "authority (O-EXACT / A-FS-INST still open)");

} // namespace matmul::v4::rc::stage3::domain_sep

#endif
