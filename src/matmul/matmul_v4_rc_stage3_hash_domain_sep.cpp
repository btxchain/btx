// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_domain_sep.h>

#include <crypto/common.h>
#include <crypto/sha256.h>

#include <cstring>

namespace matmul::v4::rc::stage3::domain_sep {

namespace {

// SHA256d over a raw byte span. Sha256dBytes in matmul_v4_rc.cpp is
// file-local, so we recompute the double pass directly here (identical bytes).
uint256 Sha256d(const uint8_t* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

uint256 Sha256dRolePrefixed(uint8_t role, const char* ascii_tag,
                            const std::vector<uint8_t>& enc)
{
    std::vector<uint8_t> pre;
    pre.reserve(1 + (ascii_tag ? std::strlen(ascii_tag) : 0) + enc.size());
    pre.push_back(role);
    if (ascii_tag != nullptr) {
        const size_t taglen = std::strlen(ascii_tag);
        pre.insert(pre.end(),
                   reinterpret_cast<const uint8_t*>(ascii_tag),
                   reinterpret_cast<const uint8_t*>(ascii_tag) + taglen);
    }
    pre.insert(pre.end(), enc.begin(), enc.end());
    return Sha256d(pre.data(), pre.size());
}

} // namespace

uint256 Sha256dFs(const char* ascii_tag, const std::vector<uint8_t>& enc)
{
    return Sha256dRolePrefixed(kRoleFs, ascii_tag, enc);
}

uint256 Sha256dBindAscii(const char* ascii_tag, const std::vector<uint8_t>& enc)
{
    return Sha256dRolePrefixed(kRoleBindAscii, ascii_tag, enc);
}

uint256 Sha256dBindRole(uint8_t role, const std::vector<uint8_t>& enc)
{
    // Binary BIND role bytes only (0x00..0x3F). Refuse the FS role and the
    // ASCII-bind role (which must carry a tag through Sha256dBindAscii).
    if (!InBindFirstByteClass(role) || role == kRoleBindAscii) {
        return uint256{}; // fail closed: caller supplied a non-binary BIND role
    }
    return Sha256dRolePrefixed(role, nullptr, enc);
}

std::vector<uint8_t> EncodeReceiptInternal(uint8_t level, uint64_t node_id,
                                           uint8_t arity, uint8_t live_mask,
                                           const uint256 d_child[4])
{
    std::vector<uint8_t> enc;
    enc.reserve(kReceiptInternalEncodingLen);
    enc.push_back(kReceiptInternalTag);
    enc.push_back(level);
    for (int i = 0; i < 8; ++i) {
        enc.push_back(static_cast<uint8_t>((node_id >> (8 * i)) & 0xFF));
    }
    enc.push_back(arity);
    enc.push_back(live_mask);
    for (int c = 0; c < 4; ++c) {
        enc.insert(enc.end(), d_child[c].begin(), d_child[c].end());
    }
    return enc;
}

uint256 Sha256dAsciiCommitment(RCStage3HashModel model, const char* ascii_tag,
                               const std::vector<uint8_t>& payload)
{
    // kLegacyV7: SHA256d(tag ‖ payload) — byte-identical to hash_air's
    // Sha256dTagged. kV8: SHA256d(0xB1 ‖ tag ‖ payload) — the D_BIND wrapper.
    const size_t taglen = ascii_tag != nullptr ? std::strlen(ascii_tag) : 0;
    std::vector<uint8_t> pre;
    pre.reserve((model == RCStage3HashModel::kV8 ? 1 : 0) + taglen +
                payload.size());
    if (model == RCStage3HashModel::kV8) pre.push_back(kRoleBindAscii);
    if (ascii_tag != nullptr) {
        pre.insert(pre.end(), reinterpret_cast<const uint8_t*>(ascii_tag),
                   reinterpret_cast<const uint8_t*>(ascii_tag) + taglen);
    }
    pre.insert(pre.end(), payload.begin(), payload.end());
    return Sha256d(pre.data(), pre.size());
}

uint256 Sha256dFsPreimage(RCStage3HashModel model, const uint8_t* legacy_preimage,
                          size_t len)
{
    // kLegacyV7: SHA256d(preimage) unchanged. kV8: SHA256d(0xF5 ‖ preimage).
    if (model == RCStage3HashModel::kLegacyV7) {
        return Sha256d(legacy_preimage, len);
    }
    std::vector<uint8_t> pre;
    pre.reserve(1 + len);
    pre.push_back(kRoleFs);
    pre.insert(pre.end(), legacy_preimage, legacy_preimage + len);
    return Sha256d(pre.data(), pre.size());
}

namespace {
// Default is the shipped transcript: no un-scoped consensus path changes.
thread_local RCStage3HashModel g_active_hash_model = RCStage3HashModel::kLegacyV7;
} // namespace

RCStage3HashModel ActiveHashModel() { return g_active_hash_model; }

RCStage3HashModelScope::RCStage3HashModelScope(RCStage3HashModel model)
    : prev_(g_active_hash_model)
{
    g_active_hash_model = model;
}

RCStage3HashModelScope::~RCStage3HashModelScope()
{
    g_active_hash_model = prev_;
}

bool AcceptBindingPreimage(const std::vector<uint8_t>& enc, std::string* why)
{
    if (enc.empty()) {
        if (why) *why = "domain_sep:empty_binding_preimage";
        return false;
    }
    if (!InBindFirstByteClass(enc[0])) {
        // The exact cross-domain confusion the doc forbids: an FS-class byte
        // (0xF5) reused as a binding commitment.
        if (why) *why = "domain_sep:binding_first_byte_not_in_D_BIND";
        return false;
    }
    if (enc.size() == kLegacyHeaderLen) {
        if (why) *why = "domain_sep:tagged_length_182_header_alias";
        return false; // SHOULD guard
    }
    return true;
}

bool AcceptFsPreimage(const std::vector<uint8_t>& enc, std::string* why)
{
    if (enc.empty()) {
        if (why) *why = "domain_sep:empty_fs_preimage";
        return false;
    }
    if (!InFsFirstByteClass(enc[0])) {
        if (why) *why = "domain_sep:fs_first_byte_not_in_D_FS";
        return false;
    }
    if (enc.size() == kLegacyHeaderLen) {
        if (why) *why = "domain_sep:tagged_length_182_header_alias";
        return false;
    }
    return true;
}

HashDomainSeparationAudit AssessHashDomainSeparation()
{
    HashDomainSeparationAudit audit;

    // Role bytes are assigned and compile-time consistent.
    audit.role_bytes_assigned =
        (kRoleFs == 0xF5) && (kRoleBindAscii == 0xB1) &&
        (kReceiptLeafTag == 0x03) && (kReceiptInternalTag == 0x04);

    // The load-bearing MUST: FS and BIND first-byte classes disjoint across the
    // full V8 registry.
    audit.fs_and_bind_first_byte_classes_disjoint =
        RegistryFirstByteClassesDisjoint(kRegistryV8, kRegistryV8Size);

    audit.registry_enumerates_call_sites = (kRegistryV8Size > 0);

    // Cross-domain confusion is rejected by construction; confirm on live data.
    {
        std::vector<uint8_t> fs_digest_preimage;
        fs_digest_preimage.push_back(kRoleFs); // an FS-class preimage
        fs_digest_preimage.push_back(0x01);
        std::string why;
        const bool rejected =
            !AcceptBindingPreimage(fs_digest_preimage, &why);
        std::vector<uint8_t> bind_preimage;
        bind_preimage.push_back(kRoleBindAscii);
        bind_preimage.push_back(0x02);
        std::string why2;
        const bool rejected2 = !AcceptFsPreimage(bind_preimage, &why2);
        audit.cross_domain_confusion_rejected = rejected && rejected2;
    }

    // Length-182 SHOULD guard is live.
    {
        std::vector<uint8_t> len182(kLegacyHeaderLen, 0x00);
        std::string why;
        audit.length_182_guard_present = !AcceptBindingPreimage(len182, &why);
    }

    // The legacy defect is reproducible (fail-open overlap the doc found).
    audit.legacy_defect_reproduced = !RegistryFirstByteClassesDisjoint(
        kRegistryLegacyDefect, kRegistryLegacyDefectSize);

    audit.pre_activation_only = true;
    audit.promoted_security_bits = 0;
    audit.note =
        "V8 role bytes (0xF5 FS / 0xB1 ASCII-bind / 0x03-0x04 receipt); "
        "H_FS and H_BIND syntactically disjoint. O-EXACT and A-FS-INST OPEN; "
        "full O-ENC per-site injectivity certificate NOT run over the real "
        "proof; consensus authority unchanged.";
    return audit;
}

} // namespace matmul::v4::rc::stage3::domain_sep
