// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/provenance.h>

#include <modelnet/identity.h>
#include <util/strencodings.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <algorithm>
#include <cstring>
#include <memory>

namespace modelnet {
namespace {

struct EvpMdCtxFree {
    void operator()(EVP_MD_CTX* p) const
    {
        if (p) EVP_MD_CTX_free(p);
    }
};
struct EvpPkeyFree {
    void operator()(EVP_PKEY* p) const
    {
        if (p) EVP_PKEY_free(p);
    }
};
struct EvpPkeyCtxFree {
    void operator()(EVP_PKEY_CTX* p) const
    {
        if (p) EVP_PKEY_CTX_free(p);
    }
};

std::string LowerAlgo(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::vector<unsigned char> MessageBytes(const ProvenanceEvidence& pe)
{
    std::vector<unsigned char> payload;
    if (!pe.payload_b64.empty()) {
        if (auto d = DecodeBase64(pe.payload_b64)) payload = std::move(*d);
    } else if (!pe.payload.empty()) {
        payload.assign(pe.payload.begin(), pe.payload.end());
    } else if (!pe.locator.empty()) {
        payload.assign(pe.locator.begin(), pe.locator.end());
    }
    if (!pe.payload_type.empty()) {
        std::vector<unsigned char> pae;
        DssePae(pe.payload_type, Span<const unsigned char>{payload.data(), payload.size()}, pae);
        return pae;
    }
    return payload;
}

std::vector<unsigned char> SignatureBytes(const ProvenanceEvidence& pe)
{
    if (!pe.signature_hex.empty()) {
        if (auto d = TryParseHex<unsigned char>(pe.signature_hex)) return *d;
        return {};
    }
    if (!pe.signature_b64.empty()) {
        if (auto d = DecodeBase64(pe.signature_b64)) return *d;
    }
    return {};
}

bool VerifyEd25519(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig)
{
    if (pk.size() != 32 || sig.size() != 64) return false;
    std::unique_ptr<EVP_PKEY, EvpPkeyFree> pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pk.data(), pk.size()));
    if (!pkey) return false;
    std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree> ctx(EVP_MD_CTX_new());
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
}

bool VerifyEcdsaP256Sha256(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig)
{
    if (pk.empty() || sig.empty() || msg.empty()) return false;
    if (pk.size() != 65 && pk.size() != 33) return false;
    std::vector<unsigned char> pub(pk.begin(), pk.end());
    char group[] = "P-256";
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxFree> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_fromdata_init(pctx.get()) != 1) return false;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size()),
        OSSL_PARAM_END,
    };
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(pctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) != 1 || !raw) return false;
    std::unique_ptr<EVP_PKEY, EvpPkeyFree> pkey(raw);
    std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree> ctx(EVP_MD_CTX_new());
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
}

} // namespace

void DssePae(const std::string& payload_type, Span<const unsigned char> payload, std::vector<unsigned char>& out)
{
    const std::string head = "DSSEv1 " + std::to_string(payload_type.size()) + " " + payload_type + " " +
                             std::to_string(payload.size()) + " ";
    out.assign(head.begin(), head.end());
    out.insert(out.end(), payload.begin(), payload.end());
}

bool VerifyProvenanceEvidence(const ProvenanceEvidence& pe, ProvenanceVerifyResult& out)
{
    out = {};
    out.algorithm = pe.algorithm;
    out.parsed = !pe.kind.empty();
    if (!out.parsed) {
        out.error = "provenance kind";
        return false;
    }
    const std::string algo = LowerAlgo(pe.algorithm);
    const auto pk = TryParseHex<unsigned char>(pe.public_key_hex);
    const auto sig = SignatureBytes(pe);
    const auto msg = MessageBytes(pe);
    if (!pk || pk->empty() || sig.empty() || msg.empty()) {
        out.verified_here = false;
        if (pe.kind == "unsigned") out.parsed = true;
        return true;
    }
    bool ok = false;
    if (algo.empty() || algo == "ml-dsa-44" || algo == "mldsa44") {
        out.algorithm = "ML-DSA-44";
        ok = VerifyMlDsa44(Span<const unsigned char>{pk->data(), pk->size()},
                           Span<const unsigned char>{msg.data(), msg.size()},
                           Span<const unsigned char>{sig.data(), sig.size()});
    } else if (algo == "ed25519") {
        out.algorithm = "ED25519";
        ok = VerifyEd25519(Span<const unsigned char>{pk->data(), pk->size()},
                           Span<const unsigned char>{msg.data(), msg.size()},
                           Span<const unsigned char>{sig.data(), sig.size()});
    } else if (algo == "ecdsa-p256-sha256" || algo == "ecdsa-sha256" || algo == "sha256withp256") {
        out.algorithm = "ECDSA-P256-SHA256";
        ok = VerifyEcdsaP256Sha256(Span<const unsigned char>{pk->data(), pk->size()},
                                   Span<const unsigned char>{msg.data(), msg.size()},
                                   Span<const unsigned char>{sig.data(), sig.size()});
    } else {
        out.error = "algorithm";
        out.verified_here = false;
        return true;
    }
    out.verified_here = ok;
    if (!ok) out.error = "SIGNATURE_INVALID";
    return true;
}

} // namespace modelnet
