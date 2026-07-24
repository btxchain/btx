// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds.h>

#include <crypto/common.h>
#include <matmul/matmul_v4_rc_fri_ext3.h> // Sha256dBytes (SHA256d counter-XOF)

#include <cstring>
#include <string>
#include <vector>

namespace matmul::v4::rc {

namespace {

using gkr_field::Add;
using gkr_field::Canonical;
using gkr_field::Fp;
using gkr_field::FromSigned;
using gkr_field::Mul;

uint64_t Low64LE(const unsigned char* bytes)
{
    uint64_t w = 0;
    for (int i = 0; i < 8; ++i) {
        w |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }
    return w;
}

Fp FreivaldsChallengeElement(const uint256& challenge_seed, uint32_t rep, uint32_t j)
{
    // retry=0 preserves the old transcript prefix; retry>0 appends LE32(retry).
    constexpr size_t kTagLen = sizeof(kRCFreivaldsDomainTag) - 1; // no NUL
    constexpr size_t kBaseLen = 32 + kTagLen + 4 + 4;
    std::vector<unsigned char> buf(kBaseLen + 4);
    std::memcpy(buf.data(), challenge_seed.data(), 32);
    std::memcpy(buf.data() + 32, kRCFreivaldsDomainTag, kTagLen);
    WriteLE32(buf.data() + 32 + kTagLen, rep);
    WriteLE32(buf.data() + 32 + kTagLen + 4, j);
    for (uint32_t retry = 0;; ++retry) {
        size_t len = kBaseLen;
        if (retry != 0) {
            WriteLE32(buf.data() + kBaseLen, retry);
            len += 4;
        }
        const uint256 h = Sha256dBytes(buf.data(), len);
        const uint64_t w = Low64LE(h.data());
        if (w < gkr_field::kP) return static_cast<Fp>(w);
    }
}

} // namespace

std::vector<Fp> FreivaldsChallengeVector(const uint256& challenge_seed,
                                         uint32_t rep, uint32_t n)
{
    std::vector<Fp> r(n);
    for (uint32_t j = 0; j < n; ++j) {
        r[j] = FreivaldsChallengeElement(challenge_seed, rep, j);
    }
    return r;
}

bool FreivaldsCheckGemm(const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                        const std::vector<int64_t>& Y, uint32_t m, uint32_t k,
                        uint32_t n, const uint256& challenge_seed, uint32_t reps,
                        std::string* why)
{
    const auto fail = [why](const char* msg) {
        if (why) *why = msg;
        return false;
    };
    // Fail-closed shape validation (64-bit products: m,k,n are uint32).
    const uint64_t mk = static_cast<uint64_t>(m) * k;
    const uint64_t kn = static_cast<uint64_t>(k) * n;
    const uint64_t mn = static_cast<uint64_t>(m) * n;
    if (A.size() != mk) return fail("freivalds: A.size() != m*k");
    if (B.size() != kn) return fail("freivalds: B.size() != k*n");
    if (Y.size() != mn) return fail("freivalds: Y.size() != m*n");
    if (reps == 0) return fail("freivalds: reps must be >= 1");

    for (uint32_t rep = 0; rep < reps; ++rep) {
        const std::vector<Fp> r = FreivaldsChallengeVector(challenge_seed, rep, n);

        // s = B·r ∈ F^k — O(kn).
        std::vector<Fp> s(k, 0);
        for (uint32_t i = 0; i < k; ++i) {
            const int8_t* row = B.data() + static_cast<size_t>(i) * n;
            Fp acc = 0;
            for (uint32_t j = 0; j < n; ++j) {
                acc = Add(acc, Mul(FromSigned(row[j]), r[j]));
            }
            s[i] = acc;
        }

        // Per row i of A and Y: compare (A·s)_i = (A·(B·r))_i against (Y·r)_i
        // — O(mk + mn) total. A·B is never formed.
        for (uint32_t i = 0; i < m; ++i) {
            const int8_t* arow = A.data() + static_cast<size_t>(i) * k;
            Fp lhs = 0;
            for (uint32_t t = 0; t < k; ++t) {
                lhs = Add(lhs, Mul(FromSigned(arow[t]), s[t]));
            }
            const int64_t* yrow = Y.data() + static_cast<size_t>(i) * n;
            Fp rhs = 0;
            for (uint32_t j = 0; j < n; ++j) {
                rhs = Add(rhs, Mul(FromSigned(yrow[j]), r[j]));
            }
            if (Canonical(lhs) != Canonical(rhs)) {
                if (why) {
                    *why = "freivalds: projection mismatch at rep " +
                           std::to_string(rep) + ", row " + std::to_string(i);
                }
                return false;
            }
        }
    }
    return true;
}

bool FreivaldsCheckGemmSegments(const std::vector<FreivaldsSegmentOperand>& segments,
                                const std::vector<int64_t>& Y, uint32_t m, uint32_t n,
                                const uint256& challenge_seed, uint32_t reps, std::string* why)
{
    const auto fail = [why](const char* msg) {
        if (why) *why = msg;
        return false;
    };
    if (reps == 0) return fail("freivalds_seg: reps must be >= 1");
    if (segments.empty()) return fail("freivalds_seg: empty segment set");
    const uint64_t mn = static_cast<uint64_t>(m) * n;
    if (Y.size() != mn) return fail("freivalds_seg: Y.size() != m*n");
    for (const auto& sg : segments) {
        const uint64_t mk = static_cast<uint64_t>(m) * sg.k_p;
        const uint64_t kn = static_cast<uint64_t>(sg.k_p) * n;
        if (sg.A_slice.size() != mk) return fail("freivalds_seg: A_slice.size() != m*k_p");
        if (sg.B_slice.size() != kn) return fail("freivalds_seg: B_slice.size() != k_p*n");
    }

    for (uint32_t rep = 0; rep < reps; ++rep) {
        const std::vector<Fp> r = FreivaldsChallengeVector(challenge_seed, rep, n);

        // Per output row i: lhs_i = Σ_p (A_p[i,:]·(B_p·r)); compare against
        // (Y·r)_i. Never forms any A_p·B_p; the projection is shared across all
        // segments (F-linearity), so the segment partials sum under ONE r.
        // Precompute each segment's s_p = B_p·r ∈ F^{k_p}.
        std::vector<std::vector<Fp>> s(segments.size());
        for (size_t p = 0; p < segments.size(); ++p) {
            const uint32_t kp = segments[p].k_p;
            std::vector<Fp> sp(kp, 0);
            const int8_t* Bp = segments[p].B_slice.data();
            for (uint32_t t = 0; t < kp; ++t) {
                const int8_t* row = Bp + static_cast<size_t>(t) * n;
                Fp acc = 0;
                for (uint32_t j = 0; j < n; ++j) acc = Add(acc, Mul(FromSigned(row[j]), r[j]));
                sp[t] = acc;
            }
            s[p] = std::move(sp);
        }
        for (uint32_t i = 0; i < m; ++i) {
            Fp lhs = 0;
            for (size_t p = 0; p < segments.size(); ++p) {
                const uint32_t kp = segments[p].k_p;
                const int8_t* arow = segments[p].A_slice.data() + static_cast<size_t>(i) * kp;
                const std::vector<Fp>& sp = s[p];
                for (uint32_t t = 0; t < kp; ++t) lhs = Add(lhs, Mul(FromSigned(arow[t]), sp[t]));
            }
            const int64_t* yrow = Y.data() + static_cast<size_t>(i) * n;
            Fp rhs = 0;
            for (uint32_t j = 0; j < n; ++j) rhs = Add(rhs, Mul(FromSigned(yrow[j]), r[j]));
            if (Canonical(lhs) != Canonical(rhs)) {
                if (why) {
                    *why = "freivalds_seg: projection mismatch at rep " + std::to_string(rep) +
                           ", row " + std::to_string(i);
                }
                return false;
            }
        }
    }
    return true;
}

} // namespace matmul::v4::rc
