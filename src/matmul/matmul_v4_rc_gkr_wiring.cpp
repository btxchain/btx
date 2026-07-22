// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_gkr_wiring.h>

#include <crypto/sha256.h>

#include <array>
#include <cstring>
#include <utility>

// CONSTRUCTION IV — copy / permutation wiring constraints. See the header
// for the mathematics; this file is the constraint builder (constructing
// routine) + direct checking routine.
// Consensus posture: arbiter OFF, heights INT32_MAX, int64 reference untouched.

namespace matmul::v4::rc {

namespace {

using gkr_field::Add;
using gkr_field::Eq;
using gkr_field::FromSigned;
using gkr_field::FromU64;
using gkr_field::Inv;
using gkr_field::IsZero;
using gkr_field::Mul;
using gkr_field::Sub;

void AppendLE32(std::vector<unsigned char>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
}

std::array<unsigned char, 32> Sha256dBytes(const unsigned char* data, size_t len)
{
    std::array<unsigned char, 32> h1{}, h2{};
    CSHA256().Write(data, len).Finalize(h1.data());
    CSHA256().Write(h1.data(), h1.size()).Finalize(h2.data());
    return h2;
}

uint32_t Log2Ceil(uint64_t n)
{
    if (n <= 1) return 0;
    uint32_t ell = 0;
    uint64_t cap = 1;
    while (cap < n) {
        cap <<= 1;
        ++ell;
    }
    return ell;
}

std::vector<Fp2> ToFp2FromI8(const std::vector<int8_t>& v)
{
    std::vector<Fp2> out;
    out.reserve(v.size());
    for (const int8_t x : v) out.push_back(Fp2::FromFp(FromSigned(x)));
    return out;
}

std::vector<Fp2> ToFp2FromI64(const std::vector<int64_t>& v)
{
    std::vector<Fp2> out;
    out.reserve(v.size());
    for (const int64_t x : v) out.push_back(Fp2::FromFp(FromSigned(x)));
    return out;
}

/** Index tag i ↦ Fp2 embedding. Injective for i < p (columns cap at 2^28). */
Fp2 IndexTag(uint64_t i) { return Fp2::FromFp(FromU64(i)); }

/** π structural check: bijection [0,n) → [0,n). */
bool IsBijection(const std::vector<uint64_t>& pi, uint64_t n, std::string* why)
{
    if (pi.size() != n) {
        if (why) *why = "pi size != n";
        return false;
    }
    std::vector<bool> seen(n, false);
    for (uint64_t j = 0; j < n; ++j) {
        const uint64_t t = pi[j];
        if (t >= n) {
            if (why) *why = "pi out of range";
            return false;
        }
        if (seen[t]) {
            if (why) *why = "pi not injective";
            return false;
        }
        seen[t] = true;
    }
    return true;
}

WiringVerifyResult Fail(std::string reason)
{
    WiringVerifyResult r;
    r.ok = false;
    r.reason = std::move(reason);
    return r;
}

WiringVerifyResult Ok(std::string reason = "ok")
{
    WiringVerifyResult r;
    r.ok = true;
    r.reason = std::move(reason);
    return r;
}

} // namespace

// ----------------------------------------------------------------------------
// FS challenge derivation (tagged SHA256d, commit-then-challenge)
// ----------------------------------------------------------------------------

Fp2 WiringChallengeFp2(const uint256& fs_seed, const char* label, uint32_t idx, uint32_t sub)
{
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCGkrWiringDomainTag),
               reinterpret_cast<const unsigned char*>(kRCGkrWiringDomainTag) +
                   sizeof(kRCGkrWiringDomainTag) - 1);
    buf.insert(buf.end(), fs_seed.data(), fs_seed.data() + 32);
    const size_t label_len = std::strlen(label);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(label),
               reinterpret_cast<const unsigned char*>(label) + label_len);
    AppendLE32(buf, idx);
    AppendLE32(buf, sub);
    const auto h = Sha256dBytes(buf.data(), buf.size());
    return gkr_field::FromChallengeBytes2(h.data());
}

std::vector<Fp2> WiringChallengePoint(const uint256& fs_seed, const char* label, uint32_t idx,
                                      uint32_t ell)
{
    std::vector<Fp2> rho;
    rho.reserve(ell);
    for (uint32_t b = 0; b < ell; ++b) rho.push_back(WiringChallengeFp2(fs_seed, label, idx, b));
    return rho;
}

// ----------------------------------------------------------------------------
// (a) EQUALITY
// ----------------------------------------------------------------------------

WiringEqualityConstraint WiringEqualityFromFp2(std::vector<Fp2> u, std::vector<Fp2> v)
{
    WiringEqualityConstraint c;
    c.len_u = u.size();
    c.len_v = v.size();
    const uint64_t logical_max = c.len_u > c.len_v ? c.len_u : c.len_v;
    c.ell = Log2Ceil(logical_max);
    const size_t padded = size_t{1} << c.ell;
    u.resize(padded, Fp2::Zero());
    v.resize(padded, Fp2::Zero());
    c.u = std::move(u);
    c.v = std::move(v);
    return c;
}

WiringEqualityConstraint WiringEqualityFromInt8(const std::vector<int8_t>& u,
                                                const std::vector<int8_t>& v)
{
    return WiringEqualityFromFp2(ToFp2FromI8(u), ToFp2FromI8(v));
}

WiringEqualityConstraint WiringEqualityFromInt64(const std::vector<int64_t>& u,
                                                 const std::vector<int64_t>& v)
{
    return WiringEqualityFromFp2(ToFp2FromI64(u), ToFp2FromI64(v));
}

WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint& c,
                                        const std::vector<Fp2>& rho)
{
    // Structural: Λ gives both sides the same logical shape; a length
    // mismatch is a wiring violation regardless of values (deterministic).
    if (c.len_u != c.len_v) return Fail("wiring equality: logical length mismatch (structural)");
    if (rho.size() != c.ell) return Fail("wiring equality: rho arity != ell");
    const size_t padded = size_t{1} << c.ell;
    if (c.u.size() != padded || c.v.size() != padded) {
        return Fail("wiring equality: column not padded to 2^ell");
    }
    // d̃(ρ) = ũ(ρ) − ṽ(ρ); accept iff 0. COMPLETENESS: u = v ⇒ identical
    // MLEs ⇒ passes for every ρ, exactly. SEPARATION: u ≠ v ⇒ d̃ is a
    // nonzero multilinear in ℓ variables (total degree ≤ ℓ); by
    // Schwartz–Zippel it vanishes at uniform ρ ∈ K^ℓ w.p. ≤ ℓ/|K|
    // (Fp3 draw, ℓ = 28 ⇒ 2^-187.19 pre-grinding, 2^-147.19 after the 2^40
    // budget; Fp2 history 2^-123.19 / 2^-83.19).
    const Fp2 eu = RCGkrMleEval1D2(c.u, rho);
    const Fp2 ev = RCGkrMleEval1D2(c.v, rho);
    if (!Eq(eu, ev)) return Fail("wiring equality: d~(rho) != 0 (u~ != u'~ at rho)");
    return Ok();
}

WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint& c, const uint256& fs_seed,
                                        uint32_t claim_index)
{
    return VerifyWiringEquality(c, WiringChallengePoint(fs_seed, "wire_eq_rho", claim_index, c.ell));
}

bool WiringEqualityOpeningClaims(const WiringEqualityConstraint& c, const std::vector<Fp2>& rho,
                                 uint32_t column_id_u, uint32_t column_id_v,
                                 std::vector<RCGkrOpeningClaim>& out, std::string* why)
{
    if (c.len_u != c.len_v) {
        if (why) *why = "wiring equality claims: logical length mismatch (structural)";
        return false;
    }
    if (rho.size() != c.ell) {
        if (why) *why = "wiring equality claims: rho arity != ell";
        return false;
    }
    const Fp2 eu = RCGkrMleEval1D2(c.u, rho);
    const Fp2 ev = RCGkrMleEval1D2(c.v, rho);
    if (!Eq(eu, ev)) {
        // The columns already disagree at ρ — emitting a shared-value claim
        // pair would be a false statement about at least one column. The
        // caller learns the wiring is broken before touching the backend.
        if (why) *why = "wiring equality claims: columns disagree at rho (wiring violated)";
        return false;
    }
    RCGkrOpeningClaim cu;
    cu.column_id = column_id_u;
    cu.point = rho;
    cu.value = eu;
    RCGkrOpeningClaim cv;
    cv.column_id = column_id_v;
    cv.point = rho;
    cv.value = ev; // == eu; the checking routine compares the shared value (d̃(ρ) = 0)
    out.push_back(std::move(cu));
    out.push_back(std::move(cv));
    return true;
}

// ----------------------------------------------------------------------------
// (b) PERMUTATION (grand product)
// ----------------------------------------------------------------------------

WiringPermutationConstraint BuildWiringPermutation(std::vector<Fp2> u, std::vector<Fp2> v,
                                                   std::vector<uint64_t> pi, const Fp2& beta,
                                                   const Fp2& gamma)
{
    WiringPermutationConstraint c;
    c.n = u.size();
    c.beta = beta;
    c.gamma = gamma;
    if (v.size() != c.n || pi.size() != c.n) {
        c.u = std::move(u);
        c.v = std::move(v);
        c.pi = std::move(pi);
        c.build_ok = false;
        c.build_note = "wiring permutation build: size mismatch";
        return c;
    }
    std::string why;
    if (!IsBijection(pi, c.n, &why)) {
        c.u = std::move(u);
        c.v = std::move(v);
        c.pi = std::move(pi);
        c.build_ok = false;
        c.build_note = "wiring permutation build: " + why;
        return c;
    }
    c.u = std::move(u);
    c.v = std::move(v);
    c.pi = std::move(pi);
    // z_0 = 1; z_{i+1} = z_i · (u_i + β·i + γ) / (v_i + β·π(i) + γ).
    // FAIL-CLOSED on any zero factor (numerator or denominator): the honest
    // instance resamples β/γ (probability ≤ 2n/|Fp2| per pair); a zero factor
    // is NEVER an accept path (same posture as the LogUp denominators).
    c.z.assign(c.n + 1, Fp2::Zero());
    c.z[0] = Fp2::One();
    for (uint64_t i = 0; i < c.n; ++i) {
        const Fp2 num = Add(c.u[i], Add(Mul(c.beta, IndexTag(i)), c.gamma));
        const Fp2 den = Add(c.v[i], Add(Mul(c.beta, IndexTag(c.pi[i])), c.gamma));
        if (IsZero(num) || IsZero(den)) {
            c.build_ok = false;
            c.build_note = "wiring permutation build: zero factor at row " + std::to_string(i) +
                           " (resample beta/gamma)";
            return c;
        }
        c.z[i + 1] = Mul(c.z[i], Mul(num, Inv(den)));
    }
    c.build_ok = true;
    c.build_note = "ok";
    return c;
}

WiringVerifyResult VerifyWiringPermutation(const WiringPermutationConstraint& c)
{
    // Fail-closed: a constraint the builder could not complete is invalid.
    if (!c.build_ok) return Fail("wiring permutation: build failed: " + c.build_note);
    if (c.u.size() != c.n || c.v.size() != c.n) return Fail("wiring permutation: size mismatch");
    std::string why;
    if (!IsBijection(c.pi, c.n, &why)) return Fail("wiring permutation: " + why);
    if (c.z.size() != c.n + 1) return Fail("wiring permutation: z size != n+1");
    // Boundary z_0 = 1.
    if (!Eq(c.z[0], Fp2::One())) return Fail("wiring permutation: z_0 != 1");
    // Step identity over the WHOLE index range (the hypercube form of this
    // check is the committed-column AIR step constraint; here we check every
    // row directly):
    //   z_{i+1}·(v_i + β·π(i) + γ) = z_i·(u_i + β·i + γ).
    for (uint64_t i = 0; i < c.n; ++i) {
        const Fp2 num = Add(c.u[i], Add(Mul(c.beta, IndexTag(i)), c.gamma));
        const Fp2 den = Add(c.v[i], Add(Mul(c.beta, IndexTag(c.pi[i])), c.gamma));
        if (IsZero(num) || IsZero(den)) {
            return Fail("wiring permutation: zero factor at row " + std::to_string(i) +
                        " (fail-closed; resample beta/gamma)");
        }
        if (!Eq(Mul(c.z[i + 1], den), Mul(c.z[i], num))) {
            return Fail("wiring permutation: step identity failed at row " + std::to_string(i));
        }
    }
    // Boundary z_n = 1 ⇔ Π num = Π den. COMPLETENESS: v_j = u_{π(j)} ∀j makes
    // the right factor j equal the left factor π(j) (same value, same tag), so
    // the multisets of factors coincide and the product telescopes to 1
    // exactly. SEPARATION: otherwise the two products differ as polynomials
    // in (β, γ) (unique factorization over Fp2[β,γ]: monic-in-γ linear
    // factors γ + β·tag + val are associate iff (tag, val) coincide, and the
    // index tags are injective since n ≤ 2^28 < p), so the difference is a
    // nonzero polynomial of total degree ≤ n and Schwartz–Zippel bounds
    // acceptance by n/|Fp2| per (β, γ) pair — n = 2^28: 2^-100 pre-grinding,
    // 2^-60 post (single pair; USE THE DUAL FORM at this size).
    if (!Eq(c.z[c.n], Fp2::One())) {
        return Fail("wiring permutation: grand product != 1 (z_n != 1: u' is not pi(u))");
    }
    return Ok();
}

WiringPermutationDual BuildWiringPermutationDual(const std::vector<Fp2>& u,
                                                 const std::vector<Fp2>& v,
                                                 const std::vector<uint64_t>& pi,
                                                 const uint256& fs_seed, uint32_t pair_index)
{
    WiringPermutationDual d;
    const Fp2 b1 = WiringChallengeFp2(fs_seed, "wire_perm_beta", pair_index, 0);
    const Fp2 g1 = WiringChallengeFp2(fs_seed, "wire_perm_gamma", pair_index, 0);
    const Fp2 b2 = WiringChallengeFp2(fs_seed, "wire_perm_beta", pair_index, 1);
    const Fp2 g2 = WiringChallengeFp2(fs_seed, "wire_perm_gamma", pair_index, 1);
    d.inst1 = BuildWiringPermutation(u, v, pi, b1, g1);
    d.inst2 = BuildWiringPermutation(u, v, pi, b2, g2);
    return d;
}

WiringVerifyResult VerifyWiringPermutationDual(const WiringPermutationDual& d)
{
    // Both instances must verify: a FALSE instance survives only if the
    // degree-≤n difference polynomial vanishes at BOTH independent (β, γ)
    // pairs — (n/|K|)²: Fp3 draw, n = 2^28 ⇒ 2^-328 pre-grinding, 2^-288
    // after the single FS round's 2^40 budget (Fp2 history 2^-200 / 2^-160;
    // mirrors the dual-α LogUp of §5.6).
    const WiringVerifyResult r1 = VerifyWiringPermutation(d.inst1);
    if (!r1.ok) return Fail("dual instance 1: " + r1.reason);
    const WiringVerifyResult r2 = VerifyWiringPermutation(d.inst2);
    if (!r2.ok) return Fail("dual instance 2: " + r2.reason);
    // Defensive: the two instances must be over the SAME vectors/π (an
    // invalid assignment must not satisfy each instance with different data).
    if (d.inst1.n != d.inst2.n) {
        return Fail("dual instances disagree on n");
    }
    for (uint64_t i = 0; i < d.inst1.n; ++i) {
        if (!Eq(d.inst1.u[i], d.inst2.u[i]) || !Eq(d.inst1.v[i], d.inst2.v[i]) ||
            d.inst1.pi[i] != d.inst2.pi[i]) {
            return Fail("dual instances bound to different columns/pi");
        }
    }
    return Ok();
}

std::vector<uint64_t> MakeTransposePermutation(uint32_t rows, uint32_t cols)
{
    // Producer u: rows×cols row-major. Consumer v = uᵀ: cols×rows row-major,
    // v[c·rows + r] = u[r·cols + c] ⇒ π[c·rows + r] = r·cols + c.
    std::vector<uint64_t> pi(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            pi[static_cast<size_t>(c) * rows + r] = static_cast<uint64_t>(r) * cols + c;
        }
    }
    return pi;
}

// ----------------------------------------------------------------------------
// Separation bounds
// ----------------------------------------------------------------------------

namespace {
/** log2 for the bound formulas (n ≥ 1). Loop-free of <cmath> dependence
 *  concerns: use a simple converging series via frexp-style bit math is
 *  overkill — columns are ≤ 2^28, doubles are exact for these integers. */
double Log2U64(uint64_t n)
{
    // Exact for n ≤ 2^53; wiring columns cap at 2^28.
    double x = static_cast<double>(n);
    double bits = 0.0;
    while (x >= 2.0) {
        x /= 2.0;
        bits += 1.0;
    }
    // x in [1,2): fractional bits via repeated squaring (24 bits of fraction
    // is ample for bound reporting).
    double frac = 0.0, step = 0.5;
    for (int i = 0; i < 24; ++i) {
        x *= x;
        if (x >= 2.0) {
            x /= 2.0;
            frac += step;
        }
        step /= 2.0;
    }
    return bits + frac;
}
} // namespace

double WiringEqualitySeparationBits(uint32_t ell, bool after_grinding)
{
    // Pr[accept false] ≤ ℓ/|K| (S2 on the nonzero multilinear difference);
    // |K| = kRCGkrWiringFieldBits bits (Fp3 challenge draw).
    // ℓ = 0: the "MLE" is the single cell itself — the comparison is exact
    // (probability 0); report field bits as a conservative finite sentinel.
    const double pre =
        (ell == 0) ? kRCGkrWiringFieldBits : kRCGkrWiringFieldBits - Log2U64(ell);
    return after_grinding ? pre - kRCGkrWiringGrindBits : pre;
}

double WiringPermutationSeparationBits(uint64_t n, bool dual, bool after_grinding)
{
    // Single: n/|K|. Dual: (n/|K|)² with ONE FS round (grinding paid once).
    // |K| = kRCGkrWiringFieldBits bits (Fp3 challenge draw).
    // n = 0: vacuous instance (empty product), exact — field-bits sentinel.
    if (n == 0) {
        const double pre = dual ? 2.0 * kRCGkrWiringFieldBits : kRCGkrWiringFieldBits;
        return after_grinding ? pre - kRCGkrWiringGrindBits : pre;
    }
    const double single = kRCGkrWiringFieldBits - Log2U64(n);
    const double pre = dual ? 2.0 * single : single;
    return after_grinding ? pre - kRCGkrWiringGrindBits : pre;
}

// ----------------------------------------------------------------------------
// Cross-layer binding helper
// ----------------------------------------------------------------------------

std::vector<WiringLayerBinding> BindAdjacentLayerWires(const std::vector<RCGkrV7WireWitness>& wires)
{
    std::vector<WiringLayerBinding> out;
    if (wires.size() < 2) return out;
    out.reserve(wires.size() - 1);
    for (size_t L = 0; L + 1 < wires.size(); ++L) {
        const RCGkrV7WireWitness& p = wires[L];
        const RCGkrV7WireWitness& q = wires[L + 1];
        WiringLayerBinding b;
        b.producer = L;
        b.consumer = L + 1;
        const uint64_t m0 = p.m, n0 = p.n;
        const uint64_t out_cells = m0 * n0;
        if (p.extract_out.size() != out_cells) {
            b.kind = WiringBindingKind::Unbound;
            b.note = "producer extract_out size != m*n (malformed wire)";
            out.push_back(std::move(b));
            continue;
        }
        const uint64_t a_cells = static_cast<uint64_t>(q.m) * q.k;
        const uint64_t b_cells = static_cast<uint64_t>(q.k) * q.n;
        // Shape-designated choice ONLY (rules 1–4 in the header); values are
        // never consulted — a value mismatch must FAIL verification, not
        // silently re-route the binding.
        if (q.m == m0 && q.k == n0 && q.A.size() == a_cells && a_cells == out_cells) {
            b.kind = WiringBindingKind::Equality;
            b.consumer_operand = 'A';
            b.eq = WiringEqualityFromInt8(p.extract_out, q.A);
            b.note = "extract_out(L) == A(L+1), direct copy";
        } else if (q.k == m0 && q.n == n0 && q.B.size() == b_cells && b_cells == out_cells) {
            b.kind = WiringBindingKind::Equality;
            b.consumer_operand = 'B';
            b.eq = WiringEqualityFromInt8(p.extract_out, q.B);
            b.note = "extract_out(L) == B(L+1), direct copy";
        } else if (q.m == n0 && q.k == m0 && q.A.size() == a_cells && a_cells == out_cells) {
            b.kind = WiringBindingKind::Permutation;
            b.consumer_operand = 'A';
            b.u = ToFp2FromI8(p.extract_out);
            b.v = ToFp2FromI8(q.A);
            b.pi = MakeTransposePermutation(p.m, p.n);
            b.note = "A(L+1) == transpose(extract_out(L)), grand-product wiring";
        } else if (q.k == n0 && q.n == m0 && q.B.size() == b_cells && b_cells == out_cells) {
            b.kind = WiringBindingKind::Permutation;
            b.consumer_operand = 'B';
            b.u = ToFp2FromI8(p.extract_out);
            b.v = ToFp2FromI8(q.B);
            b.pi = MakeTransposePermutation(p.m, p.n);
            b.note = "B(L+1) == transpose(extract_out(L)), grand-product wiring";
        } else {
            b.kind = WiringBindingKind::Unbound;
            b.note = "no shape-compatible consumer input; pair is Λ-definitional "
                     "(same column reference, §4.2) — no copy constraint emitted";
        }
        out.push_back(std::move(b));
    }
    return out;
}

WiringVerifyResult VerifyLayerBindings(const std::vector<WiringLayerBinding>& bindings,
                                       const uint256& fs_seed, bool fail_on_unbound)
{
    size_t bound = 0, unbound = 0;
    for (size_t i = 0; i < bindings.size(); ++i) {
        const WiringLayerBinding& b = bindings[i];
        const std::string where = "pair " + std::to_string(b.producer) + "->" +
                                  std::to_string(b.consumer) + ": ";
        switch (b.kind) {
        case WiringBindingKind::Equality: {
            const WiringVerifyResult r =
                VerifyWiringEquality(b.eq, fs_seed, static_cast<uint32_t>(i));
            if (!r.ok) return Fail(where + r.reason);
            ++bound;
            break;
        }
        case WiringBindingKind::Permutation: {
            const WiringPermutationDual d =
                BuildWiringPermutationDual(b.u, b.v, b.pi, fs_seed, static_cast<uint32_t>(i));
            const WiringVerifyResult r = VerifyWiringPermutationDual(d);
            if (!r.ok) return Fail(where + r.reason);
            ++bound;
            break;
        }
        case WiringBindingKind::Unbound:
            ++unbound;
            break;
        }
    }
    if (fail_on_unbound && unbound > 0) {
        return Fail("unbound (Λ-definitional) pairs present with fail_on_unbound: " +
                    std::to_string(unbound));
    }
    return Ok("ok (" + std::to_string(bound) + " bound, " + std::to_string(unbound) +
              " unbound-definitional)");
}

} // namespace matmul::v4::rc
