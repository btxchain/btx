#include <metal_stdlib>
using namespace metal;

constant uint MODULUS = 0x7fffffffu;

struct OracleParams {
    uint count;
};

inline uint rotr(uint x, uint n)
{
    return (x >> n) | (x << (32u - n));
}

inline uint sha_ch(uint x, uint y, uint z)
{
    return (x & y) ^ ((~x) & z);
}

inline uint sha_maj(uint x, uint y, uint z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint sha_bsig0(uint x)
{
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

inline uint sha_bsig1(uint x)
{
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

inline uint sha_ssig0(uint x)
{
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

inline uint sha_ssig1(uint x)
{
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

constant uint SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline void sha256_compress(thread uint state[8], thread uint w[64])
{
    for (uint t = 16; t < 64; ++t) {
        w[t] = sha_ssig1(w[t - 2]) + w[t - 7] + sha_ssig0(w[t - 15]) + w[t - 16];
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint t = 0; t < 64; ++t) {
        const uint t1 = h + sha_bsig1(e) + sha_ch(e, f, g) + SHA256_K[t] + w[t];
        const uint t2 = sha_bsig0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline void sha256_init(thread uint state[8])
{
    state[0] = 0x6a09e667u;
    state[1] = 0xbb67ae85u;
    state[2] = 0x3c6ef372u;
    state[3] = 0xa54ff53au;
    state[4] = 0x510e527fu;
    state[5] = 0x9b05688cu;
    state[6] = 0x1f83d9abu;
    state[7] = 0x5be0cd19u;
}

inline void set_byte(thread uint w[64], uint offset, uint byte)
{
    const uint word_index = offset >> 2u;
    const uint shift = (3u - (offset & 3u)) * 8u;
    w[word_index] |= (byte & 0xffu) << shift;
}

inline uint bswap32(uint x)
{
    return ((x & 0x000000ffu) << 24u) |
           ((x & 0x0000ff00u) << 8u) |
           ((x & 0x00ff0000u) >> 8u) |
           ((x & 0xff000000u) >> 24u);
}

inline uint candidate_from_seed_and_index(constant uchar* seed_internal, uint index, bool with_retry, uint retry)
{
    thread uint w[64];
    for (uint i = 0; i < 64; ++i) {
        w[i] = 0u;
    }

    for (uint i = 0; i < 32; ++i) {
        set_byte(w, i, seed_internal[31u - i]);
    }

    set_byte(w, 32u, index & 0xffu);
    set_byte(w, 33u, (index >> 8u) & 0xffu);
    set_byte(w, 34u, (index >> 16u) & 0xffu);
    set_byte(w, 35u, (index >> 24u) & 0xffu);

    uint message_len = 36u;
    if (with_retry) {
        set_byte(w, 36u, retry & 0xffu);
        set_byte(w, 37u, (retry >> 8u) & 0xffu);
        set_byte(w, 38u, (retry >> 16u) & 0xffu);
        set_byte(w, 39u, (retry >> 24u) & 0xffu);
        message_len = 40u;
    }

    set_byte(w, message_len, 0x80u);
    w[15] = message_len * 8u;

    thread uint state[8];
    sha256_init(state);
    sha256_compress(state, w);

    return bswap32(state[0]) & MODULUS;
}

inline uint fallback_candidate(constant uchar* seed_internal, uint index)
{
    thread uint w[64];
    for (uint i = 0; i < 64; ++i) {
        w[i] = 0u;
    }

    for (uint i = 0; i < 32; ++i) {
        set_byte(w, i, seed_internal[31u - i]);
    }

    set_byte(w, 32u, index & 0xffu);
    set_byte(w, 33u, (index >> 8u) & 0xffu);
    set_byte(w, 34u, (index >> 16u) & 0xffu);
    set_byte(w, 35u, (index >> 24u) & 0xffu);

    const uchar fallback_tag[15] = {
        'o', 'r', 'a', 'c', 'l', 'e', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k'
    };
    for (uint i = 0; i < 15; ++i) {
        set_byte(w, 36u + i, fallback_tag[i]);
    }

    set_byte(w, 51u, 0x80u);
    w[15] = 51u * 8u;

    thread uint state[8];
    sha256_init(state);
    sha256_compress(state, w);

    return bswap32(state[0]) % MODULUS;
}

inline uint from_oracle(constant uchar* seed_internal, uint index)
{
    for (uint retry = 0; retry < 256; ++retry) {
        const uint candidate = retry == 0
            ? candidate_from_seed_and_index(seed_internal, index, false, 0u)
            : candidate_from_seed_and_index(seed_internal, index, true, retry);
        if (candidate < MODULUS) {
            return candidate;
        }
    }
    return fallback_candidate(seed_internal, index);
}

kernel void generate_oracle_noise_vectors(constant OracleParams& p [[buffer(0)]],
                                          constant uchar* seed_el [[buffer(1)]],
                                          constant uchar* seed_er [[buffer(2)]],
                                          constant uchar* seed_fl [[buffer(3)]],
                                          constant uchar* seed_fr [[buffer(4)]],
                                          device uint* out_e_l [[buffer(5)]],
                                          device uint* out_e_r [[buffer(6)]],
                                          device uint* out_f_l [[buffer(7)]],
                                          device uint* out_f_r [[buffer(8)]],
                                          uint gid [[thread_position_in_grid]])
{
    if (gid >= p.count) {
        return;
    }
    out_e_l[gid] = from_oracle(seed_el, gid);
    out_e_r[gid] = from_oracle(seed_er, gid);
    out_f_l[gid] = from_oracle(seed_fl, gid);
    out_f_r[gid] = from_oracle(seed_fr, gid);
}

kernel void generate_oracle_vector(constant OracleParams& p [[buffer(0)]],
                                   constant uchar* seed_internal [[buffer(1)]],
                                   device uint* out [[buffer(2)]],
                                   uint gid [[thread_position_in_grid]])
{
    if (gid >= p.count) {
        return;
    }
    out[gid] = from_oracle(seed_internal, gid);
}
