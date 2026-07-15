// MatMul v4 per-stage wall-time benchmark  (NVIDIA / cuBLASLt)
// ---------------------------------------------------------------------------
// A standing check for the §K.2a-WT wall-time invariant: it runs the whole v4
// per-nonce hot path ON THE GPU and reports the measured per-stage split, so
// "the tensor GEMM must dominate measured wall-time" can be checked on real
// silicon rather than inferred from MAC/byte counts.
//
//   stage 1  operand-gen: A,B (n x n) + U (m x n) + V (n x m). With --wide, a
//            bit-exact wide counter-mode XOF matching ExpandBalancedS8Stream
//            (count -> prefix sum -> scatter); default is the retired
//            per-element XOF (kept for before/after comparison).
//   stage 2  cuBLASLt INT8->INT32: P = U*A (m x n), Q = B*V (n x m)   (§E.3)
//   stage 3  mod-q combine: Chat[a][c] = (sum_k P[a][k]*Q[k][c]) mod q, tiled.
//
// Per-stage CUDA-event timing over a batch of nonces => stage %split + nonce/s
// + a machine-parseable CSV row (+ board power via NVML).
//   --emit    reproduces the reference digest H(sigma||Chat) for fixed seeds,
//             BIT-EXACT to the CPU reference (cross-arch determinism check).
//   --verify  diffs cuBLASLt vs a scalar INT32 GEMM (self-consistency).
//   --wide    (default off) use the wide-stream XOF; omit for the legacy path.
//
// build:  nvcc -O3 -arch=native matmul_v4_stage_bench.cu -lcublasLt -lnvidia-ml -o v4bench
// run:    ./v4bench 4096 32 --wide        # n=4096, 32 nonces, wide XOF
//         ./v4bench 4096 1  --emit --wide  # print the reference-matching digest

#include <cublasLt.h>
#include <cuda_runtime.h>
#include <nvml.h>
#include <thrust/scan.h>
#include <thrust/execution_policy.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define CK(x) do { cudaError_t e=(x); if(e!=cudaSuccess){ \
    printf("CUDA %s:%d %s -> %s\n",__FILE__,__LINE__,#x,cudaGetErrorString(e)); exit(1);} } while(0)

// ===================== device SHA-256 (single 64B block) ====================
__constant__ uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

__device__ __forceinline__ uint32_t ror(uint32_t x,int n){return (x>>n)|(x<<(32-n));}

// SHA-256 of msg of length len (len<=55) -> 32-byte digest out. one block.
__device__ void sha256_1blk(const uint8_t* msg, int len, uint8_t out[32]) {
    uint8_t blk[64];
    #pragma unroll
    for (int i=0;i<64;i++) blk[i]=0;
    for (int i=0;i<len;i++) blk[i]=msg[i];
    blk[len]=0x80;
    uint64_t bits=(uint64_t)len*8;
    for (int i=0;i<8;i++) blk[63-i]=(uint8_t)(bits>>(8*i));
    uint32_t w[64];
    #pragma unroll
    for (int i=0;i<16;i++)
        w[i]=(blk[i*4]<<24)|(blk[i*4+1]<<16)|(blk[i*4+2]<<8)|blk[i*4+3];
    #pragma unroll
    for (int i=16;i<64;i++){
        uint32_t s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a;
    uint32_t e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    #pragma unroll
    for (int i=0;i<64;i++){
        uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+S1+ch+K256[i]+w[i];
        uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    uint32_t H[8]={0x6a09e667+a,0xbb67ae85+b,0x3c6ef372+c,0xa54ff53a+d,
                   0x510e527f+e,0x9b05688c+f,0x1f83d9ab+g,0x5be0cd19+h};
    #pragma unroll
    for (int i=0;i<8;i++){out[i*4]=H[i]>>24;out[i*4+1]=H[i]>>16;out[i*4+2]=H[i]>>8;out[i*4+3]=H[i];}
}

// consensus-exact: SHA(seed[32] || index_le[4] [|| retry_le[4]]), byte[0]<251 -> s8
__global__ void gen_operand(int8_t* out, const uint8_t* seed32, uint32_t count) {
    uint32_t idx = blockIdx.x*blockDim.x + threadIdx.x;
    if (idx>=count) return;
    uint8_t msg[40];
    // consensus SeedBytesLE: the reference reverses the 32-byte uint256 before
    // hashing (int8_field.cpp SeedBytesLE), so msg[i] = seed[31-i].
    #pragma unroll
    for (int i=0;i<32;i++) msg[i]=seed32[31-i];
    msg[32]=idx; msg[33]=idx>>8; msg[34]=idx>>16; msg[35]=idx>>24;
    uint8_t h[32];
    for (uint32_t retry=0; retry<256; ++retry){
        int len=36;
        if (retry>0){ msg[36]=retry;msg[37]=retry>>8;msg[38]=retry>>16;msg[39]=retry>>24; len=40; }
        sha256_1blk(msg,len,h);
        if (h[0]<251){ out[idx]=(int8_t)((int)h[0]-125); return; }
    }
    out[idx]=0;
}

// WIDE XOF (proposed fix): one SHA-256 per `per_hash` elements, consuming all 32
// output bytes in a counter/squeeze mode with rejection sampling. Models a fixed
// operand XOF that stops discarding 31/32 SHA bytes. per_hash<=30 keeps the ~2%
// rejection shortfall negligible (32*0.98~=31.4). This is a COST model of the fix
// (it is NOT byte-compatible with the per-element reference; --emit stays legacy).
__global__ void gen_operand_wide(int8_t* out, const uint8_t* seed32, uint32_t count, uint32_t per_hash){
    uint32_t t = blockIdx.x*blockDim.x + threadIdx.x;
    uint32_t base = t*per_hash;
    if (base>=count) return;
    uint8_t msg[36];
    #pragma unroll
    for (int i=0;i<32;i++) msg[i]=seed32[31-i];
    msg[32]=t; msg[33]=t>>8; msg[34]=t>>16; msg[35]=t>>24;
    uint8_t h[32]; sha256_1blk(msg,36,h);
    uint32_t w=0;
    for (int i=0;i<32 && w<per_hash && base+w<count; ++i)
        if (h[i]<251){ out[base+w]=(int8_t)((int)h[i]-125); ++w; }
    for (; w<per_hash && base+w<count; ++w) out[base+w]=0; // rare rejection shortfall (cost-model pad)
}

// BIT-EXACT wide counter-mode XOF, matching f50f0f8 ExpandBalancedS8Stream:
// block b -> SHA256(seed_le[32] || domain || LE64(b)) [41B, 1 SHA block], all 32
// bytes rejection-sampled (<251 -> byte-125) in stream order. Because rejection
// makes each element's output position depend on all prior blocks, this is a
// two-pass stream compaction (count -> exclusive prefix-sum -> scatter), exactly
// as the reference comment prescribes. domain 0x73='s' (operands), 0x71='q' (Fq).
__global__ void stream_count(const uint8_t* seed32, uint8_t domain, int8_t* scratch, uint32_t* cnt, uint32_t nblk){
    uint32_t b = blockIdx.x*blockDim.x+threadIdx.x; if(b>=nblk) return;
    uint8_t msg[41];
    #pragma unroll
    for(int i=0;i<32;i++) msg[i]=seed32[31-i];
    msg[32]=domain;
    uint64_t blk=b;
    #pragma unroll
    for(int i=0;i<8;i++) msg[33+i]=(uint8_t)(blk>>(8*i));
    uint8_t h[32]; sha256_1blk(msg,41,h);
    uint32_t c=0;
    for(int i=0;i<32;i++) if(h[i]<251) scratch[(size_t)b*32 + c++] = (int8_t)((int)h[i]-125);
    cnt[b]=c;
}
__global__ void stream_scatter(const int8_t* scratch, const uint32_t* off, const uint32_t* cnt, int8_t* out, uint32_t nblk, uint32_t count){
    uint32_t b = blockIdx.x*blockDim.x+threadIdx.x; if(b>=nblk) return;
    uint32_t o=off[b], c=cnt[b];
    for(uint32_t r=0;r<c;r++){ uint32_t pos=o+r; if(pos<count) out[pos]=scratch[(size_t)b*32+r]; }
}

// ===================== q = 2^61-1 combine ====================
__device__ __forceinline__ uint64_t fqreduce(unsigned __int128 x){
    const uint64_t Q=((uint64_t)1<<61)-1;
    uint64_t lo=(uint64_t)(x&Q), hi=(uint64_t)(x>>61);
    uint64_t s=lo+hi; s=(s&Q)+(s>>61); if(s>=Q)s-=Q; return s;
}
__device__ __forceinline__ uint64_t fqadd(uint64_t a,uint64_t b){const uint64_t Q=((uint64_t)1<<61)-1;uint64_t s=a+b;if(s>=Q)s-=Q;return s;}
__device__ __forceinline__ uint64_t fqmul(uint64_t a,uint64_t b){return fqreduce((unsigned __int128)a*b);}
__device__ __forceinline__ uint64_t fqfroms32(int32_t x){
    const uint64_t Q=((uint64_t)1<<61)-1;
    if(x>=0) return fqreduce((unsigned __int128)(uint64_t)x);
    uint64_t r=fqreduce((unsigned __int128)(uint64_t)(-(int64_t)x)); return r==0?0:Q-r;
}
__global__ void combine_modq(const int32_t* P,const int32_t* Q,uint64_t* Chat,uint32_t m,uint32_t n){
    size_t gid=(size_t)blockIdx.x*blockDim.x+threadIdx.x;
    if(gid>=(size_t)m*m) return;
    uint32_t a=gid/m, c=gid%m;
    const int32_t* prow=P+(size_t)a*n;
    uint64_t acc=0;
    for(uint32_t k=0;k<n;k++) acc=fqadd(acc,fqmul(fqfroms32(prow[k]),fqfroms32(Q[(size_t)k*m+c])));
    Chat[gid]=acc;
}

// Tiled mod-q GEMM: Chat[a][c] = sum_k P[a][k]*Q[k][c] over F_q. Coalesced loads
// of P (row-major, contiguous in k) and Q (row-major, contiguous in c) into
// shared memory, reused across the CT-tile. Byte-identical to combine_modq
// (F_q add is associative/commutative, so tile order does not change the sum).
#define CT 16
__global__ void combine_modq_tiled(const int32_t* __restrict__ P, const int32_t* __restrict__ Q,
                                   uint64_t* __restrict__ Chat, uint32_t m, uint32_t n){
    __shared__ uint64_t Ps[CT][CT];
    __shared__ uint64_t Qs[CT][CT];
    uint32_t row = blockIdx.y*CT + threadIdx.y; // a
    uint32_t col = blockIdx.x*CT + threadIdx.x; // c
    uint64_t acc = 0;
    for(uint32_t k0=0; k0<n; k0+=CT){
        uint32_t pk = k0 + threadIdx.x;         // warp varies tx -> contiguous in k (coalesced)
        Ps[threadIdx.y][threadIdx.x] = (row<m && pk<n) ? fqfroms32(P[(size_t)row*n + pk]) : 0;
        uint32_t qk = k0 + threadIdx.y;         // warp varies tx -> contiguous in c (coalesced)
        Qs[threadIdx.y][threadIdx.x] = (qk<n && col<m) ? fqfroms32(Q[(size_t)qk*m + col]) : 0;
        __syncthreads();
        #pragma unroll
        for(int kk=0; kk<CT; kk++) acc = fqadd(acc, fqmul(Ps[threadIdx.y][kk], Qs[kk][threadIdx.x]));
        __syncthreads();
    }
    if(row<m && col<m) Chat[(size_t)row*m + col] = acc;
}
// scalar INT8 GEMM (verify only): C[MxN]=A[MxK]*B[KxN] row-major
__global__ void gemm_scalar(const int8_t*A,const int8_t*B,int32_t*C,uint32_t M,uint32_t N,uint32_t Kd){
    size_t gid=(size_t)blockIdx.x*blockDim.x+threadIdx.x; if(gid>=(size_t)M*N)return;
    uint32_t r=gid/N,c=gid%N; const int8_t*ar=A+(size_t)r*Kd; int32_t acc=0;
    for(uint32_t k=0;k<Kd;k++) acc+=(int32_t)ar[k]*(int32_t)B[(size_t)k*N+c];
    C[gid]=acc;
}

// ===================== cuBLASLt INT8 GEMM (row-major, exact s8->s32) =========
bool int8_gemm(cublasLtHandle_t lt,cudaStream_t s,void*ws,size_t wsz,
               const int8_t*dA,const int8_t*dB,int32_t*dC,uint32_t M,uint32_t N,uint32_t Kd){
    cublasLtMatmulDesc_t op=nullptr; cublasLtMatrixLayout_t la=nullptr,lb=nullptr,lc=nullptr;
    cublasLtMatmulPreference_t pref=nullptr; bool ok=false;
    do{
        if(cublasLtMatmulDescCreate(&op,CUBLAS_COMPUTE_32I,CUDA_R_32I))break;
        cublasOperation_t opn=CUBLAS_OP_N;
        cublasLtMatmulDescSetAttribute(op,CUBLASLT_MATMUL_DESC_TRANSA,&opn,sizeof(opn));
        cublasLtMatmulDescSetAttribute(op,CUBLASLT_MATMUL_DESC_TRANSB,&opn,sizeof(opn));
        cublasLtOrder_t row=CUBLASLT_ORDER_ROW;
        auto mk=[&](cublasLtMatrixLayout_t*L,cudaDataType t,uint64_t r,uint64_t c,int64_t ld){
            if(cublasLtMatrixLayoutCreate(L,t,r,c,ld))return false;
            return 0==cublasLtMatrixLayoutSetAttribute(*L,CUBLASLT_MATRIX_LAYOUT_ORDER,&row,sizeof(row));};
        if(!mk(&la,CUDA_R_8I,M,Kd,Kd)||!mk(&lb,CUDA_R_8I,Kd,N,N)||!mk(&lc,CUDA_R_32I,M,N,N))break;
        cublasLtMatmulPreferenceCreate(&pref);
        cublasLtMatmulPreferenceSetAttribute(pref,CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,&wsz,sizeof(wsz));
        cublasLtMatmulHeuristicResult_t hr{}; int got=0;
        if(cublasLtMatmulAlgoGetHeuristic(lt,op,la,lb,lc,lc,pref,1,&hr,&got)||got==0){
            printf("  [cublasLt] no INT8 algo for %ux%ux%u\n",M,N,Kd); break;}
        int32_t alpha=1,beta=0;
        if(cublasLtMatmul(lt,op,&alpha,dA,la,dB,lb,&beta,dC,lc,dC,lc,&hr.algo,ws,wsz,s)){printf("  [cublasLt] matmul fail\n");break;}
        ok=true;
    }while(0);
    if(pref)cublasLtMatmulPreferenceDestroy(pref);
    if(lc)cublasLtMatrixLayoutDestroy(lc); if(lb)cublasLtMatrixLayoutDestroy(lb); if(la)cublasLtMatrixLayoutDestroy(la);
    if(op)cublasLtMatmulDescDestroy(op);
    return ok;
}

// ---- host SHA-256 (arbitrary length) for the digest byte-exact cross-check ----
static void hsha256(const uint8_t* d, size_t len, uint8_t out[32]){
    static const uint32_t Kh[64]={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    auto R=[](uint32_t x,int n){return (x>>n)|(x<<(32-n));};
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::vector<uint8_t> m(d,d+len);
    uint64_t bits=(uint64_t)len*8; m.push_back(0x80);
    while(m.size()%64!=56) m.push_back(0);
    for(int i=7;i>=0;i--) m.push_back((uint8_t)(bits>>(8*i)));
    for(size_t off=0;off<m.size();off+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|m[off+i*4+3];
        for(int i=16;i<64;i++){uint32_t a=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3),b=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+a+w[i-7]+b;}
        uint32_t a=s[0],b=s[1],c=s[2],dd=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
        for(int i=0;i<64;i++){uint32_t S1=R(e,6)^R(e,11)^R(e,25),ch=(e&f)^((~e)&g),t1=h+S1+ch+Kh[i]+w[i],S0=R(a,2)^R(a,13)^R(a,22),mj=(a&b)^(a&c)^(b&c),t2=S0+mj;h=g;g=f;f=e;e=dd+t1;dd=c;c=b;b=a;a=t1+t2;}
        s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=dd;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
    }
    for(int i=0;i<8;i++){out[i*4]=s[i]>>24;out[i*4+1]=s[i]>>16;out[i*4+2]=s[i]>>8;out[i*4+3]=s[i];}
}
// digest = SHA256d("BTX_MATMUL_V4" || sigma[32] || payload)  (matmul_v4.cpp ComputeSketchDigest)
static void sketch_digest(const uint8_t sigma[32], const uint8_t* payload, size_t plen, uint8_t out[32]){
    static const char tag[]="BTX_MATMUL_V4"; // 13 bytes, no null
    std::vector<uint8_t> buf; buf.insert(buf.end(),tag,tag+13);
    buf.insert(buf.end(),sigma,sigma+32); buf.insert(buf.end(),payload,payload+plen);
    uint8_t d1[32]; hsha256(buf.data(),buf.size(),d1); hsha256(d1,32,out);
}

int main(int argc,char**argv){
    uint32_t n = argc>1?atoi(argv[1]):4096;
    int nonces = argc>2?atoi(argv[2]):32;
    bool verify = false, emit = false, wide = false;
    for(int i=1;i<argc;i++){ std::string a=argv[i]; if(a=="--verify")verify=true; if(a=="--emit")emit=true; if(a=="--wide"||a=="--xof=wide")wide=true; }
    const uint32_t b=8, m=n/b;
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop,0));
    bool nvml_ok=false; nvmlDevice_t nvdev;
    if(nvmlInit_v2()==NVML_SUCCESS && nvmlDeviceGetHandleByIndex_v2(0,&nvdev)==NVML_SUCCESS) nvml_ok=true;
    printf("=== v4 bench | %s | n=%u m=%u nonces=%d xof=%s ===\n", prop.name, n,m,nonces, wide?"wide":"legacy");

    size_t nn=(size_t)n*n, mn=(size_t)m*n, nm=(size_t)n*m, mm=(size_t)m*m;
    int8_t *dA,*dB,*dU,*dV; int32_t *dP,*dQ,*dPs,*dQs; uint64_t *dChat,*dChatS;
    uint8_t *dSeedA,*dSeedB,*dSeedU,*dSeedV; void* ws;
    CK(cudaMalloc(&dA,nn));CK(cudaMalloc(&dB,nn));CK(cudaMalloc(&dU,mn));CK(cudaMalloc(&dV,nm));
    CK(cudaMalloc(&dP,mn*4));CK(cudaMalloc(&dQ,nm*4));CK(cudaMalloc(&dChat,mm*8));
    CK(cudaMalloc(&dSeedA,32));CK(cudaMalloc(&dSeedB,32));CK(cudaMalloc(&dSeedU,32));CK(cudaMalloc(&dSeedV,32));
    CK(cudaMalloc(&ws,(size_t)32<<20));
    // bit-exact wide-stream compaction buffers (sized for the largest operand, nn)
    uint32_t maxblk=(uint32_t)(nn/31 + 64);
    int8_t* dScratch; uint32_t *dCnt,*dOff;
    CK(cudaMalloc(&dScratch,(size_t)maxblk*32)); CK(cudaMalloc(&dCnt,maxblk*4)); CK(cudaMalloc(&dOff,maxblk*4));
    if(verify){CK(cudaMalloc(&dPs,mn*4));CK(cudaMalloc(&dQs,nm*4));CK(cudaMalloc(&dChatS,mm*8));}
    cublasLtHandle_t lt; cublasLtCreate(&lt);
    cudaStream_t s; CK(cudaStreamCreate(&s));

    auto seed=[&](uint8_t*d,int base){uint8_t h[32];for(int i=0;i<32;i++)h[i]=base+i;CK(cudaMemcpy(d,h,32,cudaMemcpyHostToDevice));};
    int T=256;
    // bit-exact wide counter-mode XOF, matches f50f0f8 ExpandBalancedS8Stream (count -> scan -> scatter)
    auto gen_stream=[&](int8_t* out, uint8_t* dSeed, uint32_t count, uint8_t domain){
        uint32_t nblk=count/31 + 64;
        stream_count<<<(nblk+T-1)/T,T,0,s>>>(dSeed,domain,dScratch,dCnt,nblk);
        thrust::exclusive_scan(thrust::cuda::par.on(s), dCnt, dCnt+nblk, dOff);
        stream_scatter<<<(nblk+T-1)/T,T,0,s>>>(dScratch,dOff,dCnt,out,nblk,count);
    };
    auto genop=[&](int8_t* d, uint8_t* sd, size_t cnt){
        if(wide) gen_stream(d,sd,(uint32_t)cnt,0x73);                               // bit-exact wide stream (f50f0f8)
        else     gen_operand<<<((uint32_t)cnt+T-1)/T,T,0,s>>>(d,sd,(uint32_t)cnt);  // legacy per-element (pre-fix)
    };
    auto launch_combine=[&](int32_t* P,int32_t* Q,uint64_t* C){ dim3 bl(CT,CT), gr((m+CT-1)/CT,(m+CT-1)/CT); combine_modq_tiled<<<gr,bl,0,s>>>(P,Q,C,m,n); };
    float t_gen=0,t_gemm=0,t_comb=0; double pw_sum=0; long pw_n=0;
    cudaEvent_t e0,e1,e2,e3; CK(cudaEventCreate(&e0));CK(cudaEventCreate(&e1));CK(cudaEventCreate(&e2));CK(cudaEventCreate(&e3));

    // ---- --emit: reproduce the reference digest for the FIXED seeds shared with
    //      `refcheck emit <n>`, for a byte-exact cross-check. ----
    if(emit){
        seed(dSeedA,0); seed(dSeedB,64); seed(dSeedU,128); seed(dSeedV,192);
        // bit-exact wide stream (matches f50f0f8); emit digest should equal the reference
        gen_stream(dA,dSeedA,nn,0x73); gen_stream(dB,dSeedB,nn,0x73);
        gen_stream(dU,dSeedU,mn,0x73); gen_stream(dV,dSeedV,nm,0x73);
        bool g1=int8_gemm(lt,s,ws,(size_t)32<<20,dU,dA,dP,m,n,n);
        bool g2=int8_gemm(lt,s,ws,(size_t)32<<20,dB,dV,dQ,n,m,n);
        if(!g1||!g2){printf("cublasLt INT8 unavailable\n");return 1;}
        launch_combine(dP,dQ,dChat);
        CK(cudaStreamSynchronize(s));
        std::vector<uint64_t> chat(mm); CK(cudaMemcpy(chat.data(),dChat,mm*8,cudaMemcpyDeviceToHost));
        int8_t a8[8]; CK(cudaMemcpy(a8,dA,8,cudaMemcpyDeviceToHost));
        std::vector<uint8_t> payload(mm*8);
        for(size_t i=0;i<mm;i++){uint64_t v=chat[i];for(int b=0;b<8;b++)payload[i*8+b]=(uint8_t)(v>>(8*b));}
        uint8_t sigma[32]; for(int i=0;i<32;i++) sigma[i]=(uint8_t)(32+i);
        uint8_t dig[32]; sketch_digest(sigma,payload.data(),payload.size(),dig);
        printf("GPU n=%u m=%u\n",n,m);
        printf("A[0..7] ="); for(int i=0;i<8;i++) printf(" %d",(int)a8[i]); printf("\n");
        printf("CHAT[0] =%llu\n",(unsigned long long)chat[0]);
        printf("DIGEST  ="); for(int i=0;i<32;i++) printf("%02x",dig[i]); printf("\n");
        return 0;
    }

    for(int it=0; it<nonces; ++it){
        // vary seeds per nonce (stand-in for nNonce64 changing the header)
        seed(dSeedA,1+it); seed(dSeedB,100+it); seed(dSeedU,50+it); seed(dSeedV,200+it);

        CK(cudaEventRecord(e0,s));
        genop(dA,dSeedA,nn); genop(dB,dSeedB,nn); genop(dU,dSeedU,mn); genop(dV,dSeedV,nm);
        CK(cudaEventRecord(e1,s));
        // P=U*A (M=m,K=n,N=n) ; Q=B*V (M=n,K=n,N=m)
        bool g1=int8_gemm(lt,s,ws,(size_t)32<<20,dU,dA,dP,m,n,n);
        bool g2=int8_gemm(lt,s,ws,(size_t)32<<20,dB,dV,dQ,n,m,n);
        if(!g1||!g2){printf("cublasLt INT8 unavailable; aborting perf\n");return 1;}
        CK(cudaEventRecord(e2,s));
        launch_combine(dP,dQ,dChat);
        CK(cudaEventRecord(e3,s));
        CK(cudaStreamSynchronize(s));
        float a,bb,c; CK(cudaEventElapsedTime(&a,e0,e1));CK(cudaEventElapsedTime(&bb,e1,e2));CK(cudaEventElapsedTime(&c,e2,e3));
        if(it>0){ t_gen+=a;t_gemm+=bb;t_comb+=c; // drop first (warmup)
            if(nvml_ok){ unsigned int mw; if(nvmlDeviceGetPowerUsage(nvdev,&mw)==NVML_SUCCESS){ pw_sum+=mw; pw_n++; } } }

        if(verify && it==0){
            gemm_scalar<<<(mn+T-1)/T,T,0,s>>>(dU,dA,dPs,m,n,n);
            gemm_scalar<<<(nm+T-1)/T,T,0,s>>>(dB,dV,dQs,n,m,n);
            launch_combine(dPs,dQs,dChatS);
            CK(cudaStreamSynchronize(s));
            std::vector<uint64_t> h1(mm),h2(mm);
            CK(cudaMemcpy(h1.data(),dChat,mm*8,cudaMemcpyDeviceToHost));
            CK(cudaMemcpy(h2.data(),dChatS,mm*8,cudaMemcpyDeviceToHost));
            size_t mism=0; for(size_t i=0;i<mm;i++) if(h1[i]!=h2[i]) mism++;
            printf("verify: cuBLASLt-vs-scalar Chat mismatches = %zu / %zu %s\n",mism,mm,mism?"FAIL":"OK");
        }
    }
    int N=nonces-1; if(N<1)N=1;
    t_gen/=N;t_gemm/=N;t_comb/=N; float tot=t_gen+t_gemm+t_comb;
    // wide stream yields ~31.4 accepted elements per SHA-256 block (+slack blocks)
    uint64_t sha = wide ? ((2ull*nn+2ull*mn)/31 + 256) : (2ull*nn+2ull*mn);
    uint64_t macs=2ull*nn*m;
    double nps=1000.0/tot;
    double avg_w=(nvml_ok && pw_n>0)?(pw_sum/pw_n/1000.0):0.0;
    double joules=avg_w*(tot/1000.0); // board joules per nonce
    printf("\n stage            ms/nonce   %%\n");
    printf(" 1 operand-gen(SHA) %7.3f  %5.1f%%   %.2f M SHA-256/nonce (%s)\n",t_gen,100*t_gen/tot,sha/1e6, wide?"wide XOF":"per-element");
    printf(" 2 INT8 GEMMs       %7.3f  %5.1f%%   %.2e MAC\n",t_gemm,100*t_gemm/tot,(double)macs);
    printf(" 3 Fq combine       %7.3f  %5.1f%%\n",t_comb,100*t_comb/tot);
    printf(" ------------------------------------------------\n");
    printf(" TOTAL              %7.3f            %.0f nonce/s\n",tot,nps);
    printf(" INT8 matmul share = %.1f%%   |   power = %.0f W   |   J/nonce = %.3f\n", 100*t_gemm/tot, avg_w, joules);
    // machine-parseable row for cross-GPU aggregation:
    // CSV,gpu,n,xof,sha_ms,gemm_ms,comb_ms,nonce_s,watts,joules_per_nonce,int8_pct
    printf("CSV,%s,%u,%s,%.4f,%.4f,%.4f,%.1f,%.1f,%.4f,%.2f\n",
           prop.name,n,wide?"wide":"legacy",t_gen,t_gemm,t_comb,nps,avg_w,joules,100.0*t_gemm/tot);
    if(nvml_ok) nvmlShutdown();
    return 0;
}
