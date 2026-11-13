// Isolated CUDA qualification worker. NOT linked into btxd or test_btx.
// GPU-01..06: tiny kernel, explicit device, finite timeout, no wallet/network.
// Tiny alloc. Does not starve ExactReplay. Set BTX_LIVE_ATTESTOR=1 to refuse.
// ISO-05 FIT (--granite-bytes): model MiB + reserve MiB must fit in total MiB
// minus the observed ExactReplay footprint. The reserve defaults to 4096 MiB.
// A lower --reserve-mib is an operator override and never prints
// CUDA_GRANITE_FIT PASS.
#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <signal.h>

__global__ void ping(int* x) { *x = 42; }

static constexpr long long DEFAULT_RESERVE_MIB = 4096;
static constexpr long long EXACTREPLAY_OBSERVED_MIB = 3382;
static constexpr long long MAX_GRANITE_BYTES = 1LL << 50;
static constexpr long long MAX_RESERVE_MIB = 1LL << 20;

static void die(const char* m) {
    std::fprintf(stderr, "cuda_qual_worker FAIL: %s\n", m);
    std::exit(1);
}

// Decimal digits only: no sign, no suffix, no overflow past max.
static bool ParseCount(const char* s, long long max, long long& out)
{
    if (*s == '\0') return false;
    long long v = 0;
    for (; *s != '\0'; ++s) {
        if (*s < '0' || *s > '9') return false;
        const int d = *s - '0';
        if (v > (max - d) / 10) return false;
        v = v * 10 + d;
    }
    out = v;
    return true;
}

int main(int argc, char** argv)
{
    alarm(8); // GPU-04 finite execution
    int gpu = -1;
    bool allow_shared = false;
    bool allow_validator = false;
    long long granite = 0;
    long long reserve_mib = DEFAULT_RESERVE_MIB;
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--gpu=", 6) == 0) gpu = std::atoi(argv[i] + 6);
        else if (std::strcmp(argv[i], "--allow-shared-gpu") == 0) allow_shared = true;
        else if (std::strcmp(argv[i], "--allow-validator-gpu") == 0) allow_validator = true;
        else if (std::strncmp(argv[i], "--granite-bytes=", 16) == 0) {
            if (!ParseCount(argv[i] + 16, MAX_GRANITE_BYTES, granite)) {
                std::fprintf(stderr, "ISO-05: --granite-bytes must be a decimal byte count up to 2^50\n");
                return 2;
            }
        } else if (std::strncmp(argv[i], "--reserve-mib=", 14) == 0) {
            if (!ParseCount(argv[i] + 14, MAX_RESERVE_MIB, reserve_mib)) {
                std::fprintf(stderr, "ISO-05: --reserve-mib must be a decimal MiB count up to 1048576\n");
                return 2;
            }
        } else if (std::strcmp(argv[i], "--help") == 0) {
            std::puts("cuda_qual_worker --gpu=N [--allow-shared-gpu] [--allow-validator-gpu]\n"
                      "                 [--granite-bytes=BYTES [--reserve-mib=MIB]]\n"
                      "ISO-05 FIT: BYTES/MiB + MIB <= total MiB - 3382 (observed ExactReplay).\n"
                      "--reserve-mib defaults to 4096. A lower value is an operator override:\n"
                      "ISO-05 OVERRIDE_FIT and CUDA_GRANITE_FIT OVERRIDE_PASS, never PASS.");
            return 0;
        }
    }
    if (const char* live = std::getenv("BTX_LIVE_ATTESTOR")) {
        if (live[0] && std::strcmp(live, "0") != 0 && !allow_shared) {
            die("refuse live attestor GPU (BTX_LIVE_ATTESTOR)");
        }
    }
    if (gpu < 0) {
        std::fprintf(stderr, "GPU-02: operator must set --gpu (does not inherit validator GPU)\n");
        return 2;
    }
    if (gpu == 0 && !allow_validator && !allow_shared) {
        std::fprintf(stderr, "GPU-02: refusing validator/mining GPU 0 without --allow-shared-gpu\n");
        return 2;
    }
    int ndev = 0;
    cudaError_t e = cudaGetDeviceCount(&ndev);
    if (e != cudaSuccess) die(cudaGetErrorString(e));
    if (gpu >= ndev) {
        std::fprintf(stderr, "GPU-02: gpu %d >= device count %d (fail before alloc)\n", gpu, ndev);
        return 2;
    }
    e = cudaSetDevice(gpu);
    if (e != cudaSuccess) die(cudaGetErrorString(e));
    int* d = nullptr;
    e = cudaMalloc(&d, sizeof(int));
    if (e != cudaSuccess) die(cudaGetErrorString(e));
    ping<<<1, 1>>>(d);
    e = cudaDeviceSynchronize();
    if (e != cudaSuccess) {
        cudaFree(d);
        die(cudaGetErrorString(e));
    }
    int h = 0;
    cudaMemcpy(&h, d, sizeof(int), cudaMemcpyDeviceToHost);
    cudaFree(d);
    if (h != 42) die("kernel result");
    cudaDeviceProp prop{};
    cudaGetDeviceProperties(&prop, gpu);
    std::printf("GPU-01 RUNTIME_OBSERVED backend=cuda device=%d name=%s sm=%d.%d mem_mb=%zu result=42\n",
                gpu, prop.name, prop.major, prop.minor, prop.totalGlobalMem / (1024 * 1024));
    std::printf("GPU-03 isolation: no wallet, no RPC cookie, no listen socket\n");
    std::printf("GPU-06 backend_hash_observation cuda/%s/%d.%d\n", prop.name, prop.major, prop.minor);
    if (granite > 0) {
        const long long free_mib = (long long)(prop.totalGlobalMem / (1024 * 1024)) - EXACTREPLAY_OBSERVED_MIB;
        const long long need_mib = granite / (1024 * 1024) + reserve_mib;
        if (need_mib > free_mib) {
            std::printf("ISO-05 REFUSE starve ExactReplay need_mib=%lld free_mib=%lld reserve_mib=%lld "
                        "default_reserve_mib=%lld\n",
                        need_mib, free_mib, reserve_mib, DEFAULT_RESERVE_MIB);
            std::printf("CUDA_GRANITE_FIT REFUSED\n");
        } else if (reserve_mib < DEFAULT_RESERVE_MIB) {
            std::printf("ISO-05 OVERRIDE_FIT granite_bytes=%lld need_mib=%lld free_mib=%lld reserve_mib=%lld "
                        "default_reserve_mib=%lld\n",
                        granite, need_mib, free_mib, reserve_mib, DEFAULT_RESERVE_MIB);
            std::printf("CUDA_GRANITE_FIT OVERRIDE_PASS (reserve below default; not release qualification)\n");
        } else {
            std::printf("ISO-05 FIT granite_bytes=%lld need_mib=%lld free_mib=%lld reserve_mib=%lld\n",
                        granite, need_mib, free_mib, reserve_mib);
            std::printf("CUDA_GRANITE_FIT PASS\n");
        }
    }
    std::printf("CUDA_QUAL_WORKER PASS\n");
    return 0;
}
