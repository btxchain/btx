// Standalone safetensors -> device copy. Not linked into btxd.
// Copies raw tensor bytes. `--smoke` runs a kernel on the first tensor (xor twice,
// weights restored). `--hold` keeps allocations until SIGTERM/SIGINT.
// Does not mine or start a network inference server.
//
// Compile (default arch; operator may add -arch=sm_120):
//   nvcc -O2 -std=c++17 -o cuda_safetensors_load cuda_safetensors_load.cu
//
// Usage:
//   cuda_safetensors_load --dir <checkout> [--max-bytes N] [--hold] [--smoke]
//
// One JSON line on stdout. CUDA missing at runtime: {"ok":false,"error":"..."} and exit 2.
// Never prints a fake ok=true.

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <cuda_runtime.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <csignal>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

constexpr uint64_t kMaxHeader = 64ull * 1024ull * 1024ull;
constexpr size_t kChunk = 64ull * 1024ull * 1024ull;

struct Tensor {
    std::string name;
    std::string dtype;
    std::vector<uint64_t> shape;
    uint64_t begin = 0;
    uint64_t end = 0;
};

std::vector<void*> g_devs;
size_t g_first_nbytes = 0;
volatile sig_atomic_t g_stop = 0;

void on_term(int)
{
    g_stop = 1;
}

void free_device()
{
    for (void* p : g_devs) {
        if (p) cudaFree(p);
    }
    g_devs.clear();
    g_first_nbytes = 0;
}

__global__ void xor_smoke(unsigned char* p, size_t n, unsigned char k)
{
    const size_t i = static_cast<size_t>(blockIdx.x) * static_cast<size_t>(blockDim.x) + static_cast<size_t>(threadIdx.x);
    if (i < n) p[i] ^= k;
}

bool run_smoke(std::string& err)
{
    if (g_devs.empty() || !g_devs[0] || g_first_nbytes == 0) {
        err = "no device tensor for smoke";
        return false;
    }
    const size_t n = std::min(g_first_nbytes, static_cast<size_t>(1048576));
    const int threads = 256;
    const int blocks = static_cast<int>((n + static_cast<size_t>(threads) - 1) / static_cast<size_t>(threads));
    xor_smoke<<<blocks, threads>>>(static_cast<unsigned char*>(g_devs[0]), n, 0x5a);
    xor_smoke<<<blocks, threads>>>(static_cast<unsigned char*>(g_devs[0]), n, 0x5a);
    cudaError_t ce = cudaDeviceSynchronize();
    if (ce != cudaSuccess) {
        err = std::string("smoke sync: ") + cudaGetErrorString(ce);
        return false;
    }
    ce = cudaGetLastError();
    if (ce != cudaSuccess) {
        err = std::string("smoke kernel: ") + cudaGetErrorString(ce);
        return false;
    }
    return true;
}

std::string json_escape(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"': o += "\\\""; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", c);
                o += b;
            } else {
                o.push_back(static_cast<char>(c));
            }
        }
    }
    return o;
}

[[noreturn]] void emit_fail(int code, const std::string& error)
{
    free_device();
    std::printf("{\"ok\":false,\"error\":\"%s\"}\n", json_escape(error).c_str());
    std::fflush(stdout);
    std::exit(code);
}

bool path_has_dotdot(const fs::path& p)
{
    for (const auto& c : p) {
        if (c == "..") return true;
    }
    return false;
}

int dtype_item(const std::string& d)
{
    if (d == "BOOL" || d == "U8" || d == "I8" || d == "F8_E5M2" || d == "F8_E4M3" || d == "F8_E8M0") return 1;
    if (d == "U16" || d == "I16" || d == "F16" || d == "BF16") return 2;
    if (d == "U32" || d == "I32" || d == "F32") return 4;
    if (d == "U64" || d == "I64" || d == "F64") return 8;
    return 0;
}

void append_utf8(std::string& s, unsigned cp)
{
    if (cp <= 0x7f) {
        s.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
        s.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        s.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        s.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        s.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

struct Parser {
    const char* p = nullptr;
    const char* end = nullptr;
    std::string err;

    void fail(const std::string& m)
    {
        if (err.empty()) err = m;
    }

    void skip_ws()
    {
        while (p < end && std::isspace(static_cast<unsigned char>(*p))) ++p;
    }

    bool eat(char c)
    {
        skip_ws();
        if (p >= end || *p != c) {
            fail(std::string("expected '") + c + "'");
            return false;
        }
        ++p;
        return true;
    }

    bool eat_lit(const char* lit)
    {
        for (; *lit; ++lit) {
            if (p >= end || *p != *lit) {
                fail("bad literal");
                return false;
            }
            ++p;
        }
        return true;
    }

    bool parse_string(std::string& s)
    {
        if (!eat('"')) return false;
        s.clear();
        while (p < end) {
            unsigned char c = static_cast<unsigned char>(*p++);
            if (c == '"') return true;
            if (c == '\\') {
                if (p >= end) {
                    fail("truncated escape");
                    return false;
                }
                char e = *p++;
                switch (e) {
                case '"':
                case '\\':
                case '/': s.push_back(e); break;
                case 'b': s.push_back('\b'); break;
                case 'f': s.push_back('\f'); break;
                case 'n': s.push_back('\n'); break;
                case 'r': s.push_back('\r'); break;
                case 't': s.push_back('\t'); break;
                case 'u': {
                    if (p + 4 > end) {
                        fail("truncated unicode escape");
                        return false;
                    }
                    unsigned cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = *p++;
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp += static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') cp += static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp += static_cast<unsigned>(h - 'A' + 10);
                        else {
                            fail("bad unicode escape");
                            return false;
                        }
                    }
                    append_utf8(s, cp);
                    break;
                }
                default:
                    fail("bad escape");
                    return false;
                }
            } else if (c < 0x20) {
                fail("raw control in string");
                return false;
            } else {
                s.push_back(static_cast<char>(c));
            }
        }
        fail("unterminated string");
        return false;
    }

    bool skip_number()
    {
        if (p < end && *p == '-') ++p;
        if (p >= end || !std::isdigit(static_cast<unsigned char>(*p))) {
            fail("number");
            return false;
        }
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        if (p < end && *p == '.') {
            ++p;
            if (p >= end || !std::isdigit(static_cast<unsigned char>(*p))) {
                fail("fraction");
                return false;
            }
            while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            ++p;
            if (p < end && (*p == '+' || *p == '-')) ++p;
            if (p >= end || !std::isdigit(static_cast<unsigned char>(*p))) {
                fail("exponent");
                return false;
            }
            while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        }
        return true;
    }

    bool skip_value()
    {
        skip_ws();
        if (p >= end) {
            fail("missing value");
            return false;
        }
        const char c = *p;
        if (c == '"') {
            std::string discard;
            return parse_string(discard);
        }
        if (c == '{') return skip_object();
        if (c == '[') return skip_array();
        if (c == 't') return eat_lit("true");
        if (c == 'f') return eat_lit("false");
        if (c == 'n') return eat_lit("null");
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return skip_number();
        fail("bad value");
        return false;
    }

    bool skip_object()
    {
        if (!eat('{')) return false;
        skip_ws();
        if (p < end && *p == '}') {
            ++p;
            return true;
        }
        while (true) {
            std::string key;
            if (!parse_string(key)) return false;
            if (!eat(':')) return false;
            if (!skip_value()) return false;
            skip_ws();
            if (p < end && *p == '}') {
                ++p;
                return true;
            }
            if (!eat(',')) return false;
        }
    }

    bool skip_array()
    {
        if (!eat('[')) return false;
        skip_ws();
        if (p < end && *p == ']') {
            ++p;
            return true;
        }
        while (true) {
            if (!skip_value()) return false;
            skip_ws();
            if (p < end && *p == ']') {
                ++p;
                return true;
            }
            if (!eat(',')) return false;
        }
    }

    bool parse_u64(uint64_t& out)
    {
        skip_ws();
        if (p >= end || !std::isdigit(static_cast<unsigned char>(*p))) {
            fail("expected unsigned integer");
            return false;
        }
        uint64_t v = 0;
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) {
            const unsigned d = static_cast<unsigned>(*p - '0');
            if (v > (UINT64_MAX - d) / 10ull) {
                fail("integer overflow");
                return false;
            }
            v = v * 10ull + d;
            ++p;
        }
        if (p < end && (*p == '.' || *p == 'e' || *p == 'E')) {
            fail("tensor numbers must be integers");
            return false;
        }
        out = v;
        return true;
    }

    bool parse_u64_array(std::vector<uint64_t>& out)
    {
        if (!eat('[')) return false;
        out.clear();
        skip_ws();
        if (p < end && *p == ']') {
            ++p;
            return true;
        }
        while (true) {
            uint64_t n = 0;
            if (!parse_u64(n)) return false;
            out.push_back(n);
            skip_ws();
            if (p < end && *p == ']') {
                ++p;
                return true;
            }
            if (!eat(',')) return false;
        }
    }

    bool parse_tensor(const std::string& name, std::vector<Tensor>& tensors)
    {
        if (!eat('{')) return false;
        std::string dtype;
        std::vector<uint64_t> shape;
        uint64_t begin = 0;
        uint64_t end_off = 0;
        bool have_dtype = false;
        bool have_shape = false;
        bool have_off = false;
        skip_ws();
        if (p < end && *p == '}') {
            fail("tensor " + name + " missing dtype/shape/data_offsets");
            return false;
        }
        while (true) {
            std::string key;
            if (!parse_string(key)) return false;
            if (!eat(':')) return false;
            if (key == "dtype") {
                if (!parse_string(dtype)) return false;
                have_dtype = true;
            } else if (key == "shape") {
                if (!parse_u64_array(shape)) return false;
                have_shape = true;
            } else if (key == "data_offsets") {
                std::vector<uint64_t> offs;
                if (!parse_u64_array(offs)) return false;
                if (offs.size() != 2) {
                    fail("data_offsets must be [begin, end] for " + name);
                    return false;
                }
                begin = offs[0];
                end_off = offs[1];
                have_off = true;
            } else if (!skip_value()) {
                return false;
            }
            skip_ws();
            if (p < end && *p == '}') {
                ++p;
                break;
            }
            if (!eat(',')) return false;
        }
        if (!have_dtype || !have_shape || !have_off) {
            fail("tensor " + name + " missing dtype/shape/data_offsets");
            return false;
        }
        if (end_off < begin) {
            fail("data_offsets inverted for " + name);
            return false;
        }
        Tensor t;
        t.name = name;
        t.dtype = dtype;
        t.shape = std::move(shape);
        t.begin = begin;
        t.end = end_off;
        tensors.push_back(std::move(t));
        return true;
    }

    bool parse_header(std::vector<Tensor>& tensors)
    {
        if (!eat('{')) return false;
        skip_ws();
        if (p < end && *p == '}') {
            ++p;
        } else {
            while (p < end) {
                std::string key;
                if (!parse_string(key)) return false;
                if (!eat(':')) return false;
                if (key == "__metadata__") {
                    if (!skip_value()) return false;
                } else if (!parse_tensor(key, tensors)) {
                    return false;
                }
                skip_ws();
                if (p < end && *p == '}') {
                    ++p;
                    break;
                }
                if (!eat(',')) return false;
            }
        }
        skip_ws();
        if (p != end) {
            fail("trailing junk after safetensors header");
            return false;
        }
        return err.empty();
    }
};

bool spans_match(const Tensor& t, uint64_t data_len, std::string& err)
{
    if (t.end < t.begin || t.end > data_len) {
        err = "data_offsets out of range for " + t.name;
        return false;
    }
    const uint64_t nbytes = t.end - t.begin;
    const int item = dtype_item(t.dtype);
    if (item <= 0) return true;
    bool zero = false;
    uint64_t prod = 1;
    for (uint64_t d : t.shape) {
        if (d == 0) {
            zero = true;
            continue;
        }
        if (prod > UINT64_MAX / d) {
            err = "shape overflow for " + t.name;
            return false;
        }
        prod *= d;
    }
    uint64_t expect = 0;
    if (!zero) {
        if (prod > UINT64_MAX / static_cast<uint64_t>(item)) {
            err = "shape overflow for " + t.name;
            return false;
        }
        expect = prod * static_cast<uint64_t>(item);
    }
    if (expect != nbytes) {
        err = "dtype/shape does not match data_offsets for " + t.name;
        return false;
    }
    return true;
}

bool copy_to_device(int fd, const unsigned char* mapped, uint64_t file_off, uint64_t nbytes, std::string& err)
{
    if (nbytes == 0) return true;
    if (nbytes > static_cast<uint64_t>(SIZE_MAX)) {
        err = "tensor larger than address space";
        return false;
    }
    void* dev = nullptr;
    cudaError_t e = cudaMalloc(&dev, static_cast<size_t>(nbytes));
    if (e != cudaSuccess || !dev) {
        err = std::string("cudaMalloc: ") + cudaGetErrorString(e);
        return false;
    }
    if (mapped) {
        e = cudaMemcpy(dev, mapped + file_off, static_cast<size_t>(nbytes), cudaMemcpyHostToDevice);
        if (e != cudaSuccess) {
            cudaFree(dev);
            err = std::string("cudaMemcpy: ") + cudaGetErrorString(e);
            return false;
        }
    } else {
        std::vector<unsigned char> buf(kChunk);
        uint64_t done = 0;
        while (done < nbytes) {
            const uint64_t remain = nbytes - done;
            const size_t n = static_cast<size_t>(remain < static_cast<uint64_t>(kChunk) ? remain : static_cast<uint64_t>(kChunk));
            const ssize_t r = pread(fd, buf.data(), n, static_cast<off_t>(file_off + done));
            if (r < 0 || static_cast<size_t>(r) != n) {
                cudaFree(dev);
                err = "pread of tensor bytes failed";
                return false;
            }
            e = cudaMemcpy(static_cast<unsigned char*>(dev) + done, buf.data(), n, cudaMemcpyHostToDevice);
            if (e != cudaSuccess) {
                cudaFree(dev);
                err = std::string("cudaMemcpy: ") + cudaGetErrorString(e);
                return false;
            }
            done += n;
        }
    }
    if (g_devs.empty()) g_first_nbytes = static_cast<size_t>(nbytes);
    g_devs.push_back(dev);
    return true;
}

bool load_file(const fs::path& path, const uint64_t* max_bytes, uint64_t& bytes_on_device, uint64_t& tensors, bool& stopped, std::string& err)
{
    if (path_has_dotdot(path)) {
        err = "refusing path with ..";
        return false;
    }
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        err = "open failed: " + path.filename().string();
        return false;
    }
    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        err = "not a regular file: " + path.filename().string();
        return false;
    }
    const uint64_t file_size = static_cast<uint64_t>(st.st_size);
    unsigned char lenb[8];
    if (file_size < 8 || pread(fd, lenb, 8, 0) != 8) {
        close(fd);
        err = "short safetensors file: " + path.filename().string();
        return false;
    }
    uint64_t header_len = 0;
    for (int i = 0; i < 8; ++i) header_len |= static_cast<uint64_t>(lenb[i]) << (8 * i);
    if (header_len == 0 || header_len > kMaxHeader) {
        close(fd);
        err = (header_len > kMaxHeader ? "safetensors header exceeds 64MiB cap: " : "empty safetensors header: ") + path.filename().string();
        return false;
    }
    if (file_size < 8 + header_len) {
        close(fd);
        err = "safetensors header past EOF: " + path.filename().string();
        return false;
    }
    std::string json(static_cast<size_t>(header_len), '\0');
    if (pread(fd, json.data(), static_cast<size_t>(header_len), 8) != static_cast<ssize_t>(header_len)) {
        close(fd);
        err = "short safetensors header read: " + path.filename().string();
        return false;
    }
    Parser parser;
    parser.p = json.data();
    parser.end = json.data() + json.size();
    std::vector<Tensor> found;
    if (!parser.parse_header(found)) {
        close(fd);
        err = path.filename().string() + ": " + (parser.err.empty() ? "bad safetensors header" : parser.err);
        return false;
    }
    const uint64_t data_base = 8 + header_len;
    const uint64_t data_len = file_size - data_base;
    for (const Tensor& t : found) {
        if (!spans_match(t, data_len, err)) {
            close(fd);
            err = path.filename().string() + ": " + err;
            return false;
        }
    }
    void* mapped = MAP_FAILED;
    if (file_size > 0 && file_size <= static_cast<uint64_t>(SIZE_MAX)) {
        mapped = mmap(nullptr, static_cast<size_t>(file_size), PROT_READ, MAP_PRIVATE, fd, 0);
    }
    const unsigned char* bytes = mapped == MAP_FAILED ? nullptr : static_cast<const unsigned char*>(mapped);
    bool ok = true;
    for (const Tensor& t : found) {
        const uint64_t nbytes = t.end - t.begin;
        if (max_bytes && bytes_on_device + nbytes > *max_bytes) {
            if (bytes_on_device == 0) {
                err = "tensor exceeds --max-bytes";
                ok = false;
            } else {
                stopped = true;
            }
            break;
        }
        if (!copy_to_device(fd, bytes, data_base + t.begin, nbytes, err)) {
            ok = false;
            break;
        }
        bytes_on_device += nbytes;
        tensors += 1;
    }
    if (mapped != MAP_FAILED) munmap(mapped, static_cast<size_t>(file_size));
    close(fd);
    return ok;
}

bool collect_files(const fs::path& root, std::vector<fs::path>& files, std::string& err)
{
    std::error_code ec;
    const auto root_st = fs::symlink_status(root, ec);
    if (ec || !fs::is_directory(root_st)) {
        err = "checkout is not a directory";
        return false;
    }
    if (fs::is_symlink(root_st)) {
        err = "refusing symlink checkout";
        return false;
    }
    fs::recursive_directory_iterator it(root, fs::directory_options::none, ec);
    if (ec) {
        err = "cannot list checkout";
        return false;
    }
    const fs::recursive_directory_iterator end;
    while (it != end) {
        std::error_code sec;
        const auto lst = it->symlink_status(sec);
        if (sec || fs::is_symlink(lst)) {
            it.disable_recursion_pending();
        } else if (fs::is_regular_file(lst)) {
            const fs::path p = it->path();
            if (path_has_dotdot(p)) {
                err = "refusing path with ..";
                return false;
            }
            const std::string name = p.filename().string();
            if (name.size() >= 12 && name.compare(name.size() - 12, 12, ".safetensors") == 0) {
                files.push_back(p);
            }
        }
        it.increment(ec);
        if (ec) {
            err = "cannot list checkout";
            return false;
        }
    }
    std::sort(files.begin(), files.end());
    return true;
}

bool parse_max_bytes(const char* s, uint64_t& out, std::string& err)
{
    if (!s || !*s) {
        err = "--max-bytes requires a number";
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s, &end, 10);
    if (end == s || *end || errno) {
        err = "bad --max-bytes";
        return false;
    }
    out = static_cast<uint64_t>(v);
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    const char* dir_arg = nullptr;
    const uint64_t* max_ptr = nullptr;
    uint64_t max_bytes = 0;
    bool have_max = false;
    bool hold = false;
    bool smoke = false;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (std::strcmp(a, "--help") == 0) {
            std::fprintf(stderr, "cuda_safetensors_load --dir <checkout> [--max-bytes N] [--hold] [--smoke]\n");
            return 0;
        }
        if (std::strcmp(a, "--dir") == 0) {
            if (i + 1 >= argc) emit_fail(1, "--dir requires a path");
            dir_arg = argv[++i];
        } else if (std::strncmp(a, "--dir=", 6) == 0) {
            dir_arg = a + 6;
        } else if (std::strcmp(a, "--max-bytes") == 0) {
            if (i + 1 >= argc) emit_fail(1, "--max-bytes requires a number");
            std::string err;
            if (!parse_max_bytes(argv[++i], max_bytes, err)) emit_fail(1, err);
            have_max = true;
        } else if (std::strncmp(a, "--max-bytes=", 12) == 0) {
            std::string err;
            if (!parse_max_bytes(a + 12, max_bytes, err)) emit_fail(1, err);
            have_max = true;
        } else if (std::strcmp(a, "--hold") == 0) {
            hold = true;
        } else if (std::strcmp(a, "--smoke") == 0) {
            smoke = true;
        } else {
            emit_fail(1, std::string("unknown argument: ") + a);
        }
    }
    if (!dir_arg || !*dir_arg) emit_fail(1, "--dir is required");
    fs::path dir(dir_arg);
    if (path_has_dotdot(dir)) emit_fail(1, "refusing path with ..");
    if (have_max) max_ptr = &max_bytes;

    std::string err;
    std::vector<fs::path> files;
    if (!collect_files(dir, files, err)) emit_fail(1, err);
    if (files.empty()) emit_fail(1, "no safetensors files");

    int ndev = 0;
    cudaError_t ce = cudaGetDeviceCount(&ndev);
    if (ce != cudaSuccess || ndev < 1) {
        const char* why = ce != cudaSuccess ? cudaGetErrorString(ce) : "no device";
        emit_fail(2, std::string("CUDA missing: ") + why);
    }
    ce = cudaSetDevice(0);
    if (ce != cudaSuccess) emit_fail(2, std::string("CUDA missing: ") + cudaGetErrorString(ce));

    cudaDeviceProp prop{};
    ce = cudaGetDeviceProperties(&prop, 0);
    if (ce != cudaSuccess) emit_fail(2, std::string("CUDA missing: ") + cudaGetErrorString(ce));
    int cuda_driver = 0;
    ce = cudaDriverGetVersion(&cuda_driver);
    if (ce != cudaSuccess) emit_fail(2, std::string("CUDA missing: ") + cudaGetErrorString(ce));

    uint64_t bytes_on_device = 0;
    uint64_t tensors = 0;
    uint64_t files_done = 0;
    bool stopped = false;
    for (const fs::path& f : files) {
        if (stopped) break;
        if (!load_file(f, max_ptr, bytes_on_device, tensors, stopped, err)) emit_fail(1, err);
        files_done += 1;
    }
    if (tensors == 0 || bytes_on_device == 0) emit_fail(1, "no tensor bytes copied to device");

    bool smoke_passed = false;
    if (smoke || hold) {
        std::string serr;
        if (!run_smoke(serr)) emit_fail(1, serr);
        smoke_passed = true;
    }

    std::printf("{\"ok\":true,\"device_name\":\"%s\",\"tensors\":%llu,\"bytes_on_device\":%llu,\"files\":%llu,\"cuda_driver\":%d,\"resident\":%s,\"hold\":%s,\"smoke_passed\":%s,\"smoke\":\"%s\"}\n",
                json_escape(prop.name).c_str(),
                static_cast<unsigned long long>(tensors),
                static_cast<unsigned long long>(bytes_on_device),
                static_cast<unsigned long long>(files_done),
                cuda_driver,
                hold ? "true" : "false",
                hold ? "true" : "false",
                smoke_passed ? "true" : "false",
                smoke_passed ? "kernel" : "");
    std::fflush(stdout);
    if (hold) {
        std::signal(SIGTERM, on_term);
        std::signal(SIGINT, on_term);
        std::signal(SIGHUP, on_term);
        while (!g_stop) pause();
    }
    free_device();
    return 0;
}
