// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/training_launch.h>

#include <modelnet/git_snapshot.h>

#include <crypto/sha384.h>

#include <cstring>
#include <string>
#include <vector>

namespace modelnet {
namespace {

constexpr int kVocab = 256;
constexpr int kCtx = 64;
constexpr int kWidth = 64;
constexpr int kHeads = 4;
constexpr int kHead = kWidth / kHeads;
constexpr int kFf = 128;
constexpr int kLayers = 2;
constexpr int kScale = 32;

constexpr int kEmbedN = kVocab * kWidth;
constexpr int kPosN = kCtx * kWidth;
constexpr int kQn = kWidth * kWidth;
constexpr int kFf1 = kWidth * kFf;
constexpr int kFf2 = kFf * kWidth;
constexpr int kLayerN = 4 * kQn + kFf1 + kFf2;
constexpr int kOutN = kWidth * kVocab;
constexpr int kEmbed = 0;
constexpr int kPos = kEmbedN;
constexpr int kLayer0 = kPos + kPosN;
constexpr int kOut = kLayer0 + kLayers * kLayerN;
constexpr int kTotal = kOut + kOutN;

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

std::string HexLower(const unsigned char* data, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

int32_t Clamp(int64_t value, int32_t limit)
{
    if (value > limit) return limit;
    if (value < -static_cast<int64_t>(limit)) return -limit;
    return static_cast<int32_t>(value);
}

const unsigned char* Corpus(unsigned& n)
{
#include <modelnet/launch_corpus.inc>
    n = kLaunchCorpusBytes;
    return kLaunchCorpus;
}

bool CorpusLocked(std::string& err)
{
    unsigned n = 0;
    const unsigned char* bytes = Corpus(n);
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    CSHA384().Write(bytes, n).Finalize(hash);
    if (HexLower(hash, sizeof(hash)) != LAUNCH_CORPUS_SHA384) return Fail(err, "BTX035_ID_MISMATCH");
    err.clear();
    return true;
}

void InitWeights(std::vector<int32_t>& weights)
{
    weights.assign(kTotal, 0);
    for (int i = 0; i < kTotal; ++i) {
        uint32_t mix = 0x9E3779B9u * static_cast<uint32_t>(i + 1);
        mix ^= mix >> 16;
        weights[i] = static_cast<int32_t>(mix % 5u) - 2;
    }
}

std::string WeightHash(const std::vector<int32_t>& weights)
{
    std::vector<unsigned char> bytes(static_cast<size_t>(kTotal) * 4);
    for (int i = 0; i < kTotal; ++i) {
        const uint32_t raw = static_cast<uint32_t>(weights[i]);
        bytes[static_cast<size_t>(i) * 4] = static_cast<unsigned char>(raw);
        bytes[static_cast<size_t>(i) * 4 + 1] = static_cast<unsigned char>(raw >> 8);
        bytes[static_cast<size_t>(i) * 4 + 2] = static_cast<unsigned char>(raw >> 16);
        bytes[static_cast<size_t>(i) * 4 + 3] = static_cast<unsigned char>(raw >> 24);
    }
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    CSHA384().Write(bytes.data(), bytes.size()).Finalize(hash);
    return HexLower(hash, sizeof(hash));
}

std::string StateHash(const LaunchCheckpoint& state)
{
    const std::string text = std::string(LAUNCH_PROFILE) + "\n" + LAUNCH_CORPUS_SHA384 + "\n" +
                             std::to_string(state.step) + "\n" + std::to_string(state.cursor) + "\n" + state.rng + "\n" +
                             state.optimizer + "\n" + state.weight_hash + "\n" + std::to_string(state.hits) + "\n" +
                             std::to_string(state.miss_mass);
    unsigned char hash[CSHA384::OUTPUT_SIZE];
    CSHA384().Write(reinterpret_cast<const unsigned char*>(text.data()), text.size()).Finalize(hash);
    return HexLower(hash, sizeof(hash));
}

int64_t ExpWeight(int delta)
{
    static const int kExp[9] = {256, 696, 1892, 5142, 13977, 37995, 103285, 280739, 763052};
    int k = -delta;
    if (k < 0) k = 0;
    if (k > 8) k = 8;
    if (k == 0) return 256;
    return (256ll * 256) / kExp[k];
}

void Project(const int32_t* matrix, int rows, int cols, const int32_t* in, int32_t* out)
{
    for (int row = 0; row < rows; ++row) {
        int64_t acc = 0;
        const int32_t* w = matrix + static_cast<size_t>(row) * cols;
        for (int col = 0; col < cols; ++col) acc += static_cast<int64_t>(w[col]) * in[col];
        out[row] = Clamp(acc / kScale, 4096);
    }
}

void ProjectGrad(const int32_t* matrix, int rows, int cols, const int32_t* in, const int32_t* d_out,
                 int32_t* d_in, int32_t* d_matrix)
{
    for (int col = 0; col < cols; ++col) d_in[col] = 0;
    for (int row = 0; row < rows; ++row) {
        const int32_t* w = matrix + static_cast<size_t>(row) * cols;
        int32_t* dw = d_matrix + static_cast<size_t>(row) * cols;
        for (int col = 0; col < cols; ++col) {
            dw[col] = Clamp(dw[col] + (static_cast<int64_t>(d_out[row]) * in[col]) / kScale, 64);
            d_in[col] = Clamp(d_in[col] + (static_cast<int64_t>(w[col]) * d_out[row]) / kScale, 4096);
        }
    }
}

void Normalize(const int32_t* in, int32_t* out, int32_t& denom)
{
    int64_t acc = 1;
    for (int i = 0; i < kWidth; ++i) acc += in[i] < 0 ? -static_cast<int64_t>(in[i]) : in[i];
    denom = static_cast<int32_t>(acc / kWidth);
    if (denom < 1) denom = 1;
    for (int i = 0; i < kWidth; ++i) out[i] = Clamp((static_cast<int64_t>(in[i]) * kScale) / denom, 4096);
}

bool Step(std::vector<int32_t>& weights, uint64_t cursor, int64_t& hits, int64_t& miss, std::string& err)
{
    unsigned corpus_n = 0;
    const unsigned char* corpus = Corpus(corpus_n);
    if (corpus_n < static_cast<unsigned>(kCtx + 1) || static_cast<int>(weights.size()) != kTotal) {
        return Fail(err, "BTX035_PROFILE");
    }
    int32_t token[kCtx];
    for (int i = 0; i < kCtx; ++i) token[i] = corpus[(cursor + static_cast<uint64_t>(i)) % corpus_n];
    const int target = corpus[(cursor + static_cast<uint64_t>(kCtx)) % corpus_n];

    int32_t resid[kCtx][kWidth];
    for (int t = 0; t < kCtx; ++t) {
        const int32_t* emb = weights.data() + kEmbed + token[t] * kWidth;
        const int32_t* pos = weights.data() + kPos + t * kWidth;
        for (int d = 0; d < kWidth; ++d) resid[t][d] = Clamp(static_cast<int64_t>(emb[d]) + pos[d], 4096);
    }

    int32_t grad[kTotal];
    std::memset(grad, 0, sizeof(grad));
    int32_t d_resid[kCtx][kWidth];
    std::memset(d_resid, 0, sizeof(d_resid));

    int32_t norm[kLayers][kCtx][kWidth];
    int32_t denom[kLayers][kCtx];
    int32_t query[kLayers][kCtx][kWidth];
    int32_t key[kLayers][kCtx][kWidth];
    int32_t value[kLayers][kCtx][kWidth];
    int32_t mixed[kLayers][kCtx][kWidth];
    int32_t attn[kLayers][kCtx][kCtx];
    int32_t hidden[kLayers][kCtx][kFf];

    for (int layer = 0; layer < kLayers; ++layer) {
        const int32_t* base = weights.data() + kLayer0 + layer * kLayerN;
        for (int t = 0; t < kCtx; ++t) {
            Normalize(resid[t], norm[layer][t], denom[layer][t]);
            Project(base + 0 * kQn, kWidth, kWidth, norm[layer][t], query[layer][t]);
            Project(base + 1 * kQn, kWidth, kWidth, norm[layer][t], key[layer][t]);
            Project(base + 2 * kQn, kWidth, kWidth, norm[layer][t], value[layer][t]);
        }
        for (int t = 0; t < kCtx; ++t) {
            int32_t mx = -8;
            int32_t score[kCtx];
            for (int s = 0; s <= t; ++s) {
                int64_t dot = 0;
                for (int d = 0; d < kWidth; ++d) {
                    dot += static_cast<int64_t>(query[layer][t][d]) * key[layer][s][d];
                }
                score[s] = Clamp(dot / kHead, 8);
                if (score[s] > mx) mx = score[s];
            }
            int64_t den = 0;
            int64_t wt[kCtx];
            for (int s = 0; s <= t; ++s) {
                int delta = score[s] - mx;
                if (delta < -8) delta = -8;
                wt[s] = ExpWeight(delta);
                den += wt[s];
            }
            if (den < 1) den = 1;
            for (int s = 0; s < kCtx; ++s) attn[layer][t][s] = 0;
            for (int s = 0; s <= t; ++s) attn[layer][t][s] = static_cast<int32_t>((wt[s] * 256) / den);
            int32_t ctxv[kWidth];
            for (int d = 0; d < kWidth; ++d) {
                int64_t acc = 0;
                for (int s = 0; s <= t; ++s) acc += static_cast<int64_t>(attn[layer][t][s]) * value[layer][s][d];
                ctxv[d] = Clamp(acc / 256, 4096);
            }
            int32_t attended[kWidth];
            Project(base + 3 * kQn, kWidth, kWidth, ctxv, attended);
            for (int d = 0; d < kWidth; ++d) mixed[layer][t][d] = Clamp(static_cast<int64_t>(resid[t][d]) + attended[d], 4096);
            int32_t ff_in[kWidth];
            int32_t ff_den = 0;
            Normalize(mixed[layer][t], ff_in, ff_den);
            denom[layer][t] = ff_den;
            Project(base + 4 * kQn, kFf, kWidth, ff_in, hidden[layer][t]);
            for (int h = 0; h < kFf; ++h) {
                if (hidden[layer][t][h] < 0) hidden[layer][t][h] = 0;
            }
            int32_t ff_out[kWidth];
            Project(base + 4 * kQn + kFf1, kWidth, kFf, hidden[layer][t], ff_out);
            for (int d = 0; d < kWidth; ++d) {
                resid[t][d] = Clamp(static_cast<int64_t>(mixed[layer][t][d]) + ff_out[d], 4096);
            }
        }
    }

    int32_t logit[kVocab];
    Project(weights.data() + kOut, kVocab, kWidth, resid[kCtx - 1], logit);
    int32_t mx = logit[0];
    for (int i = 1; i < kVocab; ++i) {
        if (logit[i] > mx) mx = logit[i];
    }
    int64_t den = 0;
    int64_t wt[kVocab];
    for (int i = 0; i < kVocab; ++i) {
        int delta = logit[i] - mx;
        if (delta < -8) delta = -8;
        if (delta > 0) delta = 0;
        wt[i] = ExpWeight(delta);
        den += wt[i];
    }
    if (den < 1) den = 1;
    int best = 0;
    int32_t best_p = -1;
    int32_t d_logit[kVocab];
    for (int i = 0; i < kVocab; ++i) {
        const int32_t prob = static_cast<int32_t>((wt[i] * 256) / den);
        if (prob > best_p) {
            best_p = prob;
            best = i;
        }
        d_logit[i] = Clamp(prob - (i == target ? 256 : 0), 4096);
    }
    if (best == target) ++hits;
    const int32_t target_prob = static_cast<int32_t>((wt[target] * 256) / den);
    miss += 256 - target_prob;

    int32_t d_last[kWidth];
    int32_t d_out_row[kOutN];
    std::memset(d_out_row, 0, sizeof(d_out_row));
    ProjectGrad(weights.data() + kOut, kVocab, kWidth, resid[kCtx - 1], d_logit, d_last, d_out_row);
    for (int i = 0; i < kOutN; ++i) grad[kOut + i] = d_out_row[i];
    for (int d = 0; d < kWidth; ++d) d_resid[kCtx - 1][d] = d_last[d];

    for (int layer = kLayers - 1; layer >= 0; --layer) {
        const int32_t* base = weights.data() + kLayer0 + layer * kLayerN;
        int32_t* d_base = grad + kLayer0 + layer * kLayerN;
        for (int t = kCtx - 1; t >= 0; --t) {
            int32_t d_h[kFf];
            int32_t d_ff_in[kWidth];
            std::memset(d_h, 0, sizeof(d_h));
            ProjectGrad(base + 4 * kQn + kFf1, kWidth, kFf, hidden[layer][t], d_resid[t], d_h, d_base + 4 * kQn + kFf1);
            for (int h = 0; h < kFf; ++h) {
                if (hidden[layer][t][h] == 0) d_h[h] = 0;
            }
            int32_t ff_in[kWidth];
            int32_t ignored = 0;
            Normalize(mixed[layer][t], ff_in, ignored);
            ProjectGrad(base + 4 * kQn, kFf, kWidth, ff_in, d_h, d_ff_in, d_base + 4 * kQn);
            for (int d = 0; d < kWidth; ++d) {
                d_resid[t][d] = Clamp(static_cast<int64_t>(d_resid[t][d]) + (static_cast<int64_t>(d_ff_in[d]) * kScale) / denom[layer][t], 4096);
            }
        }
    }

    for (int t = 0; t < kCtx; ++t) {
        int32_t* d_emb = grad + kEmbed + token[t] * kWidth;
        int32_t* d_pos = grad + kPos + t * kWidth;
        for (int d = 0; d < kWidth; ++d) {
            d_emb[d] = Clamp(static_cast<int64_t>(d_emb[d]) + d_resid[t][d], 64);
            d_pos[d] = Clamp(static_cast<int64_t>(d_pos[d]) + d_resid[t][d], 64);
        }
    }
    for (int i = 0; i < kTotal; ++i) {
        const int32_t g = Clamp(grad[i], 4);
        weights[i] = Clamp(static_cast<int64_t>(weights[i]) - g, 64);
    }
    err.clear();
    return true;
}

std::string ZeroHash()
{
    LaunchCheckpoint blank;
    blank.weight_hash = WeightHash([&] {
        std::vector<int32_t> w;
        InitWeights(w);
        return w;
    }());
    blank.rng = "0";
    blank.optimizer = "SGD_WITHOUT_MOMENTUM";
    return StateHash(blank);
}

} // namespace

bool LaunchTrainer::Run(uint64_t steps, std::string& err)
{
    if (!CorpusLocked(err)) return false;
    if (m_weights.empty()) InitWeights(m_weights);
    if (steps > 4096 || m_step + steps > 4096) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    for (uint64_t i = 0; i < steps; ++i) {
        if (!Step(m_weights, m_cursor, m_hits, m_miss, err)) return false;
        ++m_cursor;
        ++m_step;
    }
    Publish();
    err.clear();
    return true;
}

void LaunchTrainer::Publish()
{
    LaunchCheckpoint state;
    state.step = m_step;
    state.cursor = m_cursor;
    state.rng = "0";
    state.optimizer = "SGD_WITHOUT_MOMENTUM";
    state.weight_hash = WeightHash(m_weights);
    state.inherited_state = m_inherited_state;
    state.inherited_step = m_inherited_step;
    state.hits = m_hits;
    state.miss_mass = m_miss;
    state.state_hash = StateHash(state);
    m_published = state;

    Interval interval;
    interval.start_inclusive = 0;
    interval.end_exclusive = m_step;
    interval.start_state = ZeroHash();
    interval.end_state = state.state_hash;
    interval.profile = LAUNCH_PROFILE;
    interval.rng = state.rng;
    interval.optimizer = state.optimizer;
    interval.data_cursor = std::to_string(state.cursor);
    interval.publisher_only = false;
    m_intervals.clear();
    if (m_step > 0) m_intervals.push_back(std::move(interval));
}

bool LaunchTrainer::CheckState(const LaunchCheckpoint& checkpoint, std::string& err)
{
    if (checkpoint.step == 0 || checkpoint.step > 4096) return Fail(err, "BTX035_NOT_RESUMABLE");
    if (checkpoint.state_hash.empty() || checkpoint.weight_hash.empty()) return Fail(err, "BTX035_ID_MISMATCH");
    LaunchTrainer replay;
    if (checkpoint.inherited_step > 0) {
        if (checkpoint.inherited_step >= checkpoint.step || checkpoint.inherited_state.empty()) {
            return Fail(err, "BTX035_ID_MISMATCH");
        }
        LaunchTrainer parent;
        if (!parent.Run(checkpoint.inherited_step, err)) return false;
        if (parent.Checkpoint().state_hash != checkpoint.inherited_state) return Fail(err, "BTX035_ID_MISMATCH");
        replay.m_inherited_step = checkpoint.inherited_step;
        replay.m_inherited_state = checkpoint.inherited_state;
    }
    if (!replay.Run(checkpoint.step, err)) return false;
    const LaunchCheckpoint& got = replay.Checkpoint();
    if (checkpoint.cursor != got.cursor || checkpoint.rng != got.rng) return Fail(err, "BTX035_RNG");
    if (checkpoint.optimizer != got.optimizer || checkpoint.weight_hash != got.weight_hash ||
        checkpoint.hits != got.hits || checkpoint.miss_mass != got.miss_mass ||
        checkpoint.inherited_step != got.inherited_step || checkpoint.inherited_state != got.inherited_state ||
        checkpoint.state_hash != got.state_hash) {
        return Fail(err, "BTX035_ID_MISMATCH");
    }
    err.clear();
    return true;
}

bool LaunchTrainer::Resume(const LaunchCheckpoint& checkpoint, std::string& err)
{
    if (!CheckState(checkpoint, err)) return false;
    m_weights.clear();
    m_step = 0;
    m_cursor = 0;
    m_hits = 0;
    m_miss = 0;
    m_inherited_state.clear();
    m_inherited_step = 0;
    if (!Run(checkpoint.step, err)) return false;
    m_inherited_state = checkpoint.state_hash;
    m_inherited_step = checkpoint.step;
    Publish();
    err.clear();
    return true;
}

bool LaunchTrainer::ReplayMatches(const LaunchCheckpoint& published, std::string& err) const
{
    return CheckState(published, err);
}

std::string LaunchCorpusBytes()
{
    unsigned n = 0;
    const unsigned char* bytes = Corpus(n);
    return std::string(reinterpret_cast<const char*>(bytes), n);
}

std::string LaunchTokenizerBytes()
{
    return "v1|BYTE_TOKEN|256\n";
}

bool LaunchDatasetDigest(std::string& digest, std::string& err)
{
    const std::string bytes = LaunchCorpusBytes();
    if (!CorpusLocked(err)) return false;
    const std::vector<unsigned char> raw(bytes.begin(), bytes.end());
    return GitObjectDigest("blob", Span<const unsigned char>{raw.data(), raw.size()}, digest, err);
}

bool LaunchTokenizerDigest(std::string& digest, std::string& err)
{
    const std::string recipe = LaunchTokenizerBytes();
    const std::vector<unsigned char> bytes(recipe.begin(), recipe.end());
    return GitObjectDigest("blob", Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err);
}

bool EncodeLaunchArtifact(const LaunchCheckpoint& checkpoint, const std::vector<int32_t>& weights,
                          std::string& bytes, std::string& err)
{
    if (static_cast<int>(weights.size()) != kTotal || checkpoint.state_hash.size() != 96 ||
        checkpoint.weight_hash.size() != 96 || checkpoint.weight_hash != WeightHash(weights)) {
        return Fail(err, "BTX035_SCHEMA");
    }
    bytes = "v1|" + std::string(LAUNCH_PROFILE) + "|" + std::to_string(checkpoint.step) + "|" +
            std::to_string(checkpoint.cursor) + "|" + checkpoint.weight_hash + "|" + checkpoint.state_hash + "\n";
    err.clear();
    return true;
}

bool EncodeLaunchLine(const std::string& trajectory_id, const LaunchCheckpoint& checkpoint, std::string& line, std::string& err)
{
    if (trajectory_id.size() != 96 || checkpoint.state_hash.size() != 96 || checkpoint.weight_hash.size() != 96) {
        return Fail(err, "BTX035_SCHEMA");
    }
    line = "v2|" + std::string(LAUNCH_PROFILE) + "|" + trajectory_id + "|" + std::to_string(checkpoint.step) + "|" +
           std::to_string(checkpoint.cursor) + "|" + checkpoint.rng + "|" + checkpoint.optimizer + "|" +
           checkpoint.weight_hash + "|" + checkpoint.state_hash + "|" + checkpoint.inherited_state + "|" +
           std::to_string(checkpoint.inherited_step) + "|" + std::to_string(checkpoint.hits) + "|" +
           std::to_string(checkpoint.miss_mass);
    if (line.find('\n') != std::string::npos || line.find('\r') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool DecodeLaunchLine(const std::string& line, std::string& trajectory_id, LaunchCheckpoint& checkpoint, std::string& err)
{
    if (line.empty() || line.find('\n') != std::string::npos) return Fail(err, "BTX035_SCHEMA");
    std::vector<std::string> parts;
    std::string current;
    for (char c : line) {
        if (c == '|') {
            parts.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    parts.push_back(current);
    if (parts.size() != 13 || parts[0] != "v2" || parts[1] != LAUNCH_PROFILE) return Fail(err, "BTX035_SCHEMA");
    trajectory_id = parts[2];
    if (trajectory_id.size() != 96) return Fail(err, "BTX035_SCHEMA");
    auto parse_u = [](const std::string& text, uint64_t& out) {
        if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
        uint64_t value = 0;
        for (char c : text) {
            if (c < '0' || c > '9') return false;
            value = value * 10 + static_cast<uint64_t>(c - '0');
        }
        out = value;
        return true;
    };
    auto parse_i = [](const std::string& text, int64_t& out) {
        if (text.empty()) return false;
        size_t i = 0;
        int sign = 1;
        if (text[0] == '-') {
            sign = -1;
            i = 1;
        }
        if (i >= text.size()) return false;
        int64_t value = 0;
        for (; i < text.size(); ++i) {
            if (text[i] < '0' || text[i] > '9') return false;
            value = value * 10 + (text[i] - '0');
        }
        out = value * sign;
        return true;
    };
    if (!parse_u(parts[3], checkpoint.step) || !parse_u(parts[4], checkpoint.cursor) ||
        !parse_u(parts[10], checkpoint.inherited_step) || !parse_i(parts[11], checkpoint.hits) ||
        !parse_i(parts[12], checkpoint.miss_mass)) {
        return Fail(err, "BTX035_SCHEMA");
    }
    checkpoint.rng = parts[5];
    checkpoint.optimizer = parts[6];
    checkpoint.weight_hash = parts[7];
    checkpoint.state_hash = parts[8];
    checkpoint.inherited_state = parts[9];
    if (checkpoint.rng != "0" && checkpoint.rng.size() > 32) return Fail(err, "BTX035_SCHEMA");
    if (checkpoint.weight_hash.size() != 96 || checkpoint.state_hash.size() != 96) return Fail(err, "BTX035_SCHEMA");
    if (!checkpoint.inherited_state.empty() && checkpoint.inherited_state.size() != 96) return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

} // namespace modelnet
