// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
namespace hs = stage3_hash_semantic;
using gf::Fp3;

constexpr char PIN_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_DEQUANT_PIN_V1";
constexpr char AIR_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_DEQUANT_AIR_V1";
constexpr char PAGE_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_PAGE_RECEIPT_V1";
constexpr char ENDPOINT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_ENDPOINT_V1";
constexpr uint32_t DEQUANT_SPLITRAP_AUX =
    kRCStage3CoupledBankDequantColumns;
constexpr uint32_t DEQUANT_SPLITRAP_COLUMNS =
    kRCStage3CoupledBankDequantColumns + 1;

const std::vector<uint32_t>& DequantBaseColumns()
{
    static const std::vector<uint32_t> columns{
        0, 1, 2, 3, 4, 5};
    return columns;
}
constexpr char PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_BANK_PRODUCT_V1";
constexpr uint8_t MANTISSA_DOMAIN = 0x6d;
constexpr uint8_t SCALE_DOMAIN = 0x65;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_bank_product:" + detail;
    }
    return false;
}

bool IsCoupledStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement == RCStage3StatementKind::Coupled ||
           statement.statement == RCStage3StatementKind::Composed;
}

bool IsPowerOfTwo(uint64_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

Fp3 S(int64_t value)
{
    return Fp3::FromFp(gf::FromSigned(value));
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

size_t TagLen(const char* tag)
{
    return std::strlen(tag);
}

uint256 DigestUint(const std::array<uint8_t, 32>& digest)
{
    return uint256{Span<const unsigned char>{
        digest.data(), digest.size()}};
}

std::vector<uint8_t> TaggedU32Preimage(
    const char* tag, const uint256& source, uint32_t value)
{
    std::vector<uint8_t> out(
        reinterpret_cast<const uint8_t*>(tag),
        reinterpret_cast<const uint8_t*>(tag) + TagLen(tag));
    out.insert(out.end(), source.begin(), source.end());
    AppendLe32(out, value);
    return out;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

bool CounterShape(
    const ha::CounterXofManifest& manifest,
    const uint256& seed, uint8_t domain,
    ha::CounterXofMode mode, uint64_t count,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (manifest.seed != seed ||
        manifest.domain != domain ||
        manifest.mode != mode ||
        manifest.output_count != count ||
        manifest.output.size() != count ||
        manifest.commitment !=
            ha::CommitCounterXofManifest(manifest) ||
        !ha::BuildCounterXofManifestBoundaryInstances(
            manifest, boundaries, why) ||
        boundaries.empty()) {
        return Fail(why, "counter_shape");
    }
    return true;
}

bool ShaShape(
    const RCStage3CoupledBankHashExecution& execution,
    const std::vector<uint8_t>& preimage,
    const uint256& statement_commitment,
    std::string* why)
{
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (execution.manifest.mode != ha::ShaMode::Single ||
        execution.manifest.preimage != preimage ||
        execution.manifest.commitment !=
            ha::CommitShaManifest(execution.manifest) ||
        !ha::BuildShaManifestBoundaryInstances(
            execution.manifest, boundaries, why) ||
        boundaries.size() != 1 ||
        execution.proof.endpoint !=
            RCStage3RelationEndpoint::CoupledBankSeedXof ||
        execution.proof.statement_commitment !=
            statement_commitment ||
        execution.proof.manifest_commitment !=
            execution.manifest.commitment) {
        return Fail(why, "sha_shape");
    }
    return true;
}

bool ProveBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const std::vector<ha::FixedProgramBoundaryInstance>& boundaries,
    hs::FlatBoundaryProofBundle& out,
    std::string* why)
{
    out = {};
    out.endpoint = endpoint;
    out.statement_commitment = statement_commitment;
    out.manifest_commitment = manifest_commitment;
    out.proofs.resize(boundaries.size());
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < boundaries.size(); ++i) {
        ha::ProgramWitness witness;
        if (!ha::BuildProgramWitness(
                program, boundaries[i].external_values,
                witness, why) ||
            !ha::ProveFixedProgramProvenanceAir(
                program, witness, boundaries[i].external_values,
                boundaries[i].final_words,
                hs::ComputeBoundaryProofSeed(
                    endpoint, statement_commitment,
                    manifest_commitment, i, boundaries.size()),
                out.proofs[i], why)) {
            return false;
        }
    }
    return true;
}

bool BuildColumns(
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankPageProduct& page,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const uint64_t logical =
        uint64_t{shape.lobe_width} * shape.lobe_width;
    const uint64_t scales =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    if (logical != page.page_bytes.size() ||
        logical != page.mantissa.output.size() ||
        scales != page.scale.output.size() ||
        page.dequant_pin.logical_rows != logical ||
        page.dequant_pin.n_rows != logical ||
        page.dequant_pin.n_coeffs != logical ||
        !IsPowerOfTwo(logical)) {
        return Fail(why, "columns_shape");
    }
    columns.assign(
        DEQUANT_SPLITRAP_COLUMNS,
        std::vector<Fp3>(logical, Fp3::Zero()));
    const uint32_t blocks =
        shape.lobe_width / kRCMxBlockLen;
    for (uint32_t row = 0; row < shape.lobe_width; ++row) {
        for (uint32_t column = 0;
             column < shape.lobe_width; ++column) {
            const uint64_t index =
                uint64_t{row} * shape.lobe_width + column;
            const uint64_t scale_index =
                uint64_t{row} * blocks +
                column / kRCMxBlockLen;
            const uint8_t scale = page.scale.output[scale_index];
            if (scale > 3) return Fail(why, "scale_range");
            const uint8_t bit0 = scale & 1U;
            const uint8_t bit1 = (scale >> 1) & 1U;
            const uint8_t factor = uint8_t{1} << scale;
            const int8_t mantissa =
                static_cast<int8_t>(
                    page.mantissa.output[index]);
            columns[kRCStage3CoupledBankMantissa][index] =
                S(mantissa);
            columns[kRCStage3CoupledBankRepeatedScale][index] =
                U(scale);
            columns[kRCStage3CoupledBankScaleBit0][index] =
                U(bit0);
            columns[kRCStage3CoupledBankScaleBit1][index] =
                U(bit1);
            columns[kRCStage3CoupledBankScaleFactor][index] =
                U(factor);
            columns[kRCStage3CoupledBankOutput][index] =
                S(page.page_bytes[index]);
        }
    }
    return true;
}

uint256 PageReceipt(
    const RCStage3CoupledBankPageProduct& page)
{
    const uint256 pin =
        ComputeRCStage3CoupledBankDequantPinCommitment(
            page.dequant_pin);
    if (page.page_seed.manifest.commitment.IsNull() ||
        page.mantissa.commitment.IsNull() ||
        page.scale.commitment.IsNull() ||
        page.page_bytes.empty() || pin.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PAGE_DOMAIN;
    hash << kRCStage3CoupledBankProductVersion;
    hash << page.page_index;
    hash << page.page_seed.manifest.commitment;
    hash << page.mantissa.commitment;
    hash << page.scale.commitment;
    hash << pin;
    hash << page.dequant_pin.r0_row_group_root;
    return hash.GetHash();
}

uint256 EndpointRoot(
    RCStage3RelationEndpoint endpoint,
    const RCStage3CoupledBankProduct& product,
    bool pages)
{
    if (product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.header_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.bank_root_seed.manifest.commitment.IsNull() ||
        product.pages.empty()) {
        return {};
    }
    HashWriter hash;
    hash << ENDPOINT_DOMAIN;
    hash << kRCStage3CoupledBankProductVersion;
    hash << static_cast<uint16_t>(endpoint);
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.header_commitment;
    hash << product.sigma;
    hash << product.bank_root_seed.manifest.commitment;
    hash << static_cast<uint64_t>(product.pages.size());
    for (uint64_t i = 0; i < product.pages.size(); ++i) {
        const auto& page = product.pages[i];
        if (page.page_index != i ||
            page.page_receipt_commitment.IsNull()) {
            return {};
        }
        hash << page.page_index;
        if (pages) {
            hash << page.page_receipt_commitment;
            hash << page.dequant_pin.r0_row_group_root;
        } else {
            hash << page.page_seed.manifest.commitment;
            hash << page.mantissa.commitment;
            hash << page.scale.commitment;
        }
    }
    return hash.GetHash();
}

uint256 ProductCommitment(
    const RCStage3CoupledBankProduct& product)
{
    if (product.version !=
            kRCStage3CoupledBankProductVersion ||
        product.statement_commitment.IsNull() ||
        product.shape_commitment.IsNull() ||
        product.header_commitment.IsNull() ||
        product.sigma.IsNull() ||
        product.pages.empty() ||
        product.seed_xof_endpoint_root.IsNull() ||
        product.pages_endpoint_root.IsNull() ||
        product.bank_page_byte_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCT_DOMAIN << product.version;
    hash << product.statement_commitment;
    hash << product.shape_commitment;
    hash << product.header_commitment;
    hash << product.sigma;
    hash << product.bank_root_seed.manifest.commitment;
    hash << static_cast<uint64_t>(product.pages.size());
    for (const auto& page : product.pages) {
        hash << page.page_receipt_commitment;
    }
    hash << product.seed_xof_endpoint_root;
    hash << product.pages_endpoint_root;
    hash << product.bank_page_byte_root;
    return hash.GetHash();
}

bool BuildSourceRoot(
    const std::vector<RCStage3CoupledBankPageProduct>& pages,
    uint256& root,
    std::string* why)
{
    std::vector<uint8_t> bytes;
    uint64_t total{0};
    for (const auto& page : pages) {
        if (page.page_bytes.size() >
                std::numeric_limits<uint64_t>::max() - total) {
            return Fail(why, "source_overflow");
        }
        total += page.page_bytes.size();
    }
    if (total == 0 ||
        total > kRCStage3CoupledBankStreamTestMaxBytes) {
        return Fail(why, "source_bounded_size");
    }
    bytes.reserve(total);
    for (const auto& page : pages) {
        for (int8_t byte : page.page_bytes) {
            bytes.push_back(static_cast<uint8_t>(byte));
        }
    }
    RCStage3CoupledBankSourceOpening opening;
    return BuildRCStage3CoupledBankSourceOpeningForTest(
        bytes, 0, root, opening, why);
}

} // namespace

uint256 ComputeRCStage3CoupledBankDequantPinCommitment(
    const RCStage3CoupledBankDequantPin& pin)
{
    if (pin.version != kRCStage3CoupledBankProductVersion ||
        pin.statement_commitment.IsNull() ||
        pin.shape_commitment.IsNull() ||
        pin.sigma.IsNull() ||
        pin.logical_rows == 0 ||
        pin.n_rows != pin.logical_rows ||
        pin.n_coeffs != pin.n_rows ||
        !IsPowerOfTwo(pin.n_rows) ||
        pin.r0_row_group_root.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PIN_DOMAIN << pin.version;
    hash << pin.statement_commitment << pin.shape_commitment;
    hash << pin.sigma << pin.page_index;
    hash << pin.logical_rows << pin.n_rows << pin.n_coeffs;
    hash << pin.r0_row_group_root;
    return hash.GetHash();
}

uint256 ComputeRCStage3CoupledBankDequantSeed(
    const RCStage3CoupledBankDequantPin& pin)
{
    const uint256 commitment =
        ComputeRCStage3CoupledBankDequantPinCommitment(pin);
    if (commitment.IsNull()) return {};
    HashWriter hash;
    hash << AIR_SEED_DOMAIN << commitment;
    return hash.GetHash();
}

bool BuildRCStage3CoupledBankDequantConstraintSystem(
    const RCStage3CoupledBankDequantPin& pin,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "dequant_pin");
    }
    out.n_rows = pin.n_rows;
    out.n_columns = DEQUANT_SPLITRAP_COLUMNS;
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3CoupledBankDequantProgramTable(
            pin, table, why)) {
        return false;
    }
    constexpr const char* names[] = {
        "coupled.bank.scale_bit",
        "coupled.bank.scale_bit",
        "coupled.bank.scale_code",
        "coupled.bank.scale_factor",
        "coupled.bank.dequant",
    };
    static_assert(std::size(names) == 5);
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        const constraint_bytecode::Program program =
            table.programs[ordinal];
        AddConstraint(
            out, names[ordinal], program.declared_degree,
            [program](const std::vector<Fp3>& row,
                      const std::vector<Fp3>& next) {
                if (row.size() <
                        kRCStage3CoupledBankDequantColumns ||
                    next.size() <
                        kRCStage3CoupledBankDequantColumns) {
                    return Fp3::One();
                }
                const std::vector<Fp3> local_row(
                    row.begin(),
                    row.begin() +
                        kRCStage3CoupledBankDequantColumns);
                const std::vector<Fp3> local_next(
                    next.begin(),
                    next.begin() +
                        kRCStage3CoupledBankDequantColumns);
                Fp3 result = Fp3::Zero();
                if (!constraint_bytecode::EvaluateProgram(
                        program, local_row, local_next,
                        result)) {
                    return Fp3::One();
                }
                return result;
            });
    }
    AddConstraint(
        out, "coupled.bank.splitrap_aux_zero", 1,
        [](const std::vector<Fp3>& row,
           const std::vector<Fp3>&) {
            return row[DEQUANT_SPLITRAP_AUX];
        });
    out.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = DequantBaseColumns(),
        .root = pin.r0_row_group_root,
    });
    return true;
}

bool BuildRCStage3CoupledBankDequantProgramTable(
    const RCStage3CoupledBankDequantPin& pin,
    constraint_bytecode::ProgramTable& out,
    std::string* why)
{
    out = {};
    if (pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(pin) ||
        pin.pin_commitment.IsNull()) {
        return Fail(why, "dequant_bytecode_pin");
    }
    if (!BuildRCStage3CoupledBankDequantProgramTableCanonical(
            out, why) ||
        out.current_width !=
            kRCStage3CoupledBankDequantColumns) {
        return Fail(why, "dequant_bytecode_shape");
    }
    return true;
}

bool VerifyRCStage3CoupledBankDequantProof(
    const RCStage3CoupledBankDequantPin& pin,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildRCStage3CoupledBankDequantConstraintSystem(
            pin, cs, why) ||
        proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root) !=
            pin.r0_row_group_root) {
        return Fail(why, "dequant_proof_shape");
    }
    std::string air_why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            cs, proof,
            DequantBaseColumns(),
            ComputeRCStage3CoupledBankDequantSeed(pin),
            &air_why)) {
        return Fail(why, "dequant_air:" + air_why);
    }
    return true;
}

bool BuildRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledBankProduct& out,
    std::string* why)
{
    out = {};
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledBank, shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    uint64_t page_cells{0};
    uint64_t total_cells{0};
    if (!IsCoupledStatement(statement) ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        statement.public_inputs.sigma.IsNull() ||
        statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(header) ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() ||
        counts->primary != shape.bank_pages ||
        shape.lobe_width % kRCMxBlockLen != 0 ||
        !IsPowerOfTwo(shape.lobe_width) ||
        (page_cells =
             uint64_t{shape.lobe_width} *
                 shape.lobe_width) >
            std::numeric_limits<uint32_t>::max() ||
        page_cells >
            kRCStage3CoupledBankStreamTestMaxBytes ||
        shape.bank_pages >
            kRCStage3CoupledBankStreamTestMaxBytes /
                page_cells ||
        (total_cells =
             page_cells * shape.bank_pages) >
            kRCStage3CoupledBankStreamTestMaxBytes) {
        return Fail(why, "build_public_shape");
    }
    out.statement_commitment = statement_commitment;
    out.shape_commitment = shape_commitment;
    out.header_commitment =
        statement.public_inputs.header_commitment;
    out.sigma = statement.public_inputs.sigma;

    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    const auto root_preimage = TaggedU32Preimage(
        tags.bank, RCBankTemplateHash(header),
        static_cast<uint32_t>(statement.public_inputs.height));
    if (!ha::BuildShaManifest(
            root_preimage, ha::ShaMode::Single,
            out.bank_root_seed.manifest, why)) {
        return Fail(why, "build_root_seed");
    }
    out.bank_root_seed.proof.endpoint =
        RCStage3RelationEndpoint::CoupledBankSeedXof;
    out.bank_root_seed.proof.statement_commitment =
        statement_commitment;
    out.bank_root_seed.proof.manifest_commitment =
        out.bank_root_seed.manifest.commitment;
    const uint256 root_seed =
        DigestUint(out.bank_root_seed.manifest.digest);

    out.pages.reserve(shape.bank_pages);
    const uint64_t scale_cells =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    for (uint32_t page_index = 0;
         page_index < shape.bank_pages; ++page_index) {
        RCStage3CoupledBankPageProduct page;
        page.page_index = page_index;
        const auto page_preimage = TaggedU32Preimage(
            tags.bank, root_seed, page_index);
        if (!ha::BuildShaManifest(
                page_preimage, ha::ShaMode::Single,
                page.page_seed.manifest, why)) {
            return Fail(why, "build_page_seed");
        }
        page.page_seed.proof.endpoint =
            RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.page_seed.proof.statement_commitment =
            statement_commitment;
        page.page_seed.proof.manifest_commitment =
            page.page_seed.manifest.commitment;
        const uint256 page_seed =
            DigestUint(page.page_seed.manifest.digest);
        if (!ha::BuildCounterXofManifest(
                page_seed, MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                page_cells, page.mantissa, why) ||
            !ha::BuildCounterXofManifest(
                page_seed, SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scale_cells, page.scale, why)) {
            return Fail(why, "build_page_xof");
        }
        page.mantissa_proof.endpoint =
            RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.mantissa_proof.statement_commitment =
            statement_commitment;
        page.mantissa_proof.manifest_commitment =
            page.mantissa.commitment;
        page.scale_proof.endpoint =
            RCStage3RelationEndpoint::CoupledBankSeedXof;
        page.scale_proof.statement_commitment =
            statement_commitment;
        page.scale_proof.manifest_commitment =
            page.scale.commitment;
        page.page_bytes.resize(page_cells);
        const uint32_t blocks =
            shape.lobe_width / kRCMxBlockLen;
        for (uint32_t row = 0; row < shape.lobe_width; ++row) {
            for (uint32_t column = 0;
                 column < shape.lobe_width; ++column) {
                const uint64_t index =
                    uint64_t{row} * shape.lobe_width + column;
                const uint64_t scale_index =
                    uint64_t{row} * blocks +
                    column / kRCMxBlockLen;
                const int8_t mantissa =
                    static_cast<int8_t>(
                        page.mantissa.output[index]);
                page.page_bytes[index] =
                    static_cast<int8_t>(
                        static_cast<int32_t>(mantissa) *
                        (int32_t{1} <<
                         page.scale.output[scale_index]));
            }
        }
        auto& pin = page.dequant_pin;
        pin.statement_commitment = statement_commitment;
        pin.shape_commitment = shape_commitment;
        pin.sigma = statement.public_inputs.sigma;
        pin.page_index = page_index;
        pin.logical_rows = page_cells;
        pin.n_rows = page_cells;
        pin.n_coeffs = page_cells;
        std::vector<std::vector<Fp3>> columns;
        if (!BuildColumns(shape, page, columns, why)) return false;
        aq::AirConstraintSystem<Fp3> row_shape;
        row_shape.n_rows = pin.n_rows;
        row_shape.n_columns =
            DEQUANT_SPLITRAP_COLUMNS;
        const auto r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                row_shape, columns,
                DequantBaseColumns());
        if (!r0.valid ||
            r0.base_row_commitment.IsNull()) {
            return Fail(
                why, "build_page_r0:" +
                         r0.note);
        }
        pin.r0_row_group_root =
            r0.base_row_commitment;
        pin.pin_commitment =
            ComputeRCStage3CoupledBankDequantPinCommitment(pin);
        page.page_receipt_commitment = PageReceipt(page);
        if (pin.pin_commitment.IsNull() ||
            page.page_receipt_commitment.IsNull()) {
            return Fail(why, "build_page_pin");
        }
        out.pages.push_back(std::move(page));
    }
    out.seed_xof_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledBankSeedXof,
        out, false);
    out.pages_endpoint_root = EndpointRoot(
        RCStage3RelationEndpoint::CoupledBankPages,
        out, true);
    if (!BuildSourceRoot(
            out.pages, out.bank_page_byte_root, why)) {
        return false;
    }
    out.product_commitment = ProductCommitment(out);
    return !out.product_commitment.IsNull() ||
           Fail(why, "build_product_commitment");
}

bool ProveRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledBankProduct& out,
    std::string* why)
{
    if (!BuildRCStage3CoupledBankProduct(
            statement, header, shape, out, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            out.bank_root_seed.manifest, boundaries, why) ||
        !ProveBundle(
            RCStage3RelationEndpoint::CoupledBankSeedXof,
            out.statement_commitment,
            out.bank_root_seed.manifest.commitment,
            boundaries, out.bank_root_seed.proof, why)) {
        return Fail(why, "prove_root_seed");
    }
    for (auto& page : out.pages) {
        if (!ha::BuildShaManifestBoundaryInstances(
                page.page_seed.manifest, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                out.statement_commitment,
                page.page_seed.manifest.commitment,
                boundaries, page.page_seed.proof, why) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                page.mantissa, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                out.statement_commitment,
                page.mantissa.commitment,
                boundaries, page.mantissa_proof, why) ||
            !ha::BuildCounterXofManifestBoundaryInstances(
                page.scale, boundaries, why) ||
            !ProveBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                out.statement_commitment,
                page.scale.commitment,
                boundaries, page.scale_proof, why)) {
            return Fail(why, "prove_page_hash");
        }
        std::vector<std::vector<Fp3>> columns;
        aq::AirConstraintSystem<Fp3> cs;
        if (!BuildColumns(shape, page, columns, why) ||
            !BuildRCStage3CoupledBankDequantConstraintSystem(
                page.dequant_pin, cs, why)) {
            return false;
        }
        const auto retained_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                cs, columns,
                DequantBaseColumns());
        if (!retained_r0.valid ||
            retained_r0.base_row_commitment !=
                page.dequant_pin.r0_row_group_root) {
            return Fail(why, "prove_dequant_r0");
        }
        auto proved =
            aq::AirQuotientProveRowsSplitRap(
            cs, columns, DequantBaseColumns(),
            ComputeRCStage3CoupledBankDequantSeed(
                page.dequant_pin),
            {}, &retained_r0);
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "prove_dequant:" + proved.note);
        }
        page.dequant_proof = std::move(proved.proof);
    }
    return true;
}

bool ValidateRCStage3CoupledBankProductSchedule(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    std::string* why)
{
    const auto counts = ExpectedRCStage3CoupledRelationCounts(
        RCStage3RelationRole::CoupledBank, shape, why);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    const uint64_t page_cells =
        uint64_t{shape.lobe_width} * shape.lobe_width;
    const uint64_t scale_cells =
        uint64_t{shape.lobe_width} *
        (shape.lobe_width / kRCMxBlockLen);
    if (!IsCoupledStatement(statement) ||
        product.version != kRCStage3CoupledBankProductVersion ||
        product.statement_commitment != statement_commitment ||
        product.shape_commitment != shape_commitment ||
        product.header_commitment !=
            statement.public_inputs.header_commitment ||
        statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(header) ||
        product.sigma != statement.public_inputs.sigma ||
        product.sigma.IsNull() ||
        statement.public_inputs.transcript_version !=
            shape.transcript_version ||
        !counts.has_value() ||
        counts->primary != shape.bank_pages ||
        product.pages.size() != shape.bank_pages ||
        page_cells == 0 || !IsPowerOfTwo(page_cells) ||
        page_cells > std::numeric_limits<uint32_t>::max() ||
        page_cells >
            kRCStage3CoupledBankStreamTestMaxBytes ||
        shape.bank_pages >
            kRCStage3CoupledBankStreamTestMaxBytes /
                page_cells) {
        return Fail(why, "schedule_public_shape");
    }
    const auto& tags =
        RCCoupDomainTagsForVersion(shape.transcript_version);
    if (!ShaShape(
            product.bank_root_seed,
            TaggedU32Preimage(
                tags.bank, RCBankTemplateHash(header),
                static_cast<uint32_t>(
                    statement.public_inputs.height)),
            statement_commitment, why)) {
        return Fail(why, "schedule_root_seed");
    }
    const uint256 root_seed =
        DigestUint(product.bank_root_seed.manifest.digest);
    for (uint32_t i = 0; i < product.pages.size(); ++i) {
        const auto& page = product.pages[i];
        if (page.page_index != i ||
            !ShaShape(
                page.page_seed,
                TaggedU32Preimage(tags.bank, root_seed, i),
                statement_commitment, why)) {
            return Fail(
                why, "schedule_page_seed_" +
                         std::to_string(i));
        }
        const uint256 page_seed =
            DigestUint(page.page_seed.manifest.digest);
        if (!CounterShape(
                page.mantissa, page_seed,
                MANTISSA_DOMAIN,
                ha::CounterXofMode::MantissaE2M1,
                page_cells, why) ||
            !CounterShape(
                page.scale, page_seed,
                SCALE_DOMAIN,
                ha::CounterXofMode::Scale2Bit,
                scale_cells, why) ||
            page.mantissa_proof.endpoint !=
                RCStage3RelationEndpoint::CoupledBankSeedXof ||
            page.mantissa_proof.statement_commitment !=
                statement_commitment ||
            page.mantissa_proof.manifest_commitment !=
                page.mantissa.commitment ||
            page.scale_proof.endpoint !=
                RCStage3RelationEndpoint::CoupledBankSeedXof ||
            page.scale_proof.statement_commitment !=
                statement_commitment ||
            page.scale_proof.manifest_commitment !=
                page.scale.commitment ||
            page.page_bytes.size() != page_cells) {
            return Fail(
                why, "schedule_xof_" + std::to_string(i));
        }
        const auto& pin = page.dequant_pin;
        if (pin.statement_commitment != statement_commitment ||
            pin.shape_commitment != shape_commitment ||
            pin.sigma != product.sigma ||
            pin.page_index != i ||
            pin.logical_rows != page_cells ||
            pin.n_rows != page_cells ||
            pin.n_coeffs != page_cells ||
            pin.pin_commitment !=
                ComputeRCStage3CoupledBankDequantPinCommitment(
                    pin)) {
            return Fail(
                why, "schedule_pin_" + std::to_string(i));
        }
        std::vector<std::vector<Fp3>> columns;
        if (!BuildColumns(shape, page, columns, why)) {
            return false;
        }
        aq::AirConstraintSystem<Fp3> row_shape;
        row_shape.n_rows = pin.n_rows;
        row_shape.n_columns =
            DEQUANT_SPLITRAP_COLUMNS;
        const auto expected_r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                row_shape, columns,
                DequantBaseColumns());
        if (!expected_r0.valid ||
            pin.r0_row_group_root !=
                expected_r0.base_row_commitment) {
            return Fail(
                why, "schedule_row_root_" +
                         std::to_string(i));
        }
        if (page.page_receipt_commitment !=
            PageReceipt(page)) {
            return Fail(
                why, "schedule_page_receipt_" +
                         std::to_string(i));
        }
    }
    uint256 source_root;
    if (!BuildSourceRoot(product.pages, source_root, why) ||
        product.bank_page_byte_root != source_root ||
        product.seed_xof_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledBankSeedXof,
            product, false) ||
        product.pages_endpoint_root != EndpointRoot(
            RCStage3RelationEndpoint::CoupledBankPages,
            product, true) ||
        product.product_commitment !=
            ProductCommitment(product)) {
        return Fail(why, "schedule_roots_or_commitment");
    }
    return true;
}

bool VerifyRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    std::string* why)
{
    if (!ValidateRCStage3CoupledBankProductSchedule(
            statement, header, shape, product, why) ||
        !hs::VerifyShaManifestBundle(
            RCStage3RelationEndpoint::CoupledBankSeedXof,
            product.bank_root_seed.manifest,
            product.bank_root_seed.proof, why)) {
        return Fail(why, "schedule_or_root_seed_proof");
    }
    for (uint32_t i = 0; i < product.pages.size(); ++i) {
        const auto& page = product.pages[i];
        if (!hs::VerifyShaManifestBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                page.page_seed.manifest,
                page.page_seed.proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                page.mantissa,
                page.mantissa_proof, why) ||
            !hs::VerifyCounterXofManifestBundle(
                RCStage3RelationEndpoint::CoupledBankSeedXof,
                page.scale,
                page.scale_proof, why) ||
            !VerifyRCStage3CoupledBankDequantProof(
                page.dequant_pin,
                page.dequant_proof, why)) {
            return Fail(
                why, "page_proof_" + std::to_string(i));
        }
    }
    return true;
}

bool VerifyRCStage3CoupledBankStreamSourceLink(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankStreamManifest& stream_manifest,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankProduct(
            statement, header, shape, product, why) ||
        !ValidateRCStage3CoupledBankStreamManifest(
            statement, shape,
            product.bank_page_byte_root,
            stream_manifest, why)) {
        return Fail(why, "endpoint29_source_link");
    }
    return true;
}

bool ValidateRCStage3CoupledBankFlatSourceEquality(
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankRootManifest& flat_manifest,
    std::string* why)
{
    if (product.pages.empty() ||
        flat_manifest.commitment.IsNull()) {
        return Fail(why, "flat_source_link_shape");
    }
    const auto& tags = RCCoupDomainTagsForVersion(
        flat_manifest.shape.transcript_version);
    const auto* tag = reinterpret_cast<const uint8_t*>(tags.bank);
    const size_t tag_size = std::strlen(tags.bank);
    const auto& preimage = flat_manifest.sha256d.preimage;
    if (preimage.size() < tag_size ||
        !std::equal(
            tag, tag + tag_size, preimage.begin())) {
        return Fail(why, "flat_source_link_tag");
    }
    size_t cursor = tag_size;
    for (const auto& page : product.pages) {
        if (page.page_bytes.size() >
            preimage.size() - cursor) {
            return Fail(why, "flat_source_link_length");
        }
        for (int8_t value : page.page_bytes) {
            if (preimage[cursor++] !=
                static_cast<uint8_t>(value)) {
                return Fail(why, "flat_source_link_value");
            }
        }
    }
    if (cursor != preimage.size()) {
        return Fail(why, "flat_source_link_trailing");
    }
    return true;
}

bool VerifyRCStage3CoupledBankFlatSourceLink(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankRootExecution& flat_bank,
    std::string* why)
{
    if (!VerifyRCStage3CoupledBankProduct(
            statement, header, shape, product, why) ||
        !VerifyRCStage3CoupledBankRootExecution(
            statement, shape, flat_bank, why) ||
        !ValidateRCStage3CoupledBankFlatSourceEquality(
            product, flat_bank.manifest, why)) {
        return Fail(why, "endpoint28_to_29_flat_source_link");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_bank_product:endpoint28_to_29_flat_"
            "source_link_ok";
    }
    return true;
}

RCStage3CoupledBankProductAudit
CurrentRCStage3CoupledBankProductAudit()
{
    RCStage3CoupledBankProductAudit out;
    out.immutable_all_page_schedule = true;
    out.bank_seed_sha_executed = true;
    out.page_seed_sha_executed = true;
    out.mantissa_and_scale_xof_executed = true;
    out.xof_to_page_dequant_equality_executed = true;
    out.proof_owned_page_memory_root = true;
    out.endpoint29_source_root_equality_executable = true;
    out.endpoints_27_28_bounded_local_complete =
        kRCStage3CoupledBankBoundedLocalProductExecutable;
    out.production_streaming_complete =
        kRCStage3CoupledBankProductionStreamingComplete;
    out.recursively_consumed = false;
    out.transitively_complete = false;
    out.remaining =
        "The exact local product is capped at 16 MiB and its flat SHA/XOF "
        "children plus dequant quotient are not yet consumed by the "
        "normalized recursive verifier; endpoint 29 still requires its "
        "separate streamed hash proof.";
    return out;
}

} // namespace matmul::v4::rc
