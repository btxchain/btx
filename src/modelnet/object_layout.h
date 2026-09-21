// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_OBJECT_LAYOUT_H
#define BITCOIN_MODELNET_OBJECT_LAYOUT_H

#include <modelnet/types.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace modelnet {

/**
 * Swarm / origin object arithmetic. Distinct from CloudObjectLayout
 * (SOURCE_FILES vs PIECE_OBJECTS on S3/R2). This module never retargets
 * R2 AUTO away from SOURCE_FILES.
 */
enum class PhysicalObjectLayout : uint8_t {
    AUTO = 0,
    PIECE_OBJECTS = 1,
    WHOLE_FILE = 2,
    LARGE_EXTENTS = 3,
};

/** 256 MiB extents (spec §9). */
inline constexpr uint64_t LARGE_EXTENT_BYTES = 256ull * MIB;
/** 64 MiB multipart parts for whole-file uploads. */
inline constexpr uint64_t MULTIPART_PART_BYTES = 64ull * MIB;
inline constexpr uint64_t OBJECT_LAYOUT_EXAMPLE_BYTES = 400ull * GIB;

const char* PhysicalObjectLayoutName(PhysicalObjectLayout l);
bool PhysicalObjectLayoutFromName(std::string_view name, PhysicalObjectLayout& out);

uint64_t CanonicalPieceCount(uint64_t file_size_bytes);
uint64_t LargeExtentCount(uint64_t file_size_bytes, uint64_t extent_bytes = LARGE_EXTENT_BYTES);
uint64_t WholeFileObjectCount(uint64_t file_size_bytes);
uint64_t MultipartPartCount(uint64_t file_size_bytes, uint64_t part_bytes = MULTIPART_PART_BYTES);

struct ObjectLayoutPlan {
    PhysicalObjectLayout requested{PhysicalObjectLayout::AUTO};
    PhysicalObjectLayout effective{PhysicalObjectLayout::WHOLE_FILE};
    uint64_t file_size_bytes{0};
    uint64_t piece_objects{0};
    uint64_t extent_objects{0};
    uint64_t whole_file_objects{0};
    uint64_t multipart_parts{0};
    /** Always false: R2 AUTO SOURCE_FILES is not replaced. */
    bool replaces_source_files{false};
};

ObjectLayoutPlan PlanObjectLayout(uint64_t file_size_bytes, PhysicalObjectLayout requested = PhysicalObjectLayout::AUTO);
UniValue ObjectLayoutPlanJson(const ObjectLayoutPlan& plan);

} // namespace modelnet

#endif // BITCOIN_MODELNET_OBJECT_LAYOUT_H
