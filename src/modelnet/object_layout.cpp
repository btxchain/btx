// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/object_layout.h>

namespace modelnet {

const char* PhysicalObjectLayoutName(PhysicalObjectLayout l)
{
    switch (l) {
    case PhysicalObjectLayout::AUTO: return "AUTO";
    case PhysicalObjectLayout::PIECE_OBJECTS: return "PIECE_OBJECTS";
    case PhysicalObjectLayout::WHOLE_FILE: return "WHOLE_FILE";
    case PhysicalObjectLayout::LARGE_EXTENTS: return "LARGE_EXTENTS";
    }
    return "AUTO";
}

bool PhysicalObjectLayoutFromName(std::string_view name, PhysicalObjectLayout& out)
{
    if (name == "AUTO") {
        out = PhysicalObjectLayout::AUTO;
        return true;
    }
    if (name == "PIECE_OBJECTS") {
        out = PhysicalObjectLayout::PIECE_OBJECTS;
        return true;
    }
    if (name == "WHOLE_FILE") {
        out = PhysicalObjectLayout::WHOLE_FILE;
        return true;
    }
    if (name == "LARGE_EXTENTS") {
        out = PhysicalObjectLayout::LARGE_EXTENTS;
        return true;
    }
    return false;
}

uint64_t CanonicalPieceCount(uint64_t file_size_bytes)
{
    if (file_size_bytes == 0) return 1;
    return (file_size_bytes + PIECE_SIZE - 1) / PIECE_SIZE;
}

uint64_t LargeExtentCount(uint64_t file_size_bytes, uint64_t extent_bytes)
{
    if (extent_bytes == 0) extent_bytes = LARGE_EXTENT_BYTES;
    if (file_size_bytes == 0) return 1;
    return (file_size_bytes + extent_bytes - 1) / extent_bytes;
}

uint64_t WholeFileObjectCount(uint64_t /*file_size_bytes*/)
{
    return 1;
}

uint64_t MultipartPartCount(uint64_t file_size_bytes, uint64_t part_bytes)
{
    if (part_bytes == 0) part_bytes = MULTIPART_PART_BYTES;
    if (file_size_bytes == 0) return 1;
    return (file_size_bytes + part_bytes - 1) / part_bytes;
}

ObjectLayoutPlan PlanObjectLayout(uint64_t file_size_bytes, PhysicalObjectLayout requested)
{
    ObjectLayoutPlan p;
    p.requested = requested;
    p.file_size_bytes = file_size_bytes;
    p.piece_objects = CanonicalPieceCount(file_size_bytes);
    p.extent_objects = LargeExtentCount(file_size_bytes);
    p.whole_file_objects = WholeFileObjectCount(file_size_bytes);
    p.multipart_parts = MultipartPartCount(file_size_bytes);
    p.replaces_source_files = false;
    if (requested == PhysicalObjectLayout::AUTO) {
        p.effective = file_size_bytes > (4ull * GIB) ? PhysicalObjectLayout::LARGE_EXTENTS
                                                      : PhysicalObjectLayout::WHOLE_FILE;
    } else {
        p.effective = requested;
    }
    return p;
}

UniValue ObjectLayoutPlanJson(const ObjectLayoutPlan& plan)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("requested", PhysicalObjectLayoutName(plan.requested));
    o.pushKV("effective", PhysicalObjectLayoutName(plan.effective));
    o.pushKV("file_size_bytes", static_cast<int64_t>(plan.file_size_bytes));
    o.pushKV("piece_objects", static_cast<int64_t>(plan.piece_objects));
    o.pushKV("extent_objects", static_cast<int64_t>(plan.extent_objects));
    o.pushKV("whole_file_objects", static_cast<int64_t>(plan.whole_file_objects));
    o.pushKV("multipart_parts", static_cast<int64_t>(plan.multipart_parts));
    o.pushKV("replaces_source_files", plan.replaces_source_files);
    o.pushKV("cloud_r2_auto", "SOURCE_FILES");
    return o;
}

} // namespace modelnet
