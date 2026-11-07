// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_ckpt/dt_ckpt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

using std::int64_t;

void ExpectQuiet(const modelnet::DtCkpt& ckpt)
{
    BOOST_CHECK(!ckpt.launched());
    BOOST_CHECK(!ckpt.gpu());
    BOOST_CHECK(!ckpt.broadcast());
    BOOST_CHECK_EQUAL(ckpt.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(ckpt.bytes_moved(), static_cast<int64_t>(0));
}

modelnet::DtCkpt::State FullClosure()
{
    modelnet::DtCkpt::State state;
    state.weights = {10, 20, 30, 40};
    state.adam_m = {1, 1, 2};
    state.adam_v = {3, 3, 4};
    state.step = 7;
    state.rng = 8;
    state.cursor = 9;
    state.recipe_id = "recipe-1";
    state.topology_id = "topo-1";
    state.cohort_epoch = 4;
    return state;
}

modelnet::DtCkpt::State DirtyLive()
{
    modelnet::DtCkpt::State state;
    state.weights = {99};
    state.adam_m = {98};
    state.adam_v = {97};
    state.step = 1;
    state.rng = 2;
    state.cursor = 3;
    state.recipe_id = "other-recipe";
    state.topology_id = "other-topo";
    state.cohort_epoch = 5;
    return state;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_ckpt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(full_save_then_restore_matches)
{
    modelnet::DtCkpt ckpt;
    const modelnet::DtCkpt::State saved = FullClosure();
    ckpt.live() = DirtyLive();
    std::string err = "stale";
    BOOST_CHECK(ckpt.Save(saved, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(ckpt.exact_resume());
    BOOST_CHECK(!ckpt.promoted());
    BOOST_CHECK_EQUAL(ckpt.artifact().size(), static_cast<std::size_t>(96));
    BOOST_CHECK_EQUAL(ckpt.piece_count(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(ckpt.slice_ids().size(), static_cast<std::size_t>(1));

    const std::size_t pieces = ckpt.piece_count();
    BOOST_CHECK(ckpt.Save(saved, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);

    modelnet::DtCkpt::State empty = saved;
    empty.weights.clear();
    BOOST_CHECK(!ckpt.Save(empty, err));
    BOOST_CHECK_EQUAL(err, "WEIGHTS");
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    BOOST_CHECK(ckpt.exact_resume());

    ckpt.live() = DirtyLive();
    const modelnet::DtCkpt::State before = ckpt.live();
    BOOST_CHECK(before.weights != saved.weights);
    BOOST_CHECK(ckpt.Promote(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(ckpt.promoted());
    BOOST_CHECK(ckpt.usable(ckpt.artifact()));
    BOOST_CHECK(ckpt.Restore(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(ckpt.live() == saved);
    BOOST_CHECK(ckpt.live().weights == saved.weights);
    BOOST_CHECK(ckpt.live().adam_m == saved.adam_m);
    BOOST_CHECK(ckpt.live().adam_v == saved.adam_v);
    BOOST_CHECK_EQUAL(ckpt.live().step, saved.step);
    BOOST_CHECK_EQUAL(ckpt.live().rng, saved.rng);
    BOOST_CHECK_EQUAL(ckpt.live().cursor, saved.cursor);
    BOOST_CHECK(ckpt.Save(saved, err));
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    ExpectQuiet(ckpt);
    BOOST_CHECK(before.weights != ckpt.live().weights);
}

BOOST_AUTO_TEST_CASE(missing_slice_blocks_promote)
{
    modelnet::DtCkpt ckpt;
    const modelnet::DtCkpt::State saved = FullClosure();
    ckpt.live() = DirtyLive();
    const modelnet::DtCkpt::State dirty = ckpt.live();
    std::string err = "stale";
    BOOST_REQUIRE(ckpt.Save(saved, err));
    const std::vector<std::string> slices = ckpt.slice_ids();
    BOOST_REQUIRE_EQUAL(slices.size(), static_cast<std::size_t>(1));
    const std::size_t pieces = ckpt.piece_count();
    BOOST_CHECK(!ckpt.Drop(slices[0], err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(ckpt.has_piece(slices[0]));
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    BOOST_CHECK(!ckpt.usable(ckpt.artifact()));
    BOOST_CHECK(!ckpt.Resume(err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!ckpt.Promote(err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(!ckpt.promoted());
    BOOST_CHECK(!ckpt.Restore(err));
    BOOST_CHECK_EQUAL(err, "MANIFEST");
    BOOST_CHECK(ckpt.live() == dirty);
    ExpectQuiet(ckpt);
}

BOOST_AUTO_TEST_CASE(weights_only_is_not_exact_resume)
{
    modelnet::DtCkpt ckpt;
    modelnet::DtCkpt::State partial = FullClosure();
    partial.adam_m.clear();
    partial.adam_v.clear();
    ckpt.live() = DirtyLive();
    const modelnet::DtCkpt::State dirty = ckpt.live();
    std::string err = "stale";
    BOOST_CHECK(ckpt.Save(partial, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!ckpt.exact_resume());
    BOOST_CHECK_EQUAL(ckpt.piece_count(), static_cast<std::size_t>(1));
    BOOST_CHECK(ckpt.Resume(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(ckpt.usable(ckpt.artifact()));
    BOOST_CHECK(!ckpt.Promote(err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK(!ckpt.promoted());
    BOOST_CHECK(!ckpt.Restore(err));
    BOOST_CHECK_EQUAL(err, "PARTIAL");
    BOOST_CHECK(ckpt.live() == dirty);

    const std::size_t pieces = ckpt.piece_count();
    modelnet::DtCkpt::State empty = partial;
    empty.weights.clear();
    BOOST_CHECK(!ckpt.Save(empty, err));
    BOOST_CHECK_EQUAL(err, "WEIGHTS");
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    BOOST_CHECK(!ckpt.exact_resume());
    BOOST_CHECK(ckpt.Save(partial, err));
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    ExpectQuiet(ckpt);
}

BOOST_AUTO_TEST_CASE(pickle_marker_is_refused)
{
    modelnet::DtCkpt ckpt;
    modelnet::DtCkpt::State bad = FullClosure();
    const std::string marker = "PYTHON_PICKLE";
    bad.weights.assign(marker.begin(), marker.end());
    std::string err = "stale";
    BOOST_CHECK(!ckpt.Save(bad, err));
    BOOST_CHECK_EQUAL(err, "PYTHON_PICKLE");
    BOOST_CHECK_EQUAL(ckpt.piece_count(), static_cast<std::size_t>(0));
    BOOST_CHECK(!ckpt.exact_resume());
    BOOST_CHECK(!ckpt.promoted());
    BOOST_CHECK(ckpt.artifact().empty());

    const modelnet::DtCkpt::State saved = FullClosure();
    BOOST_REQUIRE(ckpt.Save(saved, err));
    const std::size_t pieces = ckpt.piece_count();
    const std::string artifact = ckpt.artifact();
    BOOST_CHECK(!ckpt.Save(bad, err));
    BOOST_CHECK_EQUAL(err, "PYTHON_PICKLE");
    BOOST_CHECK_EQUAL(ckpt.piece_count(), pieces);
    BOOST_CHECK_EQUAL(ckpt.artifact(), artifact);
    BOOST_CHECK(ckpt.exact_resume());

    modelnet::DtCkpt elf;
    modelnet::DtCkpt::State code = FullClosure();
    code.weights = {0x7f, 'E', 'L', 'F', 0x02, 0x01};
    BOOST_CHECK(!elf.Save(code, err));
    BOOST_CHECK_EQUAL(err, "CODE");
    BOOST_CHECK_EQUAL(elf.piece_count(), static_cast<std::size_t>(0));
    BOOST_CHECK(!elf.exact_resume());
    BOOST_CHECK(elf.artifact().empty());
    ExpectQuiet(ckpt);
    ExpectQuiet(elf);
}

BOOST_AUTO_TEST_SUITE_END()
