/**
 * @file test_bbs_threads.c
 * @desc Unit tests for the BBS comment reply-tree helpers in
 *       src/host/core/bbs_threads.c: display order, depth capping, broken
 *       references and re-parenting on delete.
 */
#include "../../src/host/core/bbs_threads.c"

#include "test_harness.h"

/* ---- bbs_thread_order ---- */

TEST(flat_comments_keep_their_order)
{
    int32_t refs[3] = {0, 0, 0};
    size_t order[3], depth[3];
    CHECK(bbs_thread_order(refs, 3U, order, depth) == 3U);
    CHECK(order[0] == 0U && order[1] == 1U && order[2] == 2U);
    CHECK(depth[0] == 0U && depth[1] == 0U && depth[2] == 0U);
}

TEST(replies_follow_their_parent)
{
    /* 0, 1, 2 -> 0, 3 -> 2, 4 -> 0 */
    int32_t refs[5] = {0, 0, 1, 3, 1};
    size_t order[5], depth[5];
    CHECK(bbs_thread_order(refs, 5U, order, depth) == 5U);
    const size_t want_order[5] = {0U, 2U, 3U, 4U, 1U};
    const size_t want_depth[5] = {0U, 1U, 2U, 1U, 0U};
    for (size_t idx = 0U; idx < 5U; ++idx) {
        CHECK(order[idx] == want_order[idx]);
        CHECK(depth[idx] == want_depth[idx]);
    }
}

TEST(depth_is_capped)
{
    int32_t refs[7] = {0, 1, 2, 3, 4, 5, 6};
    size_t order[7], depth[7];
    CHECK(bbs_thread_order(refs, 7U, order, depth) == 7U);
    CHECK(depth[4] == BBS_THREAD_MAX_DEPTH);
    CHECK(depth[6] == BBS_THREAD_MAX_DEPTH);
}

TEST(broken_references_are_top_level)
{
    /* Self, forward and negative references cannot form a tree. */
    int32_t refs[4] = {1, 4, -3, 99};
    size_t order[4], depth[4];
    CHECK(bbs_thread_order(refs, 4U, order, depth) == 4U);
    for (size_t idx = 0U; idx < 4U; ++idx) {
        CHECK(order[idx] == idx);
        CHECK(depth[idx] == 0U);
    }
}

/* ---- bbs_thread_remove ---- */

TEST(removing_a_parent_moves_replies_up)
{
    /* 0, 1 -> 0, 2 -> 1, 3 -> 1, 4 */
    int32_t refs[5] = {0, 1, 2, 2, 0};
    bbs_thread_remove(refs, 5U, 1U);
    /* now 0, 1(old 2) -> 0, 2(old 3) -> 0, 3(old 4) */
    CHECK(refs[0] == 0 && refs[1] == 1 && refs[2] == 1 && refs[3] == 0);
    CHECK(refs[4] == 0);
}

TEST(removing_a_root_makes_replies_roots)
{
    int32_t refs[3] = {0, 1, 2};
    bbs_thread_remove(refs, 3U, 0U);
    CHECK(refs[0] == 0 && refs[1] == 1);
}

TEST(later_references_shift_down)
{
    /* 0, 1, 2 -> 1, 3 -> 2; remove 0 */
    int32_t refs[4] = {0, 0, 2, 3};
    bbs_thread_remove(refs, 4U, 0U);
    CHECK(refs[0] == 0 && refs[1] == 1 && refs[2] == 2);
}

TEST(removing_the_last_comment)
{
    int32_t refs[2] = {0, 1};
    bbs_thread_remove(refs, 2U, 1U);
    CHECK(refs[0] == 0 && refs[1] == 0);
}

int main(void)
{
    RUN_TEST(flat_comments_keep_their_order);
    RUN_TEST(replies_follow_their_parent);
    RUN_TEST(depth_is_capped);
    RUN_TEST(broken_references_are_top_level);
    RUN_TEST(removing_a_parent_moves_replies_up);
    RUN_TEST(removing_a_root_makes_replies_roots);
    RUN_TEST(later_references_shift_down);
    RUN_TEST(removing_the_last_comment);
    return TEST_REPORT();
}
