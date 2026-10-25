/**
 * @file bbs_threads.c
 * @desc Reply-tree helpers for BBS comments.  Each comment carries a parent
 *       reference: 0 for a top-level comment, otherwise the parent's index
 *       plus one.  A parent always sits at a lower index than its replies
 *       (replies are appended), which keeps the tree free of cycles; a
 *       reference that breaks that rule is treated as top-level.  Only libc
 *       is used so the unit test can include this file.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Replies deeper than this are drawn at this depth. */
#define BBS_THREAD_MAX_DEPTH 4U

/* Parent index of comment idx, or -1 when it is top-level. */
static int32_t bbs_thread_parent_of(const int32_t *refs, size_t idx)
{
    int32_t ref = refs[idx];
    if (ref <= 0 || (size_t)(ref - 1) >= idx) {
        return -1;
    }
    return ref - 1;
}

static void bbs_thread_visit(const int32_t *refs, size_t count, size_t node,
                             size_t level, size_t *order, size_t *depth,
                             size_t *written)
{
    order[*written] = node;
    depth[*written] = level < BBS_THREAD_MAX_DEPTH ? level
                                                   : BBS_THREAD_MAX_DEPTH;
    ++*written;
    /* Children always follow their parent, so only later slots are scanned
     * and the recursion is bounded by the comment count. */
    for (size_t child = node + 1U; child < count; ++child) {
        if (bbs_thread_parent_of(refs, child) == (int32_t)node) {
            bbs_thread_visit(refs, count, child, level + 1U, order, depth,
                             written);
        }
    }
}

/*
 * Fill order[] with the comment indexes in display order (each comment
 * followed by its replies, oldest first) and depth[] with the indent level of
 * each entry.  Both arrays need room for count entries.  Returns count.
 */
static size_t bbs_thread_order(const int32_t *refs, size_t count,
                               size_t *order, size_t *depth)
{
    if (refs == nullptr || order == nullptr || depth == nullptr) {
        return 0U;
    }
    size_t written = 0U;
    for (size_t idx = 0U; idx < count; ++idx) {
        if (bbs_thread_parent_of(refs, idx) < 0) {
            bbs_thread_visit(refs, count, idx, 0U, order, depth, &written);
        }
    }
    return written;
}

/*
 * Update refs[] (count entries) for the removal of comment removed: its
 * replies move up to its own parent, later references shift down by one and
 * the entry itself is dropped.  The caller removes the comment from its own
 * array the same way and then has count - 1 comments.
 */
static void bbs_thread_remove(int32_t *refs, size_t count, size_t removed)
{
    if (refs == nullptr || removed >= count) {
        return;
    }
    const int32_t removed_ref = (int32_t)(removed + 1U);
    const int32_t inherited =
        bbs_thread_parent_of(refs, removed) < 0 ? 0 : refs[removed];
    for (size_t idx = 0U; idx < count; ++idx) {
        if (idx == removed) {
            continue;
        }
        if (bbs_thread_parent_of(refs, idx) < 0) {
            refs[idx] = 0;
        } else if (refs[idx] == removed_ref) {
            refs[idx] = inherited;
        } else if (refs[idx] > removed_ref) {
            refs[idx] -= 1;
        }
    }
    if (removed + 1U < count) {
        memmove(&refs[removed], &refs[removed + 1U],
                (count - removed - 1U) * sizeof(*refs));
    }
    refs[count - 1U] = 0;
}
