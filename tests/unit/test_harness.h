/**
 * @file test_harness.h
 * @desc Minimal single-header unit test harness for ssh-chatter.
 *
 *       Usage:
 *         TEST(name) { CHECK(cond); CHECK_STR_EQ(a, b); ... }
 *         int main(void) { RUN_TEST(name); ...; return TEST_REPORT(); }
 *
 *       A failed CHECK reports the location and aborts the current test
 *       (later tests still run). TEST_REPORT() prints a summary and returns
 *       a process exit status suitable for make.
 */
#ifndef SSH_CHATTER_TEST_HARNESS_H
#define SSH_CHATTER_TEST_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_test_passed = 0;
static int g_test_failed = 0;
static bool g_test_current_failed = false;

#define TEST(name) static void name(void)

#define TEST_FAIL_(fmt, ...)                                                   \
    do {                                                                       \
        fprintf(stderr, "  FAIL %s:%d in %s: " fmt "\n", __FILE__, __LINE__,   \
                __func__, __VA_ARGS__);                                        \
        g_test_current_failed = true;                                          \
        return;                                                                \
    } while (0)

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            TEST_FAIL_("%s", #cond);                                           \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        long long check_a_ = (long long)(a);                                   \
        long long check_b_ = (long long)(b);                                   \
        if (check_a_ != check_b_) {                                            \
            TEST_FAIL_("%s == %s (got %lld, expected %lld)", #a, #b,           \
                       check_a_, check_b_);                                    \
        }                                                                      \
    } while (0)

#define CHECK_STR_EQ(a, b)                                                     \
    do {                                                                       \
        const char *check_a_ = (a);                                            \
        const char *check_b_ = (b);                                            \
        if (check_a_ == NULL || check_b_ == NULL ||                            \
            strcmp(check_a_, check_b_) != 0) {                                 \
            TEST_FAIL_("%s == %s (got \"%s\", expected \"%s\")", #a, #b,       \
                       check_a_ ? check_a_ : "(null)",                         \
                       check_b_ ? check_b_ : "(null)");                        \
        }                                                                      \
    } while (0)

#define CHECK_MEM_EQ(a, b, len)                                                \
    do {                                                                       \
        if (memcmp((a), (b), (len)) != 0) {                                    \
            TEST_FAIL_("memcmp(%s, %s, %s) == 0", #a, #b, #len);               \
        }                                                                      \
    } while (0)

#define RUN_TEST(name)                                                         \
    do {                                                                       \
        g_test_current_failed = false;                                         \
        name();                                                                \
        if (g_test_current_failed) {                                           \
            ++g_test_failed;                                                   \
            fprintf(stderr, "[FAIL] %s\n", #name);                             \
        } else {                                                               \
            ++g_test_passed;                                                   \
            printf("[ ok ] %s\n", #name);                                      \
        }                                                                      \
    } while (0)

#define TEST_REPORT()                                                          \
    (printf("%s: %d passed, %d failed\n", __FILE__, g_test_passed,             \
            g_test_failed),                                                    \
     g_test_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE)

#endif
