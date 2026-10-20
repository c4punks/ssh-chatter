/**
 * @file test_translation_helpers.c
 * @desc Unit tests for src/translation_helpers.c: ANSI placeholder
 *       protection around translation, the "@nt" opt-out prefix, display
 *       width measurement and width-based wrapping.
 */
#include "ssh_chatter/translation_helpers.h"

#include <locale.h>

#include "test_harness.h"

/* Defined in translation_helpers.c but not exported through a header. */
int get_display_width(const char *text);
char **wrap_text_to_width(const char *text, int max_width, size_t *line_count);

/* ---- translation_prepare_text / translation_restore_text ---- */

TEST(prepare_plain_text_is_unchanged)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 99U;
    char out[128];

    CHECK(translation_prepare_text("hello world", out, sizeof(out), ph,
                                   &count));
    CHECK_STR_EQ(out, "hello world");
    CHECK_EQ(count, 0);
}

TEST(prepare_replaces_csi_sequences_with_numbered_tokens)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char out[128];

    CHECK(translation_prepare_text("\033[31mred\033[0m plain", out,
                                   sizeof(out), ph, &count));
    CHECK_STR_EQ(out, "[[ANSI0]]red[[ANSI1]] plain");
    CHECK_EQ(count, 2);
    CHECK_STR_EQ(ph[0].sequence, "\033[31m");
    CHECK_STR_EQ(ph[0].placeholder, "[[ANSI0]]");
    CHECK_STR_EQ(ph[1].sequence, "\033[0m");
}

TEST(prepare_handles_two_byte_escape)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char out[64];

    /* ESC followed by a non-'[' byte is a two-byte sequence. */
    CHECK(translation_prepare_text("a\033Mb", out, sizeof(out), ph, &count));
    CHECK_STR_EQ(out, "a[[ANSI0]]b");
    CHECK_EQ(count, 1);
    CHECK_STR_EQ(ph[0].sequence, "\033M");
}

TEST(prepare_fails_when_output_too_small)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char out[4];

    CHECK(!translation_prepare_text("hello", out, sizeof(out), ph, &count));
    CHECK(!translation_prepare_text("\033[1m", out, sizeof(out), ph, &count));
}

TEST(prepare_fails_when_placeholder_table_full)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char input[(SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS + 1U) * 4U + 1U];
    size_t pos = 0U;
    for (size_t i = 0U; i <= SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS; ++i) {
        memcpy(input + pos, "\033[0m", 4U);
        pos += 4U;
    }
    input[pos] = '\0';

    static char out[4096];
    CHECK(!translation_prepare_text(input, out, sizeof(out), ph, &count));
}

TEST(prepare_rejects_null_arguments)
{
    translation_placeholder_t ph[1];
    size_t count = 0U;
    char out[16];

    CHECK(!translation_prepare_text(NULL, out, sizeof(out), ph, &count));
    CHECK(!translation_prepare_text("x", NULL, sizeof(out), ph, &count));
    CHECK(!translation_prepare_text("x", out, 0U, ph, &count));
    CHECK(!translation_prepare_text("x", out, sizeof(out), NULL, &count));
    CHECK(!translation_prepare_text("x", out, sizeof(out), ph, NULL));
}

TEST(restore_round_trips_prepared_text)
{
    const char *original = "\033[1;32mgreen\033[0m and \033[4munder\033[0m";
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char sanitized[256];
    char restored[256];

    CHECK(translation_prepare_text(original, sanitized, sizeof(sanitized), ph,
                                   &count));
    CHECK(translation_restore_text(sanitized, restored, sizeof(restored), ph,
                                   count));
    CHECK_STR_EQ(restored, original);
}

TEST(restore_handles_reordered_tokens)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char sanitized[128];
    char restored[128];

    CHECK(translation_prepare_text("\033[31mA\033[0mB", sanitized,
                                   sizeof(sanitized), ph, &count));
    /* A translator may move tokens around; each must still expand. */
    CHECK(translation_restore_text("B[[ANSI1]] [[ANSI0]]A", restored,
                                   sizeof(restored), ph, count));
    CHECK_STR_EQ(restored, "B\033[0m \033[31mA");
}

TEST(restore_leaves_unknown_tokens_alone)
{
    translation_placeholder_t ph[1] = {0};
    char restored[64];

    CHECK(translation_restore_text("x [[ANSI7]] y", restored,
                                   sizeof(restored), ph, 0U));
    CHECK_STR_EQ(restored, "x [[ANSI7]] y");
}

TEST(restore_reports_truncation)
{
    translation_placeholder_t ph[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t count = 0U;
    char sanitized[64];
    char restored[6];

    CHECK(translation_prepare_text("\033[31mabc", sanitized, sizeof(sanitized),
                                   ph, &count));
    CHECK(!translation_restore_text(sanitized, restored, sizeof(restored), ph,
                                    count));
    /* Output is still a terminated string. */
    CHECK(memchr(restored, '\0', sizeof(restored)) != NULL);

    CHECK(!translation_restore_text("abcdefgh", restored, sizeof(restored), ph,
                                    0U));
    CHECK(memchr(restored, '\0', sizeof(restored)) != NULL);
}

/* ---- translation_strip_no_translate_prefix ---- */

TEST(no_translate_prefix_detected_case_insensitively)
{
    char body[64];

    CHECK(translation_strip_no_translate_prefix("@nt hello", body,
                                                sizeof(body)));
    CHECK_STR_EQ(body, "hello");
    CHECK(translation_strip_no_translate_prefix("@NT   spaced", body,
                                                sizeof(body)));
    CHECK_STR_EQ(body, "spaced");
    CHECK(translation_strip_no_translate_prefix("@Nt", body, sizeof(body)));
    CHECK_STR_EQ(body, "");
}

TEST(no_translate_prefix_requires_word_boundary)
{
    char body[64];

    CHECK(!translation_strip_no_translate_prefix("@nthello", body,
                                                 sizeof(body)));
    CHECK_STR_EQ(body, "");
    CHECK(!translation_strip_no_translate_prefix("nt hello", body,
                                                 sizeof(body)));
    CHECK(!translation_strip_no_translate_prefix("@n", body, sizeof(body)));
    CHECK(!translation_strip_no_translate_prefix("", body, sizeof(body)));
    CHECK(!translation_strip_no_translate_prefix(NULL, body, sizeof(body)));
}

/* ---- to_lowercase ---- */

TEST(to_lowercase_folds_ascii_only)
{
    char text[] = "HeLLo 123 \xEA\xB0\x80";
    to_lowercase(text);
    CHECK_STR_EQ(text, "hello 123 \xEA\xB0\x80");
    to_lowercase(NULL); /* Must not crash. */
}

/* ---- get_display_width ---- */

TEST(display_width_ignores_ansi_sequences)
{
    CHECK_EQ(get_display_width("abc"), 3);
    CHECK_EQ(get_display_width("\033[1;31mabc\033[0m"), 3);
    CHECK_EQ(get_display_width(""), 0);
    CHECK_EQ(get_display_width(NULL), 0);
}

TEST(display_width_counts_wide_characters)
{
    /* "가나" is two double-width Hangul syllables. */
    CHECK_EQ(get_display_width("\xEA\xB0\x80\xEB\x82\x98"), 4);
    CHECK_EQ(get_display_width("a\xEA\xB0\x80"), 3);
}

/* ---- wrap_text_to_width ---- */

TEST(wrap_breaks_on_word_boundaries)
{
    size_t count = 0U;
    char **lines = wrap_text_to_width("the quick brown fox", 10, &count);
    CHECK(lines != NULL);
    CHECK_EQ(count, 2);
    CHECK_STR_EQ(lines[0], "the quick");
    CHECK_STR_EQ(lines[1], "brown fox");
}

TEST(wrap_honours_explicit_newlines)
{
    size_t count = 0U;
    char **lines = wrap_text_to_width("one\ntwo", 80, &count);
    CHECK(lines != NULL);
    CHECK_EQ(count, 2);
    CHECK_STR_EQ(lines[0], "one");
    CHECK_STR_EQ(lines[1], "two");
}

TEST(wrap_splits_words_longer_than_width)
{
    size_t count = 0U;
    char **lines = wrap_text_to_width("abcdefghij", 4, &count);
    CHECK(lines != NULL);
    CHECK_EQ(count, 3);
    CHECK_STR_EQ(lines[0], "abcd");
    CHECK_STR_EQ(lines[1], "efgh");
    CHECK_STR_EQ(lines[2], "ij");
}

TEST(wrap_rejects_invalid_arguments)
{
    size_t count = 7U;
    CHECK(wrap_text_to_width(NULL, 10, &count) == NULL);
    CHECK_EQ(count, 0);
    count = 7U;
    CHECK(wrap_text_to_width("x", 0, &count) == NULL);
    CHECK_EQ(count, 0);
}

int main(void)
{
    /* Width tests need a UTF-8 aware wcwidth(). */
    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL) {
        setlocale(LC_CTYPE, "en_US.UTF-8");
    }

    RUN_TEST(prepare_plain_text_is_unchanged);
    RUN_TEST(prepare_replaces_csi_sequences_with_numbered_tokens);
    RUN_TEST(prepare_handles_two_byte_escape);
    RUN_TEST(prepare_fails_when_output_too_small);
    RUN_TEST(prepare_fails_when_placeholder_table_full);
    RUN_TEST(prepare_rejects_null_arguments);
    RUN_TEST(restore_round_trips_prepared_text);
    RUN_TEST(restore_handles_reordered_tokens);
    RUN_TEST(restore_leaves_unknown_tokens_alone);
    RUN_TEST(restore_reports_truncation);
    RUN_TEST(no_translate_prefix_detected_case_insensitively);
    RUN_TEST(no_translate_prefix_requires_word_boundary);
    RUN_TEST(to_lowercase_folds_ascii_only);
    RUN_TEST(display_width_ignores_ansi_sequences);
    RUN_TEST(display_width_counts_wide_characters);
    RUN_TEST(wrap_breaks_on_word_boundaries);
    RUN_TEST(wrap_honours_explicit_newlines);
    RUN_TEST(wrap_splits_words_longer_than_width);
    RUN_TEST(wrap_rejects_invalid_arguments);
    return TEST_REPORT();
}
