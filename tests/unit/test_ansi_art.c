/**
 * @file test_ansi_art.c
 * @desc Unit tests for the BBS ANSI art helpers in
 *       src/host/core/ansi_art.c: the SGR-only filter, the color carry
 *       between lines and display line composition.
 */
#include "../../src/host/core/ansi_art.c"

#include "test_harness.h"

static const char *sanitize(const char *input)
{
    static char out[512];
    host_ansi_art_sanitize(input, out, sizeof(out));
    return out;
}

/* ---- host_ansi_art_sanitize ---- */

TEST(sgr_sequences_are_kept)
{
    CHECK_STR_EQ(sanitize("\033[1;31mred\033[0m"), "\033[1;31mred\033[0m");
    CHECK_STR_EQ(sanitize("\033[38;5;208mx\033[m"), "\033[38;5;208mx\033[m");
    CHECK_STR_EQ(sanitize("\033[38;2;255;128;0;48:2::1:2:3mx"),
                 "\033[38;2;255;128;0;48:2::1:2:3mx");
}

TEST(text_newlines_and_tabs_survive)
{
    CHECK_STR_EQ(sanitize(" /\\_/\\\n( o.o )\t|\n"),
                 " /\\_/\\\n( o.o )\t|\n");
    CHECK_STR_EQ(sanitize("\xe2\x96\x88\xe2\x96\x91 \xea\xb0\x80"),
                 "\xe2\x96\x88\xe2\x96\x91 \xea\xb0\x80");
}

TEST(cursor_and_screen_control_is_dropped)
{
    CHECK_STR_EQ(sanitize("a\033[2Jb"), "ab");
    CHECK_STR_EQ(sanitize("a\033[Hb\033[10;20Hc"), "abc");
    CHECK_STR_EQ(sanitize("a\033[5Ab\033[3Cc\033[1Gd"), "abcd");
    CHECK_STR_EQ(sanitize("a\033[6nb"), "ab");     /* DSR / CPR query */
    CHECK_STR_EQ(sanitize("a\033[?25lb"), "ab");   /* private mode */
    CHECK_STR_EQ(sanitize("a\033[?1049hb"), "ab"); /* alternate screen */
    CHECK_STR_EQ(sanitize("a\033[>cb"), "ab");     /* device attributes */
}

TEST(strings_and_short_escapes_are_dropped)
{
    CHECK_STR_EQ(sanitize("a\033]0;owned\007b"), "ab");
    CHECK_STR_EQ(sanitize("a\033]52;c;ZXZpbA==\033\\b"), "ab");
    CHECK_STR_EQ(sanitize("a\033Pq#0;2;0;0;0\033\\b"), "ab");
    CHECK_STR_EQ(sanitize("a\033cb\0337c\0338d"), "abcd");
    CHECK_STR_EQ(sanitize("a\033(0b"), "ab");
}

TEST(controls_and_c1_are_dropped)
{
    CHECK_STR_EQ(sanitize("a\rb\bc\007d\x7f" "e"), "abcde");
    /* U+009B is CSI to some UTF-8 terminals. */
    CHECK_STR_EQ(sanitize("a\xc2\x9b" "2Jb"), "a2Jb");
    CHECK_STR_EQ(sanitize("\xc2\xa0ok"), "\xc2\xa0ok");
}

TEST(sgr_lookalikes_are_dropped)
{
    CHECK_STR_EQ(sanitize("a\033[1;31;?mb"), "ab");
    CHECK_STR_EQ(sanitize("a\033[1 mb"), "ab");
    /* An unterminated CSI ends at the control byte and is dropped. */
    CHECK_STR_EQ(sanitize("a\033[31\nb"), "a\nb");
    CHECK_STR_EQ(sanitize("trailing\033["), "trailing");
    CHECK_STR_EQ(sanitize("trailing\033"), "trailing");

    char huge[128];
    size_t len = 0U;
    huge[len++] = '\033';
    huge[len++] = '[';
    while (len < 90U) {
        huge[len++] = '1';
    }
    huge[len++] = 'm';
    huge[len++] = 'x';
    huge[len] = '\0';
    CHECK_STR_EQ(sanitize(huge), "x");
}

TEST(sanitize_in_place_and_bounded)
{
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "\033[2J\033[31mhi\033]0;t\007!");
    size_t len = host_ansi_art_sanitize(buffer, buffer, sizeof(buffer));
    CHECK_STR_EQ(buffer, "\033[31mhi!");
    CHECK_EQ(len, strlen("\033[31mhi!"));

    char small[8];
    len = host_ansi_art_sanitize("\033[31mabcdef", small, sizeof(small));
    /* The SGR fits, the text is cut at the buffer end. */
    CHECK_STR_EQ(small, "\033[31mab");
    CHECK_EQ(len, 7U);

    char tiny[4];
    host_ansi_art_sanitize("\033[31mabc", tiny, sizeof(tiny));
    CHECK_STR_EQ(tiny, "abc");
}

/* ---- host_ansi_art_track_sgr ---- */

static void track(const char *line, char *state, size_t state_length)
{
    host_ansi_art_track_sgr(line, strlen(line), state, state_length);
}

TEST(state_accumulates_until_reset)
{
    char state[64] = "";
    track("\033[1mA\033[34mB", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[1m\033[34m");
    track("plain", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[1m\033[34m");
    track("x\033[0my", state, sizeof(state));
    CHECK_STR_EQ(state, "");
    track("\033[33mx\033[m", state, sizeof(state));
    CHECK_STR_EQ(state, "");
}

TEST(reset_with_attributes_restarts_state)
{
    char state[64] = "\033[1m\033[34m";
    track("\033[0;31mx", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[0;31m");
    track("\033[;32mx", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[;32m");
}

TEST(full_state_keeps_newest_sequence)
{
    char state[12] = "";
    track("\033[31m\033[44m", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[31m\033[44m");
    track("\033[1m", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[1m");
}

TEST(non_sgr_does_not_touch_state)
{
    char state[32] = "\033[35m";
    track("\033[2J\033]0;x\007", state, sizeof(state));
    CHECK_STR_EQ(state, "\033[35m");
}

/* ---- host_ansi_art_compose_line ---- */

TEST(compose_adds_prefix_state_and_reset)
{
    char out[64];
    const char *line = "ab\033[32mcd";
    host_ansi_art_compose_line("> ", "\033[1m", line, strlen(line), out,
                               sizeof(out));
    CHECK_STR_EQ(out, "> \033[1mab\033[32mcd\033[0m");

    host_ansi_art_compose_line(nullptr, nullptr, "", 0U, out, sizeof(out));
    CHECK_STR_EQ(out, "\033[0m");
}

TEST(compose_respects_line_length)
{
    char out[64];
    host_ansi_art_compose_line("", "", "abc\ndef", 3U, out, sizeof(out));
    CHECK_STR_EQ(out, "abc\033[0m");
}

TEST(compose_never_splits_sequences_or_characters)
{
    char out[12]; /* 7 bytes of room before the reset */
    const char *line = "abcd\033[31mx";
    host_ansi_art_compose_line("", "", line, strlen(line), out, sizeof(out));
    CHECK_STR_EQ(out, "abcd\033[0m");

    const char *wide = "a\xe2\x96\x88\xe2\x96\x88";
    host_ansi_art_compose_line("", "", wide, strlen(wide), out, sizeof(out));
    CHECK_STR_EQ(out, "a\xe2\x96\x88\xe2\x96\x88\033[0m");

    const char *wider = "abc\xe2\x96\x88\xe2\x96\x88";
    host_ansi_art_compose_line("", "", wider, strlen(wider), out, sizeof(out));
    CHECK_STR_EQ(out, "abc\xe2\x96\x88\033[0m");
}

int main(void)
{
    RUN_TEST(sgr_sequences_are_kept);
    RUN_TEST(text_newlines_and_tabs_survive);
    RUN_TEST(cursor_and_screen_control_is_dropped);
    RUN_TEST(strings_and_short_escapes_are_dropped);
    RUN_TEST(controls_and_c1_are_dropped);
    RUN_TEST(sgr_lookalikes_are_dropped);
    RUN_TEST(sanitize_in_place_and_bounded);
    RUN_TEST(state_accumulates_until_reset);
    RUN_TEST(reset_with_attributes_restarts_state);
    RUN_TEST(full_state_keeps_newest_sequence);
    RUN_TEST(non_sgr_does_not_touch_state);
    RUN_TEST(compose_adds_prefix_state_and_reset);
    RUN_TEST(compose_respects_line_length);
    RUN_TEST(compose_never_splits_sequences_or_characters);
    return TEST_REPORT();
}
