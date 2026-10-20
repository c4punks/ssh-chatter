/**
 * @file test_codepage.c
 * @desc Unit tests for src/codepage.c: retro codepage names, per-language
 *       defaults, byte-at-a-time decoding (single-byte tables and stateful
 *       DBCS), iconv buffer conversion and auto-detection.
 */
#include "ssh_chatter/host.h"
#include "ssh_chatter/codepage.h"

#include "test_harness.h"

/* Decode a whole buffer one byte at a time, as the session input path does. */
static size_t decode_bytes(session_codepage_t codepage, const char *input,
                           char *output, size_t capacity)
{
    session_codepage_context_t context = {0, 0};
    size_t used = 0U;
    for (const unsigned char *p = (const unsigned char *)input; *p != '\0';
         ++p) {
        used += session_codepage_byte_to_utf8(codepage, &context, *p,
                                              output + used, capacity - used);
    }
    output[used] = '\0';
    return used;
}

TEST(codepage_names)
{
    CHECK_STR_EQ(session_codepage_name(SESSION_CODEPAGE_UTF8), "UTF-8");
    CHECK_STR_EQ(session_codepage_name(SESSION_CODEPAGE_CP437), "CP437");
    CHECK_STR_EQ(session_codepage_name(SESSION_CODEPAGE_CP949), "CP949");
    CHECK_STR_EQ(session_codepage_name(SESSION_CODEPAGE_AUTO), "AUTO");
    CHECK_STR_EQ(session_codepage_name(SESSION_CODEPAGE_COUNT), "Unknown");
}

TEST(iconv_names)
{
    CHECK(session_codepage_iconv_name(SESSION_CODEPAGE_UTF8) == NULL);
    CHECK_STR_EQ(session_codepage_iconv_name(SESSION_CODEPAGE_CP949),
                 "CP949//TRANSLIT");
    CHECK_STR_EQ(session_codepage_iconv_name(SESSION_CODEPAGE_CP1251),
                 "CP1251//TRANSLIT");
}

TEST(language_defaults)
{
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_KO),
             SESSION_CODEPAGE_CP949);
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_JP),
             SESSION_CODEPAGE_CP932);
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_ZH),
             SESSION_CODEPAGE_CP936);
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_RU),
             SESSION_CODEPAGE_CP1251);
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_PL),
             SESSION_CODEPAGE_CP852);
    CHECK_EQ(session_codepage_for_language(SESSION_UI_LANGUAGE_EN),
             SESSION_CODEPAGE_CP437);
    CHECK_EQ(session_codepage_for_language(-1), SESSION_CODEPAGE_CP437);
}

TEST(ascii_passes_through_every_codepage)
{
    char out[64];
    for (int cp = SESSION_CODEPAGE_UTF8; cp < SESSION_CODEPAGE_AUTO; ++cp) {
        decode_bytes((session_codepage_t)cp, "Hi 42!", out, sizeof(out));
        CHECK_STR_EQ(out, "Hi 42!");
    }
}

TEST(cp437_single_byte_table)
{
    char out[64];
    /* 0x80 = Ç, 0xC9 = ╔, 0xDB = █ */
    decode_bytes(SESSION_CODEPAGE_CP437, "\x80\xC9\xDB", out, sizeof(out));
    CHECK_STR_EQ(out, "\xC3\x87\xE2\x95\x94\xE2\x96\x88");
}

TEST(cp1251_single_byte_table)
{
    char out[64];
    /* 0xC0 = А, 0xFF = я */
    decode_bytes(SESSION_CODEPAGE_CP1251, "\xC0\xFF", out, sizeof(out));
    CHECK_STR_EQ(out, "\xD0\x90\xD1\x8F");
}

TEST(cp949_lead_byte_waits_for_trail)
{
    session_codepage_context_t context = {0, 0};
    char out[16];

    /* "가" is B0 A1 in CP949. */
    CHECK_EQ(session_codepage_byte_to_utf8(SESSION_CODEPAGE_CP949, &context,
                                           0xB0U, out, sizeof(out)),
             0);
    CHECK_EQ(context.state, 1);
    size_t n = session_codepage_byte_to_utf8(SESSION_CODEPAGE_CP949, &context,
                                             0xA1U, out, sizeof(out));
    CHECK_EQ(n, 3);
    CHECK_MEM_EQ(out, "\xEA\xB0\x80", 3U);
    CHECK_EQ(context.state, 0);
}

TEST(cp949_sentence_decodes)
{
    char out[64];
    /* "한글 ok" */
    decode_bytes(SESSION_CODEPAGE_CP949, "\xC7\xD1\xB1\xDB ok", out,
                 sizeof(out));
    CHECK_STR_EQ(out, "\xED\x95\x9C\xEA\xB8\x80 ok");
}

TEST(cp932_sentence_decodes)
{
    char out[64];
    /* "あい" in Shift-JIS */
    decode_bytes(SESSION_CODEPAGE_CP932, "\x82\xA0\x82\xA2", out, sizeof(out));
    CHECK_STR_EQ(out, "\xE3\x81\x82\xE3\x81\x84");
}

TEST(invalid_dbcs_pair_is_replaced_not_dropped)
{
    char out[64];
    /*
     * Lead byte followed by a digit: 0x30 is not a CP949 trail byte, so the
     * pair is replaced with '?' and the digit is still decoded.
     */
    decode_bytes(SESSION_CODEPAGE_CP949, "\xB0" "0", out, sizeof(out));
    CHECK_STR_EQ(out, "?0");
}

TEST(buffer_to_utf8_and_back)
{
    const char *utf8 = "\xED\x95\x9C\xEA\xB8\x80";  /* 한글 */
    const unsigned char cp949[] = {0xC7, 0xD1, 0xB1, 0xDB};
    char out[64];

    size_t n = session_codepage_to_utf8(SESSION_CODEPAGE_CP949, cp949,
                                        sizeof(cp949), out, sizeof(out));
    CHECK_EQ(n, strlen(utf8));
    CHECK_MEM_EQ(out, utf8, n);

    n = session_utf8_to_codepage(SESSION_CODEPAGE_CP949, utf8, strlen(utf8),
                                 out, sizeof(out));
    CHECK_EQ(n, sizeof(cp949));
    CHECK_MEM_EQ(out, cp949, n);
}

TEST(utf8_to_utf8_is_a_copy)
{
    char out[8];
    size_t n = session_utf8_to_codepage(SESSION_CODEPAGE_UTF8, "abc", 3U, out,
                                        sizeof(out));
    CHECK_EQ(n, 3);
    CHECK_MEM_EQ(out, "abc", 3U);
    CHECK_EQ(session_utf8_to_codepage(SESSION_CODEPAGE_UTF8, "abc", 0U, out,
                                      sizeof(out)),
             0);
}

TEST(auto_detect)
{
    const unsigned char utf8[] = "\xED\x95\x9C\xEA\xB8\x80 hi";
    const unsigned char ascii[] = "hello";
    /* Shift-JIS "ア" (0x83 0x41): only the 0x81-0x9F lead range is hit. */
    const unsigned char sjis[] = {0x83, 0x41};

    CHECK_EQ(session_codepage_detect_auto(utf8, sizeof(utf8) - 1U),
             SESSION_CODEPAGE_UTF8);
    CHECK_EQ(session_codepage_detect_auto(ascii, sizeof(ascii) - 1U),
             SESSION_CODEPAGE_UTF8);
    CHECK_EQ(session_codepage_detect_auto(NULL, 0U), SESSION_CODEPAGE_UTF8);
#ifndef SSH_CHATTER_HAVE_UCHARDET
    CHECK_EQ(session_codepage_detect_auto(sjis, sizeof(sjis)),
             SESSION_CODEPAGE_CP932);
#endif
}

/*
 * Regression: without uchardet the CP949 branch used to be unreachable
 * because every EUC-KR Hangul lead byte also set the GB2312 flag.
 */
TEST(auto_detect_heuristic_by_pairs)
{
#ifndef SSH_CHATTER_HAVE_UCHARDET
    /* "한글 테스트" in CP949 */
    const unsigned char korean[] = {0xC7, 0xD1, 0xB1, 0xDB, ' ', 0xC5,
                                    0xD7, 0xBD, 0xBA, 0xC6, 0xAE};
    /* "中文" in GBK: leads outside the Hangul range */
    const unsigned char chinese[] = {0xD6, 0xD0, 0xCE, 0xC4};
    /* "中国" in GBK: one pair in the Hangul lead range, one outside */
    const unsigned char mixed[] = {0xD6, 0xD0, 0xB9, 0xFA};
    /* "あい日本" in Shift-JIS */
    const unsigned char japanese[] = {0x82, 0xA0, 0x82, 0xA2,
                                      0x93, 0xFA, 0x96, 0x7B};
    /* Lone trailing lead byte is ignored rather than misread. */
    const unsigned char truncated[] = {'o', 'k', 0xC7};

    CHECK_EQ(session_codepage_detect_auto(korean, sizeof(korean)),
             SESSION_CODEPAGE_CP949);
    CHECK_EQ(session_codepage_detect_auto(chinese, sizeof(chinese)),
             SESSION_CODEPAGE_CP936);
    CHECK_EQ(session_codepage_detect_auto(mixed, sizeof(mixed)),
             SESSION_CODEPAGE_CP936);
    CHECK_EQ(session_codepage_detect_auto(japanese, sizeof(japanese)),
             SESSION_CODEPAGE_CP932);
    CHECK_EQ(session_codepage_detect_auto(truncated, sizeof(truncated)),
             SESSION_CODEPAGE_UTF8);
#endif
}

int main(void)
{
    RUN_TEST(codepage_names);
    RUN_TEST(iconv_names);
    RUN_TEST(language_defaults);
    RUN_TEST(ascii_passes_through_every_codepage);
    RUN_TEST(cp437_single_byte_table);
    RUN_TEST(cp1251_single_byte_table);
    RUN_TEST(cp949_lead_byte_waits_for_trail);
    RUN_TEST(cp949_sentence_decodes);
    RUN_TEST(cp932_sentence_decodes);
    RUN_TEST(invalid_dbcs_pair_is_replaced_not_dropped);
    RUN_TEST(buffer_to_utf8_and_back);
    RUN_TEST(utf8_to_utf8_is_a_copy);
    RUN_TEST(auto_detect);
    RUN_TEST(auto_detect_heuristic_by_pairs);
    return TEST_REPORT();
}
