/**
 * @file test_chardet.c
 * @desc Unit tests for src/utils/chardet.c, the UTF-8 vs. retro codepage
 *       detector used by hybrid output mode.
 */
#include "ssh_chatter/chardet.h"

#include "test_harness.h"

static bool prefers(const char *text)
{
    return sshc_chardet_prefers_utf8(text, strlen(text));
}

TEST(valid_multibyte_utf8_is_preferred)
{
    CHECK(prefers("\xEC\x95\x88\xEB\x85\x95"));        /* 안녕 */
    CHECK(prefers("caf\xC3\xA9 au lait"));               /* café */
    CHECK(prefers("\xF0\x9F\x98\x80"));                  /* emoji */
    CHECK(prefers("mixed ascii \xE3\x81\x82 kana"));     /* あ */
}

TEST(pure_ascii_is_not_preferred)
{
    CHECK(!prefers("plain ascii text"));
}

TEST(empty_or_null_is_not_preferred)
{
    CHECK(!sshc_chardet_prefers_utf8("", 0U));
    CHECK(!sshc_chardet_prefers_utf8(NULL, 10U));
}

TEST(invalid_utf8_is_not_preferred)
{
    CHECK(!prefers("\xB0\xA1"));             /* CP949 "가" */
    CHECK(!prefers("\x82\xA0"));             /* Shift-JIS "あ" */
    CHECK(!prefers("abc\xC3"));              /* truncated sequence */
    CHECK(!prefers("\xE3\x81"));             /* truncated 3-byte */
    CHECK(!prefers("\xC3\x28"));             /* bad continuation */
    CHECK(!prefers("\xFF\xFE"));             /* never valid lead bytes */
}

TEST(length_limits_the_scan)
{
    /* Only the first byte is inspected, so the multibyte tail is ignored. */
    CHECK(!sshc_chardet_prefers_utf8("a\xC3\xA9", 1U));
    /* A sequence cut by the length is invalid. */
    CHECK(!sshc_chardet_prefers_utf8("\xC3\xA9", 1U));
    CHECK(sshc_chardet_prefers_utf8("\xC3\xA9", 2U));
}

int main(void)
{
    RUN_TEST(valid_multibyte_utf8_is_preferred);
    RUN_TEST(pure_ascii_is_not_preferred);
    RUN_TEST(empty_or_null_is_not_preferred);
    RUN_TEST(invalid_utf8_is_not_preferred);
    RUN_TEST(length_limits_the_scan);
    return TEST_REPORT();
}
