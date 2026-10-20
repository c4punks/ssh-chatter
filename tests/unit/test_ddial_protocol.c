/**
 * @file test_ddial_protocol.c
 * @desc Unit tests for the DDial reply wire form
 *       ("text^ >>RE:[N] author: quote") and station key validation in
 *       src/host/ddial/protocol.c.
 */
#include "ssh_chatter/host.h"
#include "ssh_chatter/ddial_protocol.h"

#include "../../src/host/ddial/protocol.c"

#include "test_harness.h"

/* ---- ddial_format_reply_body ---- */

TEST(reply_with_line_number)
{
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(ddial_format_reply_body(out, sizeof(out),
                                  "Just put it on a party boat", 1U, "MerZz",
                                  "nope. here is the article"));
    CHECK_STR_EQ(out, "Just put it on a party boat^ >>RE:[1] MerZz: nope. "
                      "here is the article");
}

TEST(reply_without_line_number)
{
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(ddial_format_reply_body(out, sizeof(out),
                                  "zona, i need a rating.", 0U, "oxyosbourne",
                                  "ok, im paused at:49"));
    CHECK_STR_EQ(out, "zona, i need a rating.^ >>RE:oxyosbourne: ok, im "
                      "paused at:49");
}

TEST(reply_quotes_only_the_parent_text)
{
    /* Replying to a reply quotes that reply's own text, not its quote. */
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(ddial_format_reply_body(
        out, sizeof(out), "ok I /. vegas?", 0U, "oxyosbourne",
        "Just put it on a party boat^ >>RE:[1] MerZz: nope."));
    CHECK_STR_EQ(out, "ok I /. vegas?^ >>RE:oxyosbourne: Just put it on a "
                      "party boat");
}

TEST(reply_fits_the_body_limit)
{
    char text[400];
    char quote[400];
    memset(text, 't', sizeof(text) - 1U);
    text[sizeof(text) - 1U] = '\0';
    memset(quote, 'q', sizeof(quote) - 1U);
    quote[sizeof(quote) - 1U] = '\0';

    char out[1024];
    CHECK(ddial_format_reply_body(out, sizeof(out), "short", 2U, "Bob",
                                  quote));
    CHECK_EQ(strlen(out), DDIAL_MAX_BODY_LEN);
    CHECK(strncmp(out, "short^ >>RE:[2] Bob: qqq", 24U) == 0);

    /* A long reply is clipped so a little of the quote still fits. */
    CHECK(ddial_format_reply_body(out, sizeof(out), text, 2U, "Bob", quote));
    CHECK_EQ(strlen(out), DDIAL_MAX_BODY_LEN);
    CHECK(strstr(out, "^ >>RE:[2] Bob: qqqqqqqqqqqqqqqq") != NULL);
}

TEST(reply_flattens_line_breaks_and_sanitizes_author)
{
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(ddial_format_reply_body(out, sizeof(out), "a\nb", 3U, "Bo)b^",
                                  "x\r\ny"));
    CHECK_STR_EQ(out, "a b^ >>RE:[3] Bob: x  y");
}

TEST(reply_rejects_missing_parts)
{
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(!ddial_format_reply_body(out, sizeof(out), "", 1U, "Bob", "q"));
    CHECK(!ddial_format_reply_body(out, sizeof(out), "t", 1U, "", "q"));
    CHECK(!ddial_format_reply_body(out, sizeof(out), "t", 1U, "Bob", ""));
    CHECK(!ddial_format_reply_body(out, sizeof(out), NULL, 1U, "Bob", "q"));
    CHECK(!ddial_format_reply_body(out, 8U, "t", 1U, "Bob", "q"));
}

/* ---- ddial_split_reply ---- */

TEST(split_reply_with_line_number)
{
    const char *body = "it seems...^ >>RE:[2] oxyosbourne: I feel obligated";
    size_t text_len = 0U;
    uint16_t slot = 0U;
    char author[DDIAL_MAX_HANDLE_LEN];
    const char *quote = NULL;
    CHECK(ddial_split_reply(body, &text_len, &slot, author, sizeof(author),
                            &quote));
    CHECK_EQ(text_len, strlen("it seems..."));
    CHECK_EQ(slot, 2);
    CHECK_STR_EQ(author, "oxyosbourne");
    CHECK_STR_EQ(quote, "I feel obligated");
}

TEST(split_reply_without_line_number)
{
    uint16_t slot = 9U;
    char author[DDIAL_MAX_HANDLE_LEN];
    const char *quote = NULL;
    CHECK(ddial_split_reply("hi^ >>RE:Zona Mae: lmao", NULL, &slot, author,
                            sizeof(author), &quote));
    CHECK_EQ(slot, 0);
    CHECK_STR_EQ(author, "Zona Mae");
    CHECK_STR_EQ(quote, "lmao");
}

TEST(split_round_trips_format)
{
    char out[DDIAL_MAX_BODY_LEN + 1U];
    CHECK(ddial_format_reply_body(out, sizeof(out), "yes", 14U, "Ann",
                                  "are you there?"));
    size_t text_len = 0U;
    uint16_t slot = 0U;
    char author[DDIAL_MAX_HANDLE_LEN];
    const char *quote = NULL;
    CHECK(ddial_split_reply(out, &text_len, &slot, author, sizeof(author),
                            &quote));
    CHECK_EQ(text_len, 3);
    CHECK_EQ(slot, 14);
    CHECK_STR_EQ(author, "Ann");
    CHECK_STR_EQ(quote, "are you there?");
}

TEST(split_reply_in_wire_form_and_empty_brackets)
{
    uint16_t slot = 0U;
    char author[DDIAL_MAX_HANDLE_LEN];
    const char *quote = NULL;
    size_t text_len = 0U;
    CHECK(ddial_split_reply("did he say it?^ >>RE:#1[T1:MerZz) just when I",
                            &text_len, &slot, author, sizeof(author), &quote));
    CHECK_EQ(text_len, strlen("did he say it?"));
    CHECK_EQ(slot, 1);
    CHECK_STR_EQ(author, "MerZz");
    CHECK_STR_EQ(quote, "just when I");

    CHECK(ddial_split_reply("teets^ >>RE:#12(T1:Ginger Kitty) greets",
                            NULL, &slot, author, sizeof(author), &quote));
    CHECK_EQ(slot, 12);
    CHECK_STR_EQ(author, "Ginger Kitty");
    CHECK_STR_EQ(quote, "greets");

    slot = 9U;
    CHECK(ddial_split_reply("so?^ >>RE:[] darksix: spoof it", NULL, &slot,
                            author, sizeof(author), &quote));
    CHECK_EQ(slot, 0);
    CHECK_STR_EQ(author, "darksix");
    CHECK_STR_EQ(quote, "spoof it");

    CHECK(!ddial_split_reply("x^ >>RE:#1[T1:) q", NULL, NULL, NULL, 0U,
                             NULL));
}

TEST(split_rejects_non_replies)
{
    CHECK(!ddial_split_reply("plain chat", NULL, NULL, NULL, 0U, NULL));
    CHECK(!ddial_split_reply("x^ >>RE:", NULL, NULL, NULL, 0U, NULL));
    CHECK(!ddial_split_reply("x^ >>RE:[a] Bob: q", NULL, NULL, NULL, 0U,
                             NULL));
    CHECK(!ddial_split_reply("x^ >>RE:: q", NULL, NULL, NULL, 0U, NULL));
    CHECK(!ddial_split_reply(NULL, NULL, NULL, NULL, 0U, NULL));
}

/* ---- ddial_reply_quote_matches / ddial_handles_equal ---- */

TEST(quote_matches_whole_and_clipped_parent)
{
    CHECK(ddial_reply_quote_matches("nope. here is the article on it",
                                    "nope. here is the article on it"));
    CHECK(ddial_reply_quote_matches("nope. here is the article on it",
                                    "nope. here is"));
    CHECK(ddial_reply_quote_matches("nope. here is the article",
                                    "nope. here is..."));
    CHECK(ddial_reply_quote_matches("a  b\tc", "a b c"));
    CHECK(!ddial_reply_quote_matches("nope. here", "nope. there"));
    CHECK(!ddial_reply_quote_matches("short", "short and longer"));
}

TEST(quote_ignores_the_parents_own_reply_tail)
{
    CHECK(ddial_reply_quote_matches(
        "Just put it on a party boat^ >>RE:[1] MerZz: nope.",
        "Just put it on a party boat"));
    CHECK(!ddial_reply_quote_matches(
        "Just put it on a party boat^ >>RE:[1] MerZz: nope.", "nope."));
}

TEST(short_quotes_must_match_whole)
{
    CHECK(ddial_reply_quote_matches("lol", "lol"));
    CHECK(!ddial_reply_quote_matches("lolwut", "lol"));
    CHECK(!ddial_reply_quote_matches("hi", ""));
    CHECK(!ddial_reply_quote_matches(NULL, "x"));
}

TEST(handles_compare_like_the_wire)
{
    CHECK(ddial_handles_equal("MerZz", "merzz"));
    CHECK(ddial_handles_equal("Lee Yunjin", "lee yunjin"));
    CHECK(ddial_handles_equal("Bo)b", "Bob"));
    CHECK(!ddial_handles_equal("Bob", "Rob"));
    CHECK(!ddial_handles_equal("", ""));
    CHECK(!ddial_handles_equal(NULL, "a"));
}

/* ---- station keys ---- */

TEST(station_key_must_be_nine_digits)
{
    CHECK(ddial_station_key_is_wellformed("012345678"));
    CHECK(ddial_station_key_is_wellformed("999999999"));
    CHECK(!ddial_station_key_is_wellformed("12345678"));
    CHECK(!ddial_station_key_is_wellformed("1234567890"));
    CHECK(!ddial_station_key_is_wellformed("12345678a"));
    CHECK(!ddial_station_key_is_wellformed(" 12345678"));
    CHECK(!ddial_station_key_is_wellformed(""));
    CHECK(!ddial_station_key_is_wellformed(NULL));
}

int main(void)
{
    RUN_TEST(reply_with_line_number);
    RUN_TEST(reply_without_line_number);
    RUN_TEST(reply_quotes_only_the_parent_text);
    RUN_TEST(reply_fits_the_body_limit);
    RUN_TEST(reply_flattens_line_breaks_and_sanitizes_author);
    RUN_TEST(reply_rejects_missing_parts);
    RUN_TEST(split_reply_with_line_number);
    RUN_TEST(split_reply_without_line_number);
    RUN_TEST(split_round_trips_format);
    RUN_TEST(split_reply_in_wire_form_and_empty_brackets);
    RUN_TEST(split_rejects_non_replies);
    RUN_TEST(quote_matches_whole_and_clipped_parent);
    RUN_TEST(quote_ignores_the_parents_own_reply_tail);
    RUN_TEST(short_quotes_must_match_whole);
    RUN_TEST(handles_compare_like_the_wire);
    RUN_TEST(station_key_must_be_nine_digits);
    return TEST_REPORT();
}
