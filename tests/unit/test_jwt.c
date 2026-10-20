/**
 * @file test_jwt.c
 * @desc Unit tests for src/utils/jwt.c (HS256 tokens used by the web
 *       bridge): generation, verification, expiry and tamper detection.
 */
#include "ssh_chatter/memory_manager.h"
#include "ssh_chatter/utils/jwt.h"

#include "test_harness.h"

static size_t count_char(const char *text, char ch)
{
    size_t count = 0U;
    for (; *text != '\0'; ++text) {
        if (*text == ch) {
            ++count;
        }
    }
    return count;
}

TEST(generate_produces_three_base64url_segments)
{
    char *token = jwt_generate("s3cret", "alice", 60);
    CHECK(token != NULL);
    CHECK_EQ(count_char(token, '.'), 2);
    CHECK(strchr(token, '=') == NULL);
    CHECK(strchr(token, '+') == NULL);
    CHECK(strchr(token, '/') == NULL);
    /* {"alg":"HS256","typ":"JWT"} always encodes to the same header. */
    CHECK(strncmp(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", 37U) == 0);
    sshc_gc_free(token);
}

TEST(verify_accepts_valid_token_and_returns_subject)
{
    char *token = jwt_generate("s3cret", "alice", 60);
    CHECK(token != NULL);

    char *user = NULL;
    CHECK(jwt_verify("s3cret", token, &user));
    CHECK_STR_EQ(user, "alice");
    sshc_gc_free(user);

    /* The subject output is optional. */
    CHECK(jwt_verify("s3cret", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_rejects_wrong_secret)
{
    char *token = jwt_generate("s3cret", "alice", 60);
    CHECK(token != NULL);
    CHECK(!jwt_verify("other", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_rejects_expired_token)
{
    char *token = jwt_generate("s3cret", "alice", -10);
    CHECK(token != NULL);
    CHECK(!jwt_verify("s3cret", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_rejects_tampered_payload)
{
    char *token = jwt_generate("s3cret", "alice", 60);
    CHECK(token != NULL);

    char *payload = strchr(token, '.') + 1;
    payload[2] = payload[2] == 'A' ? 'B' : 'A';
    CHECK(!jwt_verify("s3cret", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_rejects_tampered_signature)
{
    char *token = jwt_generate("s3cret", "alice", 60);
    CHECK(token != NULL);

    char *signature = strrchr(token, '.') + 1;
    signature[0] = signature[0] == 'A' ? 'B' : 'A';
    CHECK(!jwt_verify("s3cret", token, NULL));

    /* A missing signature is also rejected. */
    signature[0] = '\0';
    CHECK(!jwt_verify("s3cret", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_rejects_malformed_tokens)
{
    CHECK(!jwt_verify("s3cret", "", NULL));
    CHECK(!jwt_verify("s3cret", "no-dots", NULL));
    CHECK(!jwt_verify("s3cret", "one.dot", NULL));
    CHECK(!jwt_verify(NULL, "a.b.c", NULL));
    CHECK(!jwt_verify("s3cret", NULL, NULL));
}

TEST(generate_rejects_null_inputs)
{
    CHECK(jwt_generate(NULL, "alice", 60) == NULL);
    CHECK(jwt_generate("s3cret", NULL, 60) == NULL);
}

TEST(subjects_of_various_lengths_round_trip)
{
    /* Exercise every base64 padding remainder of the payload. */
    const char *names[] = {"a", "ab", "abc", "abcd", "abcde", "user_123"};
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i) {
        char *token = jwt_generate("k", names[i], 60);
        CHECK(token != NULL);
        char *user = NULL;
        CHECK(jwt_verify("k", token, &user));
        CHECK_STR_EQ(user, names[i]);
        sshc_gc_free(user);
        sshc_gc_free(token);
    }
}

int main(void)
{
    RUN_TEST(generate_produces_three_base64url_segments);
    RUN_TEST(verify_accepts_valid_token_and_returns_subject);
    RUN_TEST(verify_rejects_wrong_secret);
    RUN_TEST(verify_rejects_expired_token);
    RUN_TEST(verify_rejects_tampered_payload);
    RUN_TEST(verify_rejects_tampered_signature);
    RUN_TEST(verify_rejects_malformed_tokens);
    RUN_TEST(generate_rejects_null_inputs);
    RUN_TEST(subjects_of_various_lengths_round_trip);
    return TEST_REPORT();
}
