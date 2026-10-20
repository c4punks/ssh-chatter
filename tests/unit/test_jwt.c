/**
 * @file test_jwt.c
 * @desc Unit tests for src/utils/jwt.c (HS256 tokens used by the web
 *       bridge): generation, verification, expiry and tamper detection.
 *       jwt.c is #included so the static base64url helpers can be tested
 *       directly.
 */
#include "../../src/utils/jwt.c"

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

/* ---- base64url_decode regressions ---- */

TEST(decode_output_is_nul_terminated)
{
    /*
     * jwt_verify() parses the payload with strstr(), so the decoder must
     * terminate it. libttak currently hands out zeroed blocks, which hid
     * the missing terminator; this pins the contract explicitly.
     */
    size_t length = 0U;
    /* base64url("{\"sub\":\"a\"}") without padding */
    unsigned char *decoded = base64url_decode("eyJzdWIiOiJhIn0", &length);
    CHECK(decoded != NULL);
    CHECK_EQ(length, 11);
    CHECK_EQ(decoded[length], '\0');
    CHECK_STR_EQ((const char *)decoded, "{\"sub\":\"a\"}");
    sshc_gc_free(decoded);
}

TEST(decode_round_trips_encode)
{
    const char *samples[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    for (size_t i = 0U; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        char *encoded = base64url_encode((const unsigned char *)samples[i],
                                         strlen(samples[i]));
        CHECK(encoded != NULL);
        size_t length = 0U;
        unsigned char *decoded = base64url_decode(encoded, &length);
        CHECK(decoded != NULL);
        CHECK_EQ(length, strlen(samples[i]));
        CHECK_STR_EQ((const char *)decoded, samples[i]);
        sshc_gc_free(decoded);
        sshc_gc_free(encoded);
    }
}

TEST(decode_rejects_non_base64url_characters)
{
    size_t length = 0U;
    /* Standard base64 '+', '/', padding '=', and arbitrary bytes. */
    CHECK(base64url_decode("ab+d", &length) == NULL);
    CHECK(base64url_decode("ab/d", &length) == NULL);
    CHECK(base64url_decode("ab==", &length) == NULL);
    CHECK(base64url_decode("ab d", &length) == NULL);
    CHECK(base64url_decode("ab\xC3\xA9", &length) == NULL);
}

/* Sign header.payload with secret the same way jwt_generate() does. */
static char *sign_token(const char *secret, const char *header_b64,
                        const char *payload_b64)
{
    char input[512];
    snprintf(input, sizeof(input), "%s.%s", header_b64, payload_b64);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0U;
    hmac_sha256(secret, input, mac, &mac_len);
    char *signature = base64url_encode(mac, mac_len);

    size_t total = strlen(input) + 1U + strlen(signature) + 1U;
    char *token = sshc_gc_malloc(total);
    snprintf(token, total, "%s.%s", input, signature);
    sshc_gc_free(signature);
    return token;
}

TEST(verify_rejects_signed_token_with_invalid_payload_characters)
{
    /*
     * The signature is valid, but the payload is not base64url. It used to
     * decode into garbage (and, with no "exp", be accepted).
     */
    char *token = sign_token("k", "eyJhbGciOiJIUzI1NiJ9", "e30+e30/");
    CHECK(token != NULL);
    CHECK(!jwt_verify("k", token, NULL));
    sshc_gc_free(token);
}

TEST(verify_handles_unterminated_subject)
{
    /* Payload {"sub":"ab with no closing quote: must not read past it. */
    char *payload = base64url_encode((const unsigned char *)"{\"sub\":\"ab",
                                     strlen("{\"sub\":\"ab"));
    char *token = sign_token("k", "eyJhbGciOiJIUzI1NiJ9", payload);
    CHECK(token != NULL);

    char *user = NULL;
    CHECK(jwt_verify("k", token, &user));
    CHECK(user == NULL);
    sshc_gc_free(token);
    sshc_gc_free(payload);
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
    RUN_TEST(decode_output_is_nul_terminated);
    RUN_TEST(decode_round_trips_encode);
    RUN_TEST(decode_rejects_non_base64url_characters);
    RUN_TEST(verify_rejects_signed_token_with_invalid_payload_characters);
    RUN_TEST(verify_handles_unterminated_subject);
    return TEST_REPORT();
}
