/**
 * @file test_security_layer.c
 * @desc Unit tests for src/security_layer.c: the onion message envelope
 *       and password hashing helpers.
 */
#include "ssh_chatter/security_layer.h"

#include "test_harness.h"

#define ENVELOPE_PREFIX "TorOnion/v1:"

TEST(encrypt_decrypt_round_trip)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));
    CHECK(layer.ready);

    const char *message = "hello, \xEC\x95\x88\xEB\x85\x95 \033[1mworld\033[0m";
    char envelope[2048];
    char plain[512];
    CHECK(security_layer_encrypt_message(&layer, message, envelope,
                                         sizeof(envelope)));
    CHECK(strncmp(envelope, ENVELOPE_PREFIX, strlen(ENVELOPE_PREFIX)) == 0);
    CHECK(strstr(envelope, "hello") == NULL);

    CHECK(security_layer_decrypt_message(&layer, envelope, plain,
                                         sizeof(plain)));
    CHECK_STR_EQ(plain, message);
    security_layer_free(&layer);
}

TEST(envelope_has_one_segment_per_level)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char envelope[2048];
    CHECK(security_layer_encrypt_message(&layer, "x", envelope,
                                         sizeof(envelope)));
    size_t dots = 0U;
    for (const char *p = envelope + strlen(ENVELOPE_PREFIX); *p != '\0'; ++p) {
        if (*p == '.') {
            ++dots;
        }
    }
    CHECK_EQ(dots, SECURITY_LAYER_LEVELS - 1);
    security_layer_free(&layer);
}

TEST(encryption_is_randomized)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char first[2048];
    char second[2048];
    CHECK(security_layer_encrypt_message(&layer, "same", first,
                                         sizeof(first)));
    CHECK(security_layer_encrypt_message(&layer, "same", second,
                                         sizeof(second)));
    CHECK(strcmp(first, second) != 0);
    security_layer_free(&layer);
}

TEST(empty_message_round_trips)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char envelope[2048];
    char plain[16] = "garbage";
    CHECK(security_layer_encrypt_message(&layer, "", envelope,
                                         sizeof(envelope)));
    CHECK(security_layer_decrypt_message(&layer, envelope, plain,
                                         sizeof(plain)));
    CHECK_STR_EQ(plain, "");
    security_layer_free(&layer);
}

TEST(tampered_envelope_is_rejected)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char envelope[2048];
    char plain[256];
    CHECK(security_layer_encrypt_message(&layer, "integrity", envelope,
                                         sizeof(envelope)));

    /* Flip one base64 character in the middle of the outer segment. */
    size_t idx = strlen(ENVELOPE_PREFIX) + 8U;
    envelope[idx] = envelope[idx] == 'A' ? 'B' : 'A';
    CHECK(!security_layer_decrypt_message(&layer, envelope, plain,
                                          sizeof(plain)));
    security_layer_free(&layer);
}

TEST(other_key_cannot_decrypt)
{
    security_layer_t a;
    security_layer_t b;
    CHECK(security_layer_init(&a));
    CHECK(security_layer_init(&b));

    char envelope[2048];
    char plain[256];
    CHECK(security_layer_encrypt_message(&a, "private", envelope,
                                         sizeof(envelope)));
    CHECK(!security_layer_decrypt_message(&b, envelope, plain, sizeof(plain)));
    security_layer_free(&a);
    security_layer_free(&b);
}

TEST(malformed_envelopes_are_rejected)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char plain[256];
    CHECK(!security_layer_decrypt_message(&layer, "", plain, sizeof(plain)));
    CHECK(!security_layer_decrypt_message(&layer, "plain text", plain,
                                          sizeof(plain)));
    CHECK(!security_layer_decrypt_message(&layer, ENVELOPE_PREFIX, plain,
                                          sizeof(plain)));
    CHECK(!security_layer_decrypt_message(&layer, ENVELOPE_PREFIX "a.b.c",
                                          plain, sizeof(plain)));
    security_layer_free(&layer);
}

TEST(small_output_buffer_fails)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));

    char envelope[16];
    CHECK(!security_layer_encrypt_message(&layer, "too long for this buffer",
                                          envelope, sizeof(envelope)));
    security_layer_free(&layer);
}

TEST(freed_layer_is_unusable)
{
    security_layer_t layer;
    CHECK(security_layer_init(&layer));
    security_layer_free(&layer);
    CHECK(!layer.ready);

    char envelope[2048];
    CHECK(!security_layer_encrypt_message(&layer, "x", envelope,
                                          sizeof(envelope)));
    security_layer_free(NULL);
}

/* ---- password hashing ---- */

TEST(legacy_hash_is_deterministic_and_salted)
{
    uint8_t salt_a[SECURITY_LAYER_SALT_LEN] = {1};
    uint8_t salt_b[SECURITY_LAYER_SALT_LEN] = {2};
    uint8_t h1[SECURITY_LAYER_HASH_LEN];
    uint8_t h2[SECURITY_LAYER_HASH_LEN];
    uint8_t h3[SECURITY_LAYER_HASH_LEN];

    security_layer_hash_password("pw", salt_a, h1);
    security_layer_hash_password("pw", salt_a, h2);
    security_layer_hash_password("pw", salt_b, h3);
    CHECK_MEM_EQ(h1, h2, sizeof(h1));
    CHECK(memcmp(h1, h3, sizeof(h1)) != 0);
    CHECK(!security_layer_is_zero_hash(h1, sizeof(h1)));
}

TEST(strong_hash_differs_from_legacy)
{
    uint8_t salt[SECURITY_LAYER_SALT_LEN] = {7};
    uint8_t legacy[SECURITY_LAYER_HASH_LEN];
    uint8_t strong1[SECURITY_LAYER_HASH_LEN];
    uint8_t strong2[SECURITY_LAYER_HASH_LEN];

    security_layer_hash_password("pw", salt, legacy);
    security_layer_hash_password_strong("pw", salt, strong1);
    security_layer_hash_password_strong("pw", salt, strong2);
    CHECK_MEM_EQ(strong1, strong2, sizeof(strong1));
    CHECK(memcmp(strong1, legacy, sizeof(strong1)) != 0);
    CHECK(!security_layer_is_zero_hash(strong1, sizeof(strong1)));
}

TEST(strong_hash_of_empty_password_matches_legacy)
{
    uint8_t salt[SECURITY_LAYER_SALT_LEN] = {9};
    uint8_t legacy[SECURITY_LAYER_HASH_LEN];
    uint8_t strong[SECURITY_LAYER_HASH_LEN];

    security_layer_hash_password("", salt, legacy);
    security_layer_hash_password_strong("", salt, strong);
    CHECK_MEM_EQ(strong, legacy, sizeof(strong));
}

TEST(generated_salts_differ)
{
    uint8_t a[SECURITY_LAYER_SALT_LEN];
    uint8_t b[SECURITY_LAYER_SALT_LEN];
    security_layer_generate_salt(a);
    security_layer_generate_salt(b);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

TEST(zero_hash_detection)
{
    uint8_t zero[SECURITY_LAYER_HASH_LEN] = {0};
    uint8_t nonzero[SECURITY_LAYER_HASH_LEN] = {0};
    nonzero[SECURITY_LAYER_HASH_LEN - 1U] = 1U;

    CHECK(security_layer_is_zero_hash(zero, sizeof(zero)));
    CHECK(!security_layer_is_zero_hash(nonzero, sizeof(nonzero)));
    CHECK(security_layer_is_zero_hash(NULL, 32U));
    CHECK(security_layer_is_zero_hash(nonzero, 0U));
}

int main(void)
{
    RUN_TEST(encrypt_decrypt_round_trip);
    RUN_TEST(envelope_has_one_segment_per_level);
    RUN_TEST(encryption_is_randomized);
    RUN_TEST(empty_message_round_trips);
    RUN_TEST(tampered_envelope_is_rejected);
    RUN_TEST(other_key_cannot_decrypt);
    RUN_TEST(malformed_envelopes_are_rejected);
    RUN_TEST(small_output_buffer_fails);
    RUN_TEST(freed_layer_is_unusable);
    RUN_TEST(legacy_hash_is_deterministic_and_salted);
    RUN_TEST(strong_hash_differs_from_legacy);
    RUN_TEST(strong_hash_of_empty_password_matches_legacy);
    RUN_TEST(generated_salts_differ);
    RUN_TEST(zero_hash_detection);
    return TEST_REPORT();
}
