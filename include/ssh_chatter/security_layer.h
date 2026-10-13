/**
 * @file security_layer.h
 * @desc In-memory message protection and password hashing.
 *
 *       Messages are sealed in SECURITY_LAYER_LEVELS nested AES-256-GCM
 *       layers ("onion" envelope), each with its own subkey derived from a
 *       random per-process master key. The envelope is
 *       "TorOnion/v1:<b64>.<b64>.<b64>" (outermost layer first), where each
 *       segment is base64(IV || tag || ciphertext). Because the master key is
 *       never persisted, envelopes are only readable by the same process.
 */
#ifndef SSH_CHATTER_SECURITY_LAYER_H
#define SSH_CHATTER_SECURITY_LAYER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Number of nested encryption layers. */
#define SECURITY_LAYER_LEVELS 3
/* AES-GCM nonce and tag sizes in bytes. */
#define SECURITY_LAYER_IV_LEN 12
#define SECURITY_LAYER_TAG_LEN 16
/* Password hashing: salt size, digest size and PBKDF2 work factor. */
#define SECURITY_LAYER_SALT_LEN 16
#define SECURITY_LAYER_HASH_LEN 32
#define SECURITY_LAYER_PBKDF2_ITERATIONS 100000U

typedef struct security_layer {
    unsigned char master_key[32]; /* Random at init, never stored */
    unsigned char subkeys[SECURITY_LAYER_LEVELS][32]; /* SHA-512(master || i) */
    bool ready; /* Set once keys are derived */
} security_layer_t;

/**
 * @desc Generate a fresh master key and derive the per-layer subkeys.
 * @param layer Layer to initialize.
 * @return true on success; errno is set on failure.
 */
bool security_layer_init(security_layer_t *layer);

/**
 * @desc Wipe all key material and mark the layer unusable.
 * @param layer Layer to clear (nullptr is ignored).
 */
void security_layer_free(security_layer_t *layer);

/**
 * @desc Seal plaintext into an onion envelope.
 * @param layer     Initialized layer.
 * @param plaintext NUL-terminated message.
 * @param out       Receives the envelope string.
 * @param out_len   Size of out; ENOSPC when too small.
 * @return true on success; errno is set on failure.
 */
bool security_layer_encrypt_message(const security_layer_t *layer,
                                    const char *plaintext, char *out,
                                    size_t out_len);

/**
 * @desc Open an envelope produced by security_layer_encrypt_message(),
 *       verifying the GCM tag of every layer.
 * @param layer         Layer holding the same keys used for encryption.
 * @param envelope      Envelope string.
 * @param plaintext     Receives the original message.
 * @param plaintext_len Size of plaintext.
 * @return true on success, false on malformed or tampered input.
 */
bool security_layer_decrypt_message(const security_layer_t *layer,
                                    const char *envelope, char *plaintext,
                                    size_t plaintext_len);

/* Fill salt with SECURITY_LAYER_SALT_LEN random bytes. */
void security_layer_generate_salt(uint8_t *salt);

/**
 * @desc Legacy password hash: SHA-256(salt || password). Kept so existing
 *       stored hashes keep verifying.
 * @param hash_output Receives SECURITY_LAYER_HASH_LEN bytes.
 */
void security_layer_hash_password(const char *password, const uint8_t *salt,
                                  uint8_t *hash_output);
/**
 * @desc Preferred password hash: PBKDF2-HMAC-SHA256 with
 *       SECURITY_LAYER_PBKDF2_ITERATIONS rounds. Empty passwords use the
 *       legacy hash so the "no password set" check keeps working.
 * @param hash_output Receives SECURITY_LAYER_HASH_LEN bytes (zeroed when
 *                    PBKDF2 fails).
 */
void security_layer_hash_password_strong(const char *password,
                                         const uint8_t *salt,
                                         uint8_t *hash_output);
/* True when hash is all zero bytes, nullptr or empty (no password set). */
bool security_layer_is_zero_hash(const uint8_t *hash, size_t len);

#endif
