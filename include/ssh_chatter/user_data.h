/**
 * @file user_data.h
 * @desc Persistent per-user profile records. Each record is stored as a
 *       fixed-size binary file under the user-data root, keyed by the
 *       sanitized username and, for unregistered names, by IP variant.
 *
 *       The struct layout below IS the on-disk format: append new fields
 *       only by consuming `reserved` or by bumping the record version in
 *       user_data.c, never by reordering existing members.
 */
#ifndef SSH_CHATTER_USER_DATA_H
#define SSH_CHATTER_USER_DATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum stored mail messages per user. */
#ifndef USER_DATA_MAILBOX_LIMIT
#define USER_DATA_MAILBOX_LIMIT 32U
#endif

/* Maximum length of one mail message. */
#ifndef USER_DATA_MAILBOX_MESSAGE_LEN
#define USER_DATA_MAILBOX_MESSAGE_LEN 256U
#endif

/* Size of the stored profile picture (ASCII art). */
#ifndef USER_DATA_PROFILE_PICTURE_LEN
#define USER_DATA_PROFILE_PICTURE_LEN 20480U
#endif

/* Number of Alpha Centauri flag-planting timestamps kept. */
#ifndef USER_DATA_FLAG_HISTORY_LIMIT
#define USER_DATA_FLAG_HISTORY_LIMIT 16U
#endif

/* These sizes are owned by host.h, which must be included first. */
#ifndef SSH_CHATTER_USERNAME_LEN
#error "SSH_CHATTER_USERNAME_LEN must be defined before including user_data.h"
#endif

#ifndef SSH_CHATTER_COLOR_CODE_LEN
#error "SSH_CHATTER_COLOR_CODE_LEN must be defined before including user_data.h"
#endif

#ifndef SSH_CHATTER_COLOR_NAME_LEN
#error "SSH_CHATTER_COLOR_NAME_LEN must be defined before including user_data.h"
#endif

#ifndef SSH_CHAT_SERVER_URL_LEN
#define SSH_CHAT_SERVER_URL_LEN 256U
#endif

/* One message in a user's mailbox. */
typedef struct user_data_mail_entry {
    uint64_t timestamp;
    char sender[SSH_CHATTER_USERNAME_LEN];
    char message[USER_DATA_MAILBOX_MESSAGE_LEN];
} user_data_mail_entry_t;

/* Saved progress of the Alpha Centauri voyage minigame. */
typedef struct alpha_centauri_save {
    uint8_t active;        /* Non-zero while a voyage is in progress */
    uint8_t stage;         /* Current mission stage */
    uint8_t eva_ready;     /* EVA unlocked for the current stage */
    uint8_t awaiting_flag; /* Arrived; waiting for the player to plant a flag */
    double velocity_fraction_c;
    double distance_travelled_ly;
    double distance_remaining_ly;
    double fuel_percent;
    double oxygen_days;
    double mission_time_years;
    double radiation_msv;
} alpha_centauri_save_t;

/* Complete persisted profile of one user (also the on-disk layout). */
typedef struct user_data_record {
    uint32_t magic;   /* File signature, checked on load */
    uint32_t version; /* Record format version; older files are upgraded */
    char username[SSH_CHATTER_USERNAME_LEN];
    char preferred_nickname[SSH_CHATTER_USERNAME_LEN];
    /* Saved /color settings, applied when has_user_theme is set. */
    uint8_t has_user_theme;
    uint8_t user_is_bold;
    char user_color_code[SSH_CHATTER_COLOR_CODE_LEN];
    char user_highlight_code[SSH_CHATTER_COLOR_CODE_LEN];
    char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
    char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
    char last_ip[SSH_CHATTER_IP_LEN]; /* Used to tell IP variants apart */
    uint32_t mailbox_count;
    user_data_mail_entry_t mailbox[USER_DATA_MAILBOX_LIMIT];
    char profile_picture[USER_DATA_PROFILE_PICTURE_LEN];
    alpha_centauri_save_t alpha;
    uint32_t flag_count;         /* Lifetime flags planted */
    uint32_t flag_history_count; /* Valid entries in flag_history */
    uint64_t flag_history[USER_DATA_FLAG_HISTORY_LIMIT]; /* Oldest first */
    uint64_t last_updated; /* Unix time of the last save */
    char ssh_chat_server_url[SSH_CHAT_SERVER_URL_LEN];
    uint16_t ssh_chat_server_port;
    uint8_t password_salt[16];
    uint8_t password_hash[32]; /* All zero when no password is set */
    /*
     * Flag bytes carved out of the reserved area (see accessors below):
     *   [0] reserved nickname applies to every IP
     *   [1] fixnick enabled
     *   [2] password hash algorithm (USER_DATA_HASH_*)
     */
    uint8_t reserved[16];
} user_data_record_t;

/* Values of reserved[2]: which hash produced password_hash. */
#define USER_DATA_HASH_LEGACY 0U
#define USER_DATA_HASH_PBKDF2 1U

/* In-memory record cache: slot count and entry lifetime. */
#ifndef USER_DATA_CACHE_SIZE
#define USER_DATA_CACHE_SIZE 64U
#endif

#ifndef USER_DATA_CACHE_TTL_SECONDS
#define USER_DATA_CACHE_TTL_SECONDS 300
#endif

typedef struct user_data_cache_entry {
    bool in_use;
    char username[SSH_CHATTER_USERNAME_LEN];
    user_data_record_t record;
    time_t loaded_at;
} user_data_cache_entry_t;

/* ---- Names and paths ---- */

/**
 * @desc Turn a nickname into a safe file name: lowercase, keep [a-z0-9-_.],
 *       map other non-space bytes to '_', drop whitespace. Falls back to
 *       "user" when nothing survives.
 */
bool user_data_sanitize_username(const char *restrict username,
                                 char *restrict sanitized, size_t length);
/* Copy input to output with ANSI escape sequences removed. */
bool user_data_strip_ansi_sequences(const char *restrict input,
                                    char *restrict output, size_t length);
/**
 * @desc Resolve the record file for a user. A username-only file is used
 *       when it belongs to a registered (password) or IP-wide name;
 *       otherwise the IP variant whose last_ip matches is chosen.
 * @param create_if_missing Pick a free variant slot when none matches.
 * @return true when path was filled.
 */
bool user_data_path_for(const char *restrict root,
                        const char *restrict username, const char *restrict ip,
                        bool create_if_missing, char *restrict path,
                        size_t length);
/* Create the user-data root and its profile subdirectory if missing. */
bool user_data_ensure_root(const char *restrict root);
/* ---- Record I/O ---- */

/* Fill record with defaults for a brand-new user. */
bool user_data_init(user_data_record_t *restrict record,
                    const char *restrict username, const char *restrict ip);
/* Load an existing record; false when none exists or it is invalid. */
bool user_data_load(const char *restrict root, const char *restrict username,
                    const char *restrict ip,
                    user_data_record_t *restrict record);
/* Persist record; ip (or record->last_ip) selects the IP variant. */
bool user_data_save(const char *restrict root,
                    const user_data_record_t *restrict record,
                    const char *restrict ip);
/* Load the record, creating and saving a default one if absent. */
bool user_data_ensure_exists(const char *restrict root,
                             const char *restrict username,
                             const char *restrict ip,
                             user_data_record_t *restrict record);
/* ---- Field accessors ---- */

/* Remote ssh-chat server URL/port remembered for this user. */
void user_data_set_ssh_chat_server_config(user_data_record_t *restrict record,
                                          const char *restrict url,
                                          uint16_t port);
void user_data_get_ssh_chat_server_config(
    const user_data_record_t *restrict record, char *restrict url,
    size_t url_len, uint16_t *restrict port);
/* True when a password hash is stored. */
bool user_data_has_password(const user_data_record_t *restrict record);
/* Nickname reservation that holds regardless of source IP (reserved[0]). */
bool user_data_reserved_nickname_is_ip_wide(
    const user_data_record_t *restrict record);
void user_data_set_reserved_nickname_ip_wide(
    user_data_record_t *restrict record, bool enabled);
/* Whether the user's nickname is pinned (reserved[1]). */
bool user_data_fixnick_enabled(const user_data_record_t *restrict record);
void user_data_set_fixnick_enabled(user_data_record_t *restrict record,
                                   bool enabled);
/* Hash algorithm of password_hash (reserved[2]); unknown values read as legacy. */
uint8_t user_data_password_hash_algorithm(
    const user_data_record_t *restrict record);
void user_data_set_password_hash_algorithm(
    user_data_record_t *restrict record, uint8_t algorithm);
/**
 * @desc Check password against the stored hash using the recorded
 *       algorithm.
 * @param was_legacy Optional; set on a match to whether the legacy hash was
 *                   used, so the caller can upgrade it.
 */
bool user_data_verify_password(const user_data_record_t *restrict record,
                               const char *restrict password,
                               bool *restrict was_legacy);
/* Re-hash password with a new salt using PBKDF2 (no-op for empty passwords). */
void user_data_upgrade_password_hash(user_data_record_t *restrict record,
                                     const char *restrict password);

#endif /* SSH_CHATTER_USER_DATA_H */
