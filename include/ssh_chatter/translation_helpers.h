/**
 * @file translation_helpers.h
 * @desc Text preparation around the translator. ANSI escape sequences are
 *       swapped for "[[ANSIn]]" placeholders before a line is sent to a
 *       provider and swapped back afterwards, so colors survive translation.
 */
#ifndef SSH_CHATTER_TRANSLATION_HELPERS_H
#define SSH_CHATTER_TRANSLATION_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include "host.h"

/* Maximum ANSI sequences that can be protected in one line. */
#ifndef SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS
#define SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS 32U
#endif

/* Buffer size of one placeholder token such as "[[ANSI12]]". */
#ifndef SSH_CHATTER_PLACEHOLDER_TOKEN_LEN
#define SSH_CHATTER_PLACEHOLDER_TOKEN_LEN 16U
#endif

/* Buffer size of one captured escape sequence. */
#ifndef SSH_CHATTER_PLACEHOLDER_SEQUENCE_LEN
#define SSH_CHATTER_PLACEHOLDER_SEQUENCE_LEN 64U
#endif

/* Scratch buffer size for a line in flight; translations may grow text. */
#ifndef SSH_CHATTER_TRANSLATION_WORKING_LEN
#define SSH_CHATTER_TRANSLATION_WORKING_LEN (SSH_CHATTER_MESSAGE_LIMIT * 4U)
#endif

/* Maximum lines combined into a single batched translation request. */
#ifndef SSH_CHATTER_TRANSLATION_BATCH_MAX
#define SSH_CHATTER_TRANSLATION_BATCH_MAX 16U
#endif

#ifndef SSH_CHATTER_TRANSLATION_BATCH_BUFFER
#define SSH_CHATTER_TRANSLATION_BATCH_BUFFER                                   \
    (SSH_CHATTER_TRANSLATION_WORKING_LEN * SSH_CHATTER_TRANSLATION_BATCH_MAX)
#endif

/* Buffer size for a language name ("Korean", "English", ...). */
#ifndef SSH_CHATTER_LANG_NAME_LEN
#define SSH_CHATTER_LANG_NAME_LEN 64
#endif

/* One protected escape sequence and the token that stands in for it. */
typedef struct translation_placeholder {
    char placeholder[SSH_CHATTER_PLACEHOLDER_TOKEN_LEN];
    char sequence[SSH_CHATTER_PLACEHOLDER_SEQUENCE_LEN];
} translation_placeholder_t;

/**
 * @desc Replace every ANSI escape sequence in message with a placeholder.
 * @param message           Input line.
 * @param sanitized         Receives the placeholder-substituted text.
 * @param sanitized_len     Size of sanitized.
 * @param placeholders      Array of SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS
 *                          entries that receives the captured sequences.
 * @param placeholder_count Receives the number of entries used.
 * @return false when a buffer or the placeholder table is too small.
 */
bool translation_prepare_text(const char *message, char *sanitized,
                              size_t sanitized_len,
                              translation_placeholder_t *placeholders,
                              size_t *placeholder_count);

/**
 * @desc Inverse of translation_prepare_text(): expand placeholders found in
 *       the translated text back into their original escape sequences.
 * @return false when output is too small (output is still terminated).
 */
bool translation_restore_text(const char *translated, char *output,
                              size_t output_len,
                              const translation_placeholder_t *placeholders,
                              size_t placeholder_count);

/**
 * @desc Detect the "@nt" (no-translate) prefix, case-insensitive and
 *       followed by whitespace or end of string.
 * @param message      Input line.
 * @param stripped     Receives the message body after the prefix; set to ""
 *                     when there is no prefix.
 * @param stripped_len Size of stripped.
 * @return true when the prefix was present.
 */
bool translation_strip_no_translate_prefix(const char *message, char *stripped,
                                           size_t stripped_len);

/* True when str contains only 7-bit ASCII bytes. */
bool is_pure_ascii(const char *str);

/* Lowercase str in place, byte by byte with tolower(). */
void to_lowercase(char *str);

#endif
