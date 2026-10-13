/**
 * @file ssh_chatter_backend.h
 * @desc Small C API wrapping the translator for callers that only need
 *       "translate one line of terminal output" and the welcome banner.
 *       Usable from C++ as well.
 */
#ifndef SSH_CHATTER_BACKEND_H
#define SSH_CHATTER_BACKEND_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @desc Read the banner file at path into a newly allocated string.
 * @param path Banner file path.
 * @return The banner text (caller frees), or nullptr on error.
 */
char *session_show_welcome_banner(const char *path);

/**
 * @desc Initialize the translator backend (idempotent).
 */
void ssh_chatter_backend_init(void);

/**
 * @desc Translate one line while preserving its ANSI escape sequences. Lines
 *       starting with the "@nt" no-translate prefix are returned with the
 *       prefix removed and are not sent to a provider.
 * @param message           Line to translate (may contain ANSI escapes).
 * @param target_language   Target language name.
 * @param translated        Receives the translated line.
 * @param translated_len    Size of translated.
 * @param detected_language Optional; receives the detected source language.
 * @param detected_len      Size of detected_language.
 * @return true on success (including the no-translate case).
 */
bool ssh_chatter_backend_translate_line(const char *message,
                                        const char *target_language,
                                        char *translated, size_t translated_len,
                                        char *detected_language,
                                        size_t detected_len);

#ifdef __cplusplus
}
#endif

#endif
