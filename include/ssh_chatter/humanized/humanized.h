/**
 * @file humanized.h
 * @desc Minimal, dependency-free error logger used across the server.
 */
#ifndef SSH_CHATTER_HUMANIZED_H
#define SSH_CHATTER_HUMANIZED_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

/**
 * @desc Print "[section] message (code: N)" to stderr.
 * @param section    Subsystem tag; "unknown" when nullptr.
 * @param message    Human-readable message; when nullptr, strerror() of
 *                   error_code (or of errno if error_code is 0) is used.
 * @param error_code errno-style code included in the output.
 */
static inline void humanized_log_error(const char *section, const char *message,
                                       int error_code)
{
    if (section == nullptr) {
        section = "unknown";
    }
    if (message == nullptr) {
        message = strerror(error_code != 0 ? error_code : errno);
    }
    fprintf(stderr, "[%s] %s (code: %d)\n", section, message, error_code);
}

#endif
