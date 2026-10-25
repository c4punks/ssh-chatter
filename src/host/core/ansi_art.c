/**
 * @file ansi_art.c
 * @desc ANSI art helpers for the BBS art board: an SGR-only filter for
 *       stored bodies and the color carry used when art is printed one line
 *       at a time. Only libc is used so the unit test can include this file.
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Longest SGR sequence kept; anything longer is dropped as garbage. */
#define HOST_ANSI_ART_MAX_SGR_LEN 64U

/*
 * Length of the escape sequence starting at text, or 0 when text does not
 * start with ESC. CSI runs to its final byte, OSC/DCS/SOS/PM/APC strings to
 * BEL or ST, anything else is a short ESC form. A control byte inside a CSI
 * ends it early so a broken sequence never swallows the next line.
 */
static size_t host_ansi_escape_length(const char *text)
{
    if (text == nullptr || text[0] != '\033') {
        return 0U;
    }

    const unsigned char *cursor = (const unsigned char *)text + 1;
    if (*cursor == '\0') {
        return 1U;
    }

    if (*cursor == '[') {
        ++cursor;
        while (*cursor >= 0x20U && *cursor < 0x40U) {
            ++cursor;
        }
        if (*cursor >= 0x40U && *cursor <= 0x7eU) {
            ++cursor;
        }
        return (size_t)((const char *)cursor - text);
    }

    if (*cursor == ']' || *cursor == 'P' || *cursor == 'X' ||
        *cursor == '^' || *cursor == '_') {
        ++cursor;
        while (*cursor != '\0') {
            if (*cursor == 0x07U) {
                ++cursor;
                break;
            }
            if (*cursor == 0x1bU && cursor[1] == '\\') {
                cursor += 2;
                break;
            }
            ++cursor;
        }
        return (size_t)((const char *)cursor - text);
    }

    while (*cursor >= 0x20U && *cursor <= 0x2fU) {
        ++cursor;
    }
    if (*cursor != '\0') {
        ++cursor;
    }
    return (size_t)((const char *)cursor - text);
}

/* Whether the length bytes at sequence are one SGR: ESC [ [0-9;:]* m. */
static bool host_ansi_is_sgr(const char *sequence, size_t length)
{
    if (sequence == nullptr || length < 3U ||
        length > HOST_ANSI_ART_MAX_SGR_LEN || sequence[0] != '\033' ||
        sequence[1] != '[' || sequence[length - 1U] != 'm') {
        return false;
    }

    for (size_t idx = 2U; idx + 1U < length; ++idx) {
        const char ch = sequence[idx];
        if ((ch < '0' || ch > '9') && ch != ';' && ch != ':') {
            return false;
        }
    }
    return true;
}

/* Whether an SGR starts with a reset (empty or zero first parameter). */
static bool host_ansi_sgr_starts_with_reset(const char *sequence,
                                            size_t length)
{
    size_t idx = 2U;
    while (idx + 1U < length && sequence[idx] == '0') {
        ++idx;
    }
    return idx + 1U >= length || sequence[idx] == ';' || sequence[idx] == ':';
}

/*
 * Copy input to output keeping printable text, newlines, tabs and SGR
 * sequences only. Every other escape sequence, C0/C1 control and DEL is
 * dropped, so stored art can recolor text but never move the cursor, clear
 * the screen, retitle the window or query the terminal. Output may alias
 * input. Returns the output length.
 */
static size_t host_ansi_art_sanitize(const char *input, char *output,
                                     size_t length)
{
    if (output == nullptr || length == 0U) {
        return 0U;
    }

    const char *cursor = input != nullptr ? input : "";
    size_t out = 0U;
    while (*cursor != '\0') {
        const size_t sequence = host_ansi_escape_length(cursor);
        if (sequence > 0U) {
            if (host_ansi_is_sgr(cursor, sequence) &&
                out + sequence < length) {
                memmove(output + out, cursor, sequence);
                out += sequence;
            }
            cursor += sequence;
            continue;
        }

        const unsigned char ch = (unsigned char)*cursor;
        /* U+0080..U+009F: UTF-8 terminals may act on these C1 controls. */
        if (ch == 0xc2U && (unsigned char)cursor[1] >= 0x80U &&
            (unsigned char)cursor[1] <= 0x9fU) {
            cursor += 2;
            continue;
        }
        ++cursor;
        if ((ch < 0x20U && ch != '\n' && ch != '\t') || ch == 0x7fU) {
            continue;
        }
        if (out + 1U >= length) {
            break;
        }
        output[out++] = (char)ch;
    }

    output[out] = '\0';
    return out;
}

/*
 * Fold the SGR sequences of one line (length bytes) into state, the colors
 * still active at its end, so the next line can be primed with them. A reset
 * clears the state; when it is full the newest sequence replaces it.
 */
static void host_ansi_art_track_sgr(const char *line, size_t length,
                                    char *state, size_t state_length)
{
    if (line == nullptr || state == nullptr || state_length == 0U) {
        return;
    }

    size_t used = strnlen(state, state_length - 1U);
    size_t offset = 0U;
    while (offset < length && line[offset] != '\0') {
        size_t sequence = host_ansi_escape_length(line + offset);
        if (sequence == 0U) {
            ++offset;
            continue;
        }
        if (offset + sequence > length) {
            break;
        }
        const char *sgr = line + offset;
        offset += sequence;
        if (!host_ansi_is_sgr(sgr, sequence)) {
            continue;
        }
        if (host_ansi_sgr_starts_with_reset(sgr, sequence)) {
            used = 0U;
            if (sequence <= 4U) {
                continue; /* bare reset: nothing left to carry */
            }
        }
        if (used + sequence >= state_length) {
            used = 0U;
            if (sequence >= state_length) {
                continue;
            }
        }
        memcpy(state + used, sgr, sequence);
        used += sequence;
    }
    state[used] = '\0';
}

/*
 * Build one display line: prefix, the carried state, then as much of line
 * (length bytes) as fits, cut only between whole escape sequences and whole
 * UTF-8 characters, and finally a reset so color never bleeds past it.
 */
static void host_ansi_art_compose_line(const char *prefix, const char *state,
                                       const char *line, size_t length,
                                       char *out, size_t out_length)
{
    static const char kReset[] = "\033[0m";

    if (out == nullptr || out_length == 0U) {
        return;
    }
    out[0] = '\0';
    if (out_length < sizeof(kReset)) {
        return;
    }

    const size_t limit = out_length - sizeof(kReset);
    size_t used = 0U;
    const char *heads[2] = {prefix, state};
    for (size_t part = 0U; part < 2U; ++part) {
        if (heads[part] == nullptr) {
            continue;
        }
        size_t head_length = strlen(heads[part]);
        if (used + head_length > limit) {
            head_length = 0U;
        }
        memcpy(out + used, heads[part], head_length);
        used += head_length;
    }

    size_t offset = 0U;
    while (line != nullptr && offset < length && line[offset] != '\0') {
        size_t unit = host_ansi_escape_length(line + offset);
        if (unit == 0U) {
            unit = 1U;
            while (offset + unit < length &&
                   ((unsigned char)line[offset + unit] & 0xc0U) == 0x80U) {
                ++unit;
            }
        }
        if (offset + unit > length || used + unit > limit) {
            break;
        }
        memcpy(out + used, line + offset, unit);
        used += unit;
        offset += unit;
    }

    memcpy(out + used, kReset, sizeof(kReset));
}
