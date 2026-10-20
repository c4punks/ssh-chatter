/**
 * @file ddial_protocol.c
 * @desc Diversi Dial protocol parser and formatter.
 *
 * Reference: Diversi-DIAL Master 6502 assembly (refs/ddialmaster/dialmstr.txt)
 * and Retro-Dial/magviz.ca wire conventions.
 */

#include "ssh_chatter/ddial_protocol.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *ddial_tier_symbol(ddial_user_tier_t tier)
{
    switch (tier) {
    case DDIAL_TIER_PASSWORD:
        return "*";
    case DDIAL_TIER_MASTER:
        return "$";
    case DDIAL_TIER_GUEST:
    default:
        return "";
    }
}

static const char *ddial_tier_bracket_open(ddial_user_tier_t tier)
{
    switch (tier) {
    case DDIAL_TIER_PASSWORD:
        return "[";
    case DDIAL_TIER_MASTER:
        return "<";
    case DDIAL_TIER_GUEST:
    default:
        return "(";
    }
}

static const char *ddial_tier_bracket_close(ddial_user_tier_t tier)
{
    switch (tier) {
    case DDIAL_TIER_PASSWORD:
        return "]";
    case DDIAL_TIER_MASTER:
        return ">";
    case DDIAL_TIER_GUEST:
    default:
        return ")";
    }
}

/* Copy a handle for the wire: strip ANSI noise, then drop the characters the
 * protocol forbids in handles ('^' ')' '}' CR LF, plus the other bracket
 * closers that would terminate the handle early), and cap the result at
 * DDIAL_MAX_HANDLE_WIRE_LEN. */
size_t ddial_sanitize_handle(const char *src, size_t src_len, char *dst,
                             size_t dst_cap)
{
    if (dst == nullptr || dst_cap == 0U) {
        return 0U;
    }
    dst[0] = '\0';
    if (src == nullptr) {
        return 0U;
    }

    char stripped[DDIAL_MAX_HANDLE_LEN];
    ddial_strip_ansi(src, src_len, stripped, sizeof(stripped));

    size_t j = 0U;
    for (size_t i = 0U; stripped[i] != '\0' && j + 1U < dst_cap &&
                        j < DDIAL_MAX_HANDLE_WIRE_LEN;
         ++i) {
        unsigned char c = (unsigned char)stripped[i];
        if (c == '^' || c == ')' || c == '}' || c == ']' || c == '>' ||
            c == '\r' || c == '\n') {
            continue;
        }
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return j;
}

/* Line numbers containing the digit 8 or 9 are invalid on strict ddials
 * (only 7 modem slots per board: 0-7, 10-17, 20-27, ...). */
bool ddial_slot_is_valid(uint16_t slot)
{
    uint16_t n = slot;
    if (n == 0U) {
        return true;
    }
    while (n > 0U) {
        uint16_t digit = (uint16_t)(n % 10U);
        if (digit == 8U || digit == 9U) {
            return false;
        }
        n = (uint16_t)(n / 10U);
    }
    return true;
}

/* Truncate a message body to the 255-char ddial limit and make sure it does
 * not carry an embedded CR/LF (the line terminator must appear only once, at
 * the very end of the wire line). */
static size_t ddial_clean_body(const char *message, char *dst, size_t dst_cap)
{
    if (dst == nullptr || dst_cap == 0U) {
        return 0U;
    }
    dst[0] = '\0';
    if (message == nullptr) {
        return 0U;
    }
    size_t j = 0U;
    for (size_t i = 0U; message[i] != '\0' && j + 1U < dst_cap &&
                        j < DDIAL_MAX_BODY_LEN;
         ++i) {
        char c = message[i];
        if (c == '\r' || c == '\n') {
            break;
        }
        dst[j++] = c;
    }
    dst[j] = '\0';
    return j;
}

ddial_command_t ddial_parse_command(const char *line, size_t line_len,
                                    ddial_parsed_message_t *out_msg)
{
    if (line == nullptr || line_len == 0U || out_msg == nullptr) {
        return DDIAL_CMD_UNKNOWN;
    }

    memset(out_msg, 0, sizeof(*out_msg));
    out_msg->channel = DDIAL_DEFAULT_CHANNEL;

    size_t pos = 0U;
    while (pos < line_len && isspace((unsigned char)line[pos])) {
        ++pos;
    }
    if (pos >= line_len) {
        return DDIAL_CMD_UNKNOWN;
    }

    if (line[pos] != '/') {
        /* Bare text is treated as chat on current channel. */
        out_msg->command = DDIAL_CMD_CHAT;
        size_t copy_len = line_len - pos;
        if (copy_len >= sizeof(out_msg->body)) {
            copy_len = sizeof(out_msg->body) - 1U;
        }
        memcpy(out_msg->body, line + pos, copy_len);
        out_msg->body[copy_len] = '\0';
        return DDIAL_CMD_CHAT;
    }

    if (pos + 1U >= line_len) {
        return DDIAL_CMD_UNKNOWN;
    }

    char cmd_char = (char)toupper((unsigned char)line[pos + 1U]);
    size_t arg_start = pos + 2U;
    while (arg_start < line_len && isspace((unsigned char)line[arg_start])) {
        ++arg_start;
    }
    const char *args = (arg_start < line_len) ? line + arg_start : "";
    size_t args_len = (arg_start < line_len) ? line_len - arg_start : 0U;

    switch (cmd_char) {
    case 'C':
        out_msg->command = DDIAL_CMD_CHAT;
        break;
    case 'P':
        out_msg->command = DDIAL_CMD_PRIVATE;
        break;
    case 'J':
        out_msg->command = DDIAL_CMD_JOIN;
        break;
    case 'W':
        out_msg->command = DDIAL_CMD_WHO;
        return DDIAL_CMD_WHO;
    case 'E':
        out_msg->command = DDIAL_CMD_MAIL;
        return DDIAL_CMD_MAIL;
    case 'Q':
        out_msg->command = DDIAL_CMD_QUIT;
        return DDIAL_CMD_QUIT;
    case 'H':
    case '?':
        out_msg->command = DDIAL_CMD_HELP;
        return DDIAL_CMD_HELP;
    case 'T':
        out_msg->command = DDIAL_CMD_TIME;
        return DDIAL_CMD_TIME;
    case 'U':
        out_msg->command = DDIAL_CMD_USERS;
        return DDIAL_CMD_USERS;
    case 'S':
        out_msg->command = DDIAL_CMD_STATS;
        return DDIAL_CMD_STATS;
    case 'N':
        out_msg->command = DDIAL_CMD_NEWS;
        return DDIAL_CMD_NEWS;
    case 'I':
        out_msg->command = DDIAL_CMD_INFO;
        return DDIAL_CMD_INFO;
    case 'V':
        out_msg->command = DDIAL_CMD_VERSION;
        return DDIAL_CMD_VERSION;
    case 'B':
        out_msg->command = DDIAL_CMD_BELL;
        return DDIAL_CMD_BELL;
    case 'D':
        out_msg->command = DDIAL_CMD_DUPLEX;
        return DDIAL_CMD_DUPLEX;
    case 'K':
        out_msg->command = DDIAL_CMD_KICK;
        /* Argument is the target slot number. */
        {
            size_t body_len = args_len;
            if (body_len >= sizeof(out_msg->body)) {
                body_len = sizeof(out_msg->body) - 1U;
            }
            if (body_len > 0U) {
                memcpy(out_msg->body, args, body_len);
                out_msg->body[body_len] = '\0';
            }
        }
        return DDIAL_CMD_KICK;
    default:
        return DDIAL_CMD_UNKNOWN;
    }

    if (out_msg->command == DDIAL_CMD_PRIVATE && args_len > 0U) {
        /* Format: /P<handle><message> (handle is first token) */
        size_t name_start = 0U;
        while (name_start < args_len &&
               isspace((unsigned char)args[name_start])) {
            ++name_start;
        }
        size_t name_end = name_start;
        while (name_end < args_len &&
               !isspace((unsigned char)args[name_end])) {
            ++name_end;
        }
        size_t name_len = name_end - name_start;
        if (name_len > 0U && name_len < sizeof(out_msg->handle)) {
            memcpy(out_msg->handle, args + name_start, name_len);
            out_msg->handle[name_len] = '\0';
        }
        size_t body_start = name_end;
        while (body_start < args_len &&
               isspace((unsigned char)args[body_start])) {
            ++body_start;
        }
        size_t body_len = args_len - body_start;
        if (body_len >= sizeof(out_msg->body)) {
            body_len = sizeof(out_msg->body) - 1U;
        }
        if (body_len > 0U) {
            memcpy(out_msg->body, args + body_start, body_len);
            out_msg->body[body_len] = '\0';
        }
    } else if (out_msg->command == DDIAL_CMD_JOIN && args_len > 0U) {
        int ch = args[0] - '0';
        if (ch >= DDIAL_MIN_CHANNEL && ch <= DDIAL_MAX_CHANNEL) {
            out_msg->channel = (uint8_t)ch;
        }
    } else {
        size_t body_len = args_len;
        if (body_len >= sizeof(out_msg->body)) {
            body_len = sizeof(out_msg->body) - 1U;
        }
        if (body_len > 0U) {
            memcpy(out_msg->body, args, body_len);
            out_msg->body[body_len] = '\0';
        }
    }

    return out_msg->command;
}

bool ddial_format_chat(char *dst, size_t dst_cap, uint16_t slot,
                       uint8_t channel, ddial_user_tier_t tier,
                       const char *handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr ||
        message == nullptr) {
        return false;
    }

    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));

    const char *bo = ddial_tier_bracket_open(tier);
    const char *bc = ddial_tier_bracket_close(tier);
    const char *sym = ddial_tier_symbol(tier);

    if (channel < DDIAL_MIN_CHANNEL) {
        channel = DDIAL_DEFAULT_CHANNEL;
    }
    if (channel > DDIAL_MAX_CHANNEL) {
        channel = DDIAL_MAX_CHANNEL;
    }

    int written = snprintf(dst, dst_cap, "#%u%sT%u:%s%s%s %s\r\n",
                           (unsigned int)slot, bo, (unsigned int)channel,
                           clean_handle, sym, bc, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

bool ddial_format_private(char *dst, size_t dst_cap, uint16_t from_slot,
                          const char *from_handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || from_handle == nullptr ||
        message == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(from_handle, strlen(from_handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));
    int written =
        snprintf(dst, dst_cap, "IM from #%u[%s]: %s\r\n",
                 (unsigned int)from_slot, clean_handle, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

bool ddial_format_who_entry(char *dst, size_t dst_cap, uint16_t slot,
                            uint8_t channel, ddial_user_tier_t tier,
                            const char *handle, uint16_t account)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    const char *bo = ddial_tier_bracket_open(tier);
    const char *bc = ddial_tier_bracket_close(tier);
    const char *sym = ddial_tier_symbol(tier);

    int written =
        snprintf(dst, dst_cap, "#%u%sT%u:%s%s%s #%03u\r\n",
                 (unsigned int)slot, bo, (unsigned int)channel, clean_handle,
                 sym, bc, (unsigned int)account);
    return written > 0 && (size_t)written < dst_cap;
}

/* Link-mode public chat: #slot[Tchan:handle) message\r\n  (no tier symbol in
 * the on-wire form sent over a link -- the bracket already encodes the tier). */
bool ddial_format_link_chat(char *dst, size_t dst_cap, uint16_t slot,
                            uint8_t channel, ddial_user_tier_t tier,
                            const char *handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr ||
        message == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));
    const char *bo = ddial_tier_bracket_open(tier);
    if (channel < DDIAL_MIN_CHANNEL) { channel = DDIAL_DEFAULT_CHANNEL; }
    if (channel > DDIAL_MAX_CHANNEL)  { channel = DDIAL_MAX_CHANNEL; }
    int written = snprintf(dst, dst_cap, "#%u%sT%u:%s) %s\r\n",
                           (unsigned int)slot, bo,
                           (unsigned int)channel, clean_handle, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

/* Dual-channel link chat: same wire form as link chat but prefixed with '~'
 * so the remote station posts it on the "other" tuned channel. */
bool ddial_format_link_dual_chat(char *dst, size_t dst_cap, uint16_t slot,
                                 uint8_t channel, ddial_user_tier_t tier,
                                 const char *handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr ||
        message == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));
    const char *bo = ddial_tier_bracket_open(tier);
    if (channel < DDIAL_MIN_CHANNEL) { channel = DDIAL_DEFAULT_CHANNEL; }
    if (channel > DDIAL_MAX_CHANNEL)  { channel = DDIAL_MAX_CHANNEL; }
    int written = snprintf(dst, dst_cap, "~#%u%sT%u:%s) %s\r\n",
                           (unsigned int)slot, bo,
                           (unsigned int)channel, clean_handle, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

/* Station broadcast list header: "}}}-.<station>" ("}}}-," when locked). */
bool ddial_format_broadcast_header(char *dst, size_t dst_cap,
                                   const char *station_name,
                                   bool station_locked)
{
    if (dst == nullptr || dst_cap == 0U || station_name == nullptr ||
        station_name[0] == '\0') {
        return false;
    }
    char clean_name[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(station_name, strlen(station_name), clean_name,
                          sizeof(clean_name));
    if (clean_name[0] == '\0') {
        return false;
    }
    int written = snprintf(dst, dst_cap, "}}}-%c%s",
                           station_locked ? ',' : '.', clean_name);
    return written > 0 && (size_t)written < dst_cap;
}

/* One user entry in a station broadcast list: "^#<slot>[T<ch>:<handle>:<acct>".
 * Link users use '=' as the line type: "^#99[T1=Hard Drive Cafe:902". */
bool ddial_format_broadcast_entry(char *dst, size_t dst_cap, uint16_t slot,
                                  uint8_t channel, ddial_user_tier_t tier,
                                  const char *handle, uint16_t account,
                                  bool is_link)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    const char *bo = ddial_tier_bracket_open(tier);
    if (channel < DDIAL_MIN_CHANNEL) { channel = DDIAL_DEFAULT_CHANNEL; }
    if (channel > DDIAL_MAX_CHANNEL)  { channel = DDIAL_MAX_CHANNEL; }
    int written;
    if (is_link) {
        written = snprintf(dst, dst_cap, "^#%u%sT%u=%s:%u",
                           (unsigned int)slot, bo, (unsigned int)channel,
                           clean_handle, (unsigned int)account);
    } else if (tier == DDIAL_TIER_GUEST) {
        /* Guests appear without an account number. */
        written = snprintf(dst, dst_cap, "^#%u%sT%u:%s",
                           (unsigned int)slot, bo, (unsigned int)channel,
                           clean_handle);
    } else {
        written = snprintf(dst, dst_cap, "^#%u%sT%u:%s:%u",
                           (unsigned int)slot, bo, (unsigned int)channel,
                           clean_handle, (unsigned int)account);
    }
    return written > 0 && (size_t)written < dst_cap;
}

/* Link-mode private message sent to a target slot on the remote station.
 * Format: /P<target_slot> #<our_slot>[T<ch>:<our_handle>) <message>\r\n */
bool ddial_format_link_private(char *dst, size_t dst_cap,
                               uint16_t target_slot,
                               uint16_t our_slot, uint8_t channel,
                               ddial_user_tier_t our_tier,
                               const char *our_handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || our_handle == nullptr ||
        message == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(our_handle, strlen(our_handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));
    const char *bo = ddial_tier_bracket_open(our_tier);
    if (channel < DDIAL_MIN_CHANNEL) { channel = DDIAL_DEFAULT_CHANNEL; }
    if (channel > DDIAL_MAX_CHANNEL)  { channel = DDIAL_MAX_CHANNEL; }
    int written = snprintf(dst, dst_cap,
                           "/P%u #%u%sT%u:%s) %s\r\n",
                           (unsigned int)target_slot,
                           (unsigned int)our_slot, bo,
                           (unsigned int)channel, clean_handle, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

/* Link-mode email routing.
 * Format: /E~<to_station_padded>(<from_account>:<from_handle>) <message>\r\n
 * Example: /E~001123(002:User) hello */
bool ddial_format_link_email(char *dst, size_t dst_cap,
                             uint16_t to_station, uint16_t from_account,
                             const char *from_handle, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || from_handle == nullptr ||
        message == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(from_handle, strlen(from_handle), clean_handle,
                          sizeof(clean_handle));
    char clean_body[DDIAL_MAX_BODY_LEN + 1U];
    ddial_clean_body(message, clean_body, sizeof(clean_body));
    int written = snprintf(dst, dst_cap,
                           "/E~%03u(%03u:%s) %s\r\n",
                           (unsigned int)to_station,
                           (unsigned int)from_account,
                           clean_handle, clean_body);
    return written > 0 && (size_t)written < dst_cap;
}

static bool ddial_format_link_event(char *dst, size_t dst_cap,
                                    uint16_t slot, uint8_t channel,
                                    ddial_user_tier_t tier,
                                    const char *handle, uint16_t account,
                                    bool is_link, bool station_locked,
                                    bool is_login);

/* Member login broadcast over a link.
 *   member: }-->. +^#<slot>[T<ch>:<handle>:#<account>*\r\n
 *   guest:  }}-->. +^#<slot>(T<ch>:?\r\n
 *   link:   }-->. +^#<slot>[T<ch>=<station>\r\n
 * If locked use ',' instead of '.'. */
bool ddial_format_link_login(char *dst, size_t dst_cap,
                             uint16_t slot, uint8_t channel,
                             ddial_user_tier_t tier,
                             const char *handle, uint16_t account,
                             bool is_link, bool station_locked)
{
    return ddial_format_link_event(dst, dst_cap, slot, channel, tier, handle,
                                   account, is_link, station_locked, true);
}

/* Member logout broadcast over a link. */
bool ddial_format_link_logout(char *dst, size_t dst_cap,
                              uint16_t slot, uint8_t channel,
                              ddial_user_tier_t tier,
                              const char *handle, uint16_t account,
                              bool is_link, bool station_locked)
{
    return ddial_format_link_event(dst, dst_cap, slot, channel, tier, handle,
                                   account, is_link, station_locked, false);
}

static bool ddial_format_link_event(char *dst, size_t dst_cap,
                                    uint16_t slot, uint8_t channel,
                                    ddial_user_tier_t tier,
                                    const char *handle, uint16_t account,
                                    bool is_link, bool station_locked,
                                    bool is_login)
{
    if (dst == nullptr || dst_cap == 0U || handle == nullptr) {
        return false;
    }
    char clean_handle[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(handle, strlen(handle), clean_handle,
                          sizeof(clean_handle));
    const char *bo = ddial_tier_bracket_open(tier);
    /* Member/link = }, Guest = }} */
    const char *prefix = (tier == DDIAL_TIER_GUEST) ? "}}" : "}";
    char lock_char = station_locked ? ',' : '.';
    char sign = is_login ? '+' : '-';
    if (channel < DDIAL_MIN_CHANNEL) { channel = DDIAL_DEFAULT_CHANNEL; }
    if (channel > DDIAL_MAX_CHANNEL)  { channel = DDIAL_MAX_CHANNEL; }

    int written;
    if (is_link) {
        written = snprintf(dst, dst_cap, "%s-->%c %c^#%u%sT%u=%s\r\n",
                           prefix, lock_char, sign, (unsigned int)slot, bo,
                           (unsigned int)channel, clean_handle);
    } else if (tier == DDIAL_TIER_GUEST) {
        written = snprintf(dst, dst_cap, "%s-->%c %c^#%u%sT%u:?\r\n",
                           prefix, lock_char, sign, (unsigned int)slot, bo,
                           (unsigned int)channel);
    } else if (account > 0U) {
        written = snprintf(dst, dst_cap, "%s-->%c %c^#%u%sT%u:%s:#%u*\r\n",
                           prefix, lock_char, sign, (unsigned int)slot, bo,
                           (unsigned int)channel, clean_handle,
                           (unsigned int)account);
    } else {
        written = snprintf(dst, dst_cap, "%s-->%c %c^#%u%sT%u:%s\r\n",
                           prefix, lock_char, sign, (unsigned int)slot, bo,
                           (unsigned int)channel, clean_handle);
    }
    return written > 0 && (size_t)written < dst_cap;
}

/* Expand DDial caret-newlines: replace every '^' with '\n' in-place.
 * Returns the new string length. */
size_t ddial_expand_carets(const char *src, size_t src_len,
                           char *dst, size_t dst_cap)
{
    if (src == nullptr || dst == nullptr || dst_cap == 0U) {
        return 0U;
    }
    size_t j = 0U;
    for (size_t i = 0U; i < src_len && j + 1U < dst_cap; ++i) {
        if (src[i] == '^') {
            dst[j++] = '\n';
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
    return j;
}

/* Parse an inbound link broadcast prefix.
 * Returns DDIAL_LINK_MSG_UNKNOWN if the line does not start with '}'.
 * On success fills *out_kind and advances *p past the prefix bytes. */
ddial_link_msg_t ddial_parse_link_prefix(const char *line,
                                          const char **out_rest)
{
    if (line == nullptr || line[0] != '}') {
        if (out_rest) *out_rest = line;
        return DDIAL_LINK_MSG_UNKNOWN;
    }
    if (line[1] != '\0' && line[1] == '}' && line[2] == '}') {
        if (out_rest) *out_rest = line + 3;
        return DDIAL_LINK_MSG_STATION_BROADCAST;
    }
    if (line[1] == '}') {
        if (out_rest) *out_rest = line + 2;
        return DDIAL_LINK_MSG_GUEST_EVENT;
    }
    if (out_rest) *out_rest = line + 1;
    return DDIAL_LINK_MSG_MEMBER_EVENT;
}

bool ddial_format_prompt(char *dst, size_t dst_cap)
{
    if (dst == nullptr || dst_cap == 0U) {
        return false;
    }
    int written = snprintf(dst, dst_cap, "--> ");
    return written > 0 && (size_t)written < dst_cap;
}

bool ddial_format_system(char *dst, size_t dst_cap, const char *message)
{
    if (dst == nullptr || dst_cap == 0U || message == nullptr) {
        return false;
    }
    int written = snprintf(dst, dst_cap, "** %s **\r\n", message);
    return written > 0 && (size_t)written < dst_cap;
}

size_t ddial_strip_ansi(const char *src, size_t src_len, char *dst,
                        size_t dst_cap)
{
    if (src == nullptr || dst == nullptr || dst_cap == 0U) {
        return 0U;
    }

    size_t j = 0U;
    for (size_t i = 0U; i < src_len && j + 1U < dst_cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == 0x1B) {
            if (i + 1U < src_len && src[i + 1U] == '[') {
                i += 2U;
                while (i < src_len) {
                    unsigned char p = (unsigned char)src[i];
                    if (p >= 0x40 && p <= 0x7E) {
                        break;
                    }
                    ++i;
                }
                continue;
            }
            if (i + 1U < src_len) {
                ++i;
                continue;
            }
            continue;
        }
        if (c == 0x07 || c == 0x08) {
            continue;
        }
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return j;
}

size_t ddial_filter_telnet_iac(const char *src, size_t src_len, char *dst,
                               size_t dst_cap)
{
    if (src == nullptr || dst == nullptr || dst_cap == 0U) {
        return 0U;
    }

    size_t j = 0U;
    for (size_t i = 0U; i < src_len && j < dst_cap; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c != 0xFF) {
            if (j + 1U < dst_cap) {
                dst[j++] = (char)c;
            }
            continue;
        }
        if (i + 1U >= src_len) {
            break;
        }
        unsigned char cmd = (unsigned char)src[i + 1U];
        if (cmd == 0xFF) {
            dst[j++] = '\xFF';
            ++i;
        } else if (cmd == 0xFA) {
            /* Skip until IAC SE (0xFF 0xF0) */
            i += 2U;
            while (i < src_len) {
                if ((unsigned char)src[i] == 0xFF && i + 1U < src_len && (unsigned char)src[i + 1U] == 0xF0) {
                    ++i; /* Point to 0xF0 so the loop increment moves past it */
                    break;
                }
                ++i;
            }
        } else if (cmd >= 0xF0 && cmd <= 0xF9) {
            ++i;
        } else if ((cmd >= 0xFB && cmd <= 0xFE) && i + 2U < src_len) {
            i += 2U;
        } else {
            ++i;
        }
    }
    return j;
}

/* Parse one bracketed identity "#<slot><bo>T<ch><lt>:<handle><bc>" starting at
 * *pp.  Advances *pp past the closing bracket on success. */
static bool ddial_parse_identity(const char **pp, uint16_t *out_slot,
                                 uint8_t *out_channel, bool *out_is_link,
                                 char *out_handle, size_t handle_cap)
{
    const char *p = *pp;
    if (*p != '#') {
        return false;
    }
    ++p;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    unsigned long slot = strtoul(p, (char **)&p, 10);
    if (slot > UINT16_MAX) {
        return false;
    }
    char bo = *p;
    if (bo != '(' && bo != '[' && bo != '<') {
        return false;
    }
    ++p;
    if (*p != 'T' || !isdigit((unsigned char)p[1])) {
        return false;
    }
    unsigned int channel = (unsigned int)(p[1] - '0');
    p += 2;
    bool is_link = false;
    if (*p == ':' || *p == '=') {
        is_link = (*p == '=');
        ++p;
    }
    const char *handle_start = p;
    while (*p != '\0' && *p != ')' && *p != ']' && *p != '>') {
        ++p;
    }
    if (*p == '\0') {
        return false;
    }
    const char *handle_end = p;
    /* A ':' inside the handle region begins the account number; strip it. */
    for (const char *q = handle_start; q < handle_end; ++q) {
        if (*q == ':') {
            handle_end = q;
            break;
        }
    }
    while (handle_end > handle_start &&
           (handle_end[-1] == '*' || handle_end[-1] == '$')) {
        --handle_end;
    }
    if (out_handle != nullptr && handle_cap > 0U) {
        size_t len = (size_t)(handle_end - handle_start);
        if (len >= handle_cap) {
            len = handle_cap - 1U;
        }
        memcpy(out_handle, handle_start, len);
        out_handle[len] = '\0';
    }
    if (out_slot != nullptr) {
        *out_slot = (uint16_t)slot;
    }
    if (out_channel != nullptr) {
        *out_channel = (uint8_t)channel;
    }
    if (out_is_link != nullptr) {
        *out_is_link = is_link;
    }
    *pp = p + 1;
    return true;
}

/* Parse an inbound public chat line from a link:
 *   "[link_slot]#<slot><bo>T<ch>:<handle><bc> <message>"
 * with an optional leading '~' marking a dual-channel message. */
bool ddial_parse_incoming_chat(const char *line, uint16_t *out_link_slot,
                               uint16_t *out_slot, uint8_t *out_channel,
                               bool *out_is_link, bool *out_dual_channel,
                               char *out_handle, size_t handle_cap,
                               const char **out_message)
{
    if (line == nullptr) {
        return false;
    }
    const char *p = line;

    bool dual = false;
    if (*p == (char)DDIAL_LINK_ESCAPE) {
        dual = true;
        ++p;
    }

    /* Optional link slot prefix, e.g. "99#2[T1:Freddy)". */
    const char *save = p;
    uint16_t link_slot = 0U;
    if (isdigit((unsigned char)*p)) {
        unsigned long candidate = strtoul(p, (char **)&p, 10);
        if (*p == '#' && candidate > 0U && candidate <= UINT16_MAX) {
            link_slot = (uint16_t)candidate;
        } else {
            p = save;
        }
    }

    if (!ddial_parse_identity(&p, out_slot, out_channel, out_is_link,
                              out_handle, handle_cap)) {
        return false;
    }
    if (*p == ' ') {
        ++p;
    }
    if (out_link_slot != nullptr) {
        *out_link_slot = link_slot;
    }
    if (out_dual_channel != nullptr) {
        *out_dual_channel = dual;
    }
    if (out_message != nullptr) {
        *out_message = p;
    }
    return true;
}

/* Parse an inbound private message arriving over a link:
 *   "/P<target_slot> #<from_slot><bo>T<ch>:<handle><bc> <message>" */
bool ddial_parse_incoming_private(const char *line, uint16_t *out_target_slot,
                                  uint16_t *out_from_slot,
                                  uint8_t *out_channel, char *out_handle,
                                  size_t handle_cap, const char **out_message)
{
    if (line == nullptr || line[0] != '/' ||
        (line[1] != 'P' && line[1] != 'p')) {
        return false;
    }
    const char *p = line + 2;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    unsigned long target = strtoul(p, (char **)&p, 10);
    if (target > UINT16_MAX) {
        return false;
    }
    while (*p == ' ') {
        ++p;
    }
    if (!ddial_parse_identity(&p, out_from_slot, out_channel, nullptr,
                              out_handle, handle_cap)) {
        return false;
    }
    if (*p == ' ') {
        ++p;
    }
    if (out_target_slot != nullptr) {
        *out_target_slot = (uint16_t)target;
    }
    if (out_message != nullptr) {
        *out_message = p;
    }
    return true;
}

/* Parse an inbound e-mail line:
 *   "/E~<from_station_3d><to_id_3d>(<from_id>:<handle>) <message>" */
bool ddial_parse_incoming_email(const char *line, unsigned *out_from_station,
                                unsigned *out_to_id, unsigned *out_from_id,
                                char *out_handle, size_t handle_cap,
                                const char **out_message)
{
    if (line == nullptr || line[0] != '/' ||
        (line[1] != 'E' && line[1] != 'e') || line[2] != '~') {
        return false;
    }
    const char *p = line + 3;
    for (int i = 0; i < 6; ++i) {
        if (!isdigit((unsigned char)p[i])) {
            return false;
        }
    }
    unsigned from_station =
        (unsigned)((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));
    unsigned to_id =
        (unsigned)((p[3] - '0') * 100 + (p[4] - '0') * 10 + (p[5] - '0'));
    p += 6;
    if (*p != '(') {
        return false;
    }
    ++p;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    unsigned from_id = (unsigned)strtoul(p, (char **)&p, 10);
    if (*p != ':') {
        return false;
    }
    ++p;
    const char *handle_start = p;
    while (*p != '\0' && *p != ')') {
        ++p;
    }
    if (*p != ')') {
        return false;
    }
    if (out_handle != nullptr && handle_cap > 0U) {
        size_t len = (size_t)(p - handle_start);
        if (len >= handle_cap) {
            len = handle_cap - 1U;
        }
        memcpy(out_handle, handle_start, len);
        out_handle[len] = '\0';
    }
    ++p;
    if (*p == ' ') {
        ++p;
    }
    if (out_from_station != nullptr) {
        *out_from_station = from_station;
    }
    if (out_to_id != nullptr) {
        *out_to_id = to_id;
    }
    if (out_from_id != nullptr) {
        *out_from_id = from_id;
    }
    if (out_message != nullptr) {
        *out_message = p;
    }
    return true;
}

/* ---- DDial-style replies -----------------------------------------------
 *
 * A reply travels as ordinary chat whose body ends in a quote of the line
 * it answers:
 *
 *     text^ >>RE:[N] author: quoted text
 *
 * '^' is the DDial line break, N is the quoted author's line number (left
 * out when unknown) and the quote is the parent's own text, without any
 * ">>RE:" tail of its own.  Clients that understand the marker show the
 * line as a reply; older ones simply print it. */

#define DDIAL_REPLY_MARKER "^ >>RE:"
#define SSH_CHATTER_DDIAL_FOLD_CAP 1024U

bool ddial_split_reply(const char *body, size_t *out_text_len,
                       uint16_t *out_quoted_slot, char *out_author,
                       size_t author_cap, const char **out_quote)
{
    if (body == nullptr) {
        return false;
    }
    const char *marker = strstr(body, DDIAL_REPLY_MARKER);
    if (marker == nullptr) {
        return false;
    }
    const char *p = marker + sizeof(DDIAL_REPLY_MARKER) - 1U;
    uint16_t slot = 0U;
    /* Some clients quote the speaker in wire form instead:
     * ">>RE:#1[T1:MerZz) quote" (optionally "~#..."). */
    const char *wire = *p == (char)DDIAL_LINK_ESCAPE ? p + 1 : p;
    if (*wire == '#') {
        char handle[DDIAL_MAX_HANDLE_LEN];
        uint16_t wire_slot = 0U;
        const char *q = wire;
        if (!ddial_parse_identity(&q, &wire_slot, nullptr, nullptr, handle,
                                  sizeof(handle)) ||
            handle[0] == '\0') {
            return false;
        }
        if (*q == ' ') {
            ++q;
        }
        if (out_author != nullptr && author_cap > 0U) {
            snprintf(out_author, author_cap, "%s", handle);
        }
        if (out_text_len != nullptr) {
            *out_text_len = (size_t)(marker - body);
        }
        if (out_quoted_slot != nullptr) {
            *out_quoted_slot = wire_slot;
        }
        if (out_quote != nullptr) {
            *out_quote = q;
        }
        return true;
    }
    /* "[] author: quote" -- the line number left empty. */
    if (p[0] == '[' && p[1] == ']') {
        p += 2;
        while (*p == ' ') {
            ++p;
        }
    } else if (*p == '[') {
        const char *q = p + 1;
        unsigned long value = 0UL;
        bool digits = false;
        while (isdigit((unsigned char)*q) && value <= UINT16_MAX) {
            value = value * 10UL + (unsigned long)(*q - '0');
            digits = true;
            ++q;
        }
        if (!digits || *q != ']' || value > UINT16_MAX) {
            return false;
        }
        slot = (uint16_t)value;
        p = q + 1;
        while (*p == ' ') {
            ++p;
        }
    }
    const char *sep = strstr(p, ": ");
    if (sep == nullptr || sep == p) {
        return false;
    }
    if (out_author != nullptr && author_cap > 0U) {
        size_t len = (size_t)(sep - p);
        if (len >= author_cap) {
            len = author_cap - 1U;
        }
        memcpy(out_author, p, len);
        out_author[len] = '\0';
    }
    if (out_text_len != nullptr) {
        *out_text_len = (size_t)(marker - body);
    }
    if (out_quoted_slot != nullptr) {
        *out_quoted_slot = slot;
    }
    if (out_quote != nullptr) {
        *out_quote = sep + 2;
    }
    return true;
}

/* Copy src into dst as one line: CR/LF/tab become spaces, other control
 * bytes are dropped. Returns the length written. */
static size_t ddial_reply_copy_flat(const char *src, size_t src_len,
                                    char *dst, size_t dst_cap)
{
    size_t j = 0U;
    for (size_t i = 0U; i < src_len && src[i] != '\0' && j + 1U < dst_cap;
         ++i) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r' || c == '\n' || c == '\t') {
            c = ' ';
        } else if (c < 0x20U || c == 0x7FU) {
            continue;
        }
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return j;
}

bool ddial_format_reply_body(char *dst, size_t dst_cap, const char *text,
                             uint16_t quoted_slot, const char *author,
                             const char *quote)
{
    if (dst == nullptr || dst_cap == 0U) {
        return false;
    }
    dst[0] = '\0';
    if (text == nullptr || author == nullptr || quote == nullptr) {
        return false;
    }

    char clean_author[DDIAL_MAX_HANDLE_LEN];
    if (ddial_sanitize_handle(author, strlen(author), clean_author,
                              sizeof(clean_author)) == 0U ||
        clean_author[0] == '\0') {
        return false;
    }

    /* Quote only what the parent said, not the reply it was itself. */
    size_t quote_len = strlen(quote);
    size_t parent_text_len = 0U;
    if (ddial_split_reply(quote, &parent_text_len, nullptr, nullptr, 0U,
                          nullptr)) {
        quote_len = parent_text_len;
    }

    char flat_text[DDIAL_MAX_BODY_LEN + 1U];
    size_t text_len =
        ddial_reply_copy_flat(text, strlen(text), flat_text, sizeof(flat_text));
    char flat_quote[DDIAL_MAX_BODY_LEN + 1U];
    size_t flat_quote_len =
        ddial_reply_copy_flat(quote, quote_len, flat_quote, sizeof(flat_quote));
    while (text_len > 0U && flat_text[text_len - 1U] == ' ') {
        flat_text[--text_len] = '\0';
    }
    if (text_len == 0U || flat_quote_len == 0U) {
        return false;
    }

    char head[DDIAL_MAX_HANDLE_LEN + 32U];
    int head_len;
    if (quoted_slot != 0U) {
        head_len = snprintf(head, sizeof(head), DDIAL_REPLY_MARKER "[%u] %s: ",
                            (unsigned)quoted_slot, clean_author);
    } else {
        head_len = snprintf(head, sizeof(head), DDIAL_REPLY_MARKER "%s: ",
                            clean_author);
    }
    if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
        return false;
    }

    size_t limit = dst_cap - 1U;
    if (limit > DDIAL_MAX_BODY_LEN) {
        limit = DDIAL_MAX_BODY_LEN;
    }
    /* The reply text wins; the quote is clipped to what is left, but keep
     * a few quoted characters so the receiver can still match the parent. */
    enum { DDIAL_REPLY_MIN_QUOTE = 16 };
    size_t min_quote = flat_quote_len < DDIAL_REPLY_MIN_QUOTE
                           ? flat_quote_len
                           : DDIAL_REPLY_MIN_QUOTE;
    if ((size_t)head_len + min_quote > limit) {
        return false;
    }
    if (text_len + (size_t)head_len + min_quote > limit) {
        text_len = limit - (size_t)head_len - min_quote;
    }
    size_t room = limit - text_len - (size_t)head_len;
    if (flat_quote_len > room) {
        flat_quote_len = room;
    }

    memcpy(dst, flat_text, text_len);
    memcpy(dst + text_len, head, (size_t)head_len);
    memcpy(dst + text_len + (size_t)head_len, flat_quote, flat_quote_len);
    dst[text_len + (size_t)head_len + flat_quote_len] = '\0';
    return true;
}

/* A station link key is exactly nine ASCII digits. */
bool ddial_station_key_is_wellformed(const char *key)
{
    if (key == nullptr) {
        return false;
    }
    size_t len = 0U;
    for (; key[len] != '\0'; ++len) {
        if (!isdigit((unsigned char)key[len]) || len >= DDIAL_STATION_KEY_LEN) {
            return false;
        }
    }
    return len == DDIAL_STATION_KEY_LEN;
}

/* Copy src into dst with runs of whitespace folded to one space and the
 * ends trimmed. */
static size_t ddial_reply_fold_space(const char *src, size_t src_len, char *dst,
                                     size_t dst_cap)
{
    size_t j = 0U;
    bool pending_space = false;
    for (size_t i = 0U; i < src_len && src[i] != '\0' && j + 1U < dst_cap;
         ++i) {
        unsigned char c = (unsigned char)src[i];
        if (isspace(c)) {
            pending_space = j > 0U;
            continue;
        }
        if (pending_space && j + 2U < dst_cap) {
            dst[j++] = ' ';
        }
        pending_space = false;
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
    return j;
}

bool ddial_reply_quote_matches(const char *parent_text, const char *quote)
{
    if (parent_text == nullptr || quote == nullptr) {
        return false;
    }
    size_t parent_len = strlen(parent_text);
    size_t own_len = 0U;
    if (ddial_split_reply(parent_text, &own_len, nullptr, nullptr, 0U,
                          nullptr)) {
        parent_len = own_len;
    }
    char parent[SSH_CHATTER_DDIAL_FOLD_CAP];
    char wanted[SSH_CHATTER_DDIAL_FOLD_CAP];
    size_t plen = ddial_reply_fold_space(parent_text, parent_len, parent,
                                         sizeof(parent));
    size_t qlen = ddial_reply_fold_space(quote, strlen(quote), wanted,
                                         sizeof(wanted));
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (attempt == 1) {
            /* A clipped quote may end in an ellipsis: drop it and retry. */
            if (qlen < 3U || strcmp(wanted + qlen - 3U, "...") != 0) {
                break;
            }
            while (qlen > 0U && wanted[qlen - 1U] == '.') {
                wanted[--qlen] = '\0';
            }
            while (qlen > 0U && wanted[qlen - 1U] == ' ') {
                wanted[--qlen] = '\0';
            }
        }
        if (qlen == 0U || plen == 0U || qlen > plen) {
            continue;
        }
        /* Very short quotes must match whole; longer ones may be clipped. */
        if (qlen < 4U) {
            if (qlen == plen && strcmp(parent, wanted) == 0) {
                return true;
            }
            continue;
        }
        if (strncmp(parent, wanted, qlen) == 0) {
            return true;
        }
    }
    return false;
}

bool ddial_handles_equal(const char *a, const char *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    char ca[DDIAL_MAX_HANDLE_LEN];
    char cb[DDIAL_MAX_HANDLE_LEN];
    ddial_sanitize_handle(a, strlen(a), ca, sizeof(ca));
    ddial_sanitize_handle(b, strlen(b), cb, sizeof(cb));
    return ca[0] != '\0' && strcasecmp(ca, cb) == 0;
}
