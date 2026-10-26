/**
 * @file ftn.c
 * @desc FTN wire formats: addresses, Type 2+ packet headers, packed
 *       messages, the FTS-0001 date field and the echomail body with its
 *       kludge and control lines.  All multi-byte fields are little-endian
 *       and are serialised byte by byte, never through packed structs.
 *
 *       References: FTS-0001 (packets, packed messages), FSC-0039 and
 *       FSC-0048 (Type 2+ header), FTS-0004 (echomail, SEEN-BY, Origin),
 *       FTS-0009 (MSGID/REPLY), FTS-4000 (control paragraphs), FTS-5003
 *       (CHRS).  Synchronet's sbbsecho was used as a behavioural reference.
 *       Only libc is used so the unit test can include this file.
 */

#include "ftn.h"

#include <ctype.h>
#include <errno.h>
#include <iconv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Addresses                                                          */
/* ------------------------------------------------------------------ */

static bool ftn_parse_u16(const char **cursor, uint16_t *out)
{
    const char *p = *cursor;
    if (!isdigit((unsigned char)*p)) {
        return false;
    }
    unsigned long value = 0UL;
    while (isdigit((unsigned char)*p)) {
        value = value * 10UL + (unsigned long)(*p - '0');
        if (value > 65535UL) {
            return false;
        }
        ++p;
    }
    *out = (uint16_t)value;
    *cursor = p;
    return true;
}

/* Parse "zone:net/node[.point][@domain]" or "net/node[.point]" (zone 0).
 * Surrounding blanks are allowed; anything else after the address is not. */
static bool ftn_addr_parse(const char *text, ftn_addr_t *out)
{
    if (text == nullptr || out == nullptr) {
        return false;
    }
    ftn_addr_t addr = {0};
    const char *p = text;
    while (*p == ' ' || *p == '\t') {
        ++p;
    }
    uint16_t first = 0U;
    if (!ftn_parse_u16(&p, &first)) {
        return false;
    }
    if (*p == ':') {
        addr.zone = first;
        ++p;
        if (!ftn_parse_u16(&p, &addr.net)) {
            return false;
        }
    } else {
        addr.net = first;
    }
    if (*p != '/') {
        return false;
    }
    ++p;
    if (!ftn_parse_u16(&p, &addr.node)) {
        return false;
    }
    if (*p == '.') {
        ++p;
        if (!ftn_parse_u16(&p, &addr.point)) {
            return false;
        }
    }
    if (*p == '@') {
        ++p;
        while (*p != '\0' && *p != ' ' && *p != '\t') {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' &&
                *p != '.') {
                return false;
            }
            ++p;
        }
    }
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p != '\0') {
        return false;
    }
    *out = addr;
    return true;
}

static void ftn_addr_format(const ftn_addr_t *addr, char *out, size_t size)
{
    if (out == nullptr || size == 0U) {
        return;
    }
    if (addr == nullptr) {
        out[0] = '\0';
        return;
    }
    if (addr->point != 0U) {
        snprintf(out, size, "%u:%u/%u.%u", addr->zone, addr->net, addr->node,
                 addr->point);
    } else {
        snprintf(out, size, "%u:%u/%u", addr->zone, addr->net, addr->node);
    }
}

static bool ftn_addr_equal(const ftn_addr_t *a, const ftn_addr_t *b)
{
    return a->zone == b->zone && a->net == b->net && a->node == b->node &&
           a->point == b->point;
}

/* ------------------------------------------------------------------ */
/* Little-endian helpers                                              */
/* ------------------------------------------------------------------ */

static void ftn_put16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value & 0xFFU);
    out[1] = (uint8_t)(value >> 8);
}

static uint16_t ftn_get16(const uint8_t *in)
{
    return (uint16_t)(in[0] | (in[1] << 8));
}

/* ------------------------------------------------------------------ */
/* Packet header (58 bytes)                                           */
/* ------------------------------------------------------------------ */

/* Write a Type 2+ header (FSC-0039 layout, which Type 2 readers also
 * accept).  The capability word announces Type 2+ support. */
static void ftn_pkt_header_write(uint8_t out[FTN_PKT_HEADER_LEN],
                                 const ftn_pkt_header_t *header)
{
    memset(out, 0, FTN_PKT_HEADER_LEN);
    ftn_put16(out + 0, header->orig.node);
    ftn_put16(out + 2, header->dest.node);
    ftn_put16(out + 4, (uint16_t)(header->created.tm_year + 1900));
    ftn_put16(out + 6, (uint16_t)header->created.tm_mon); /* 0-11 */
    ftn_put16(out + 8, (uint16_t)header->created.tm_mday);
    ftn_put16(out + 10, (uint16_t)header->created.tm_hour);
    ftn_put16(out + 12, (uint16_t)header->created.tm_min);
    ftn_put16(out + 14, (uint16_t)header->created.tm_sec);
    ftn_put16(out + 16, 0U);  /* baud */
    ftn_put16(out + 18, 2U);  /* packet type */
    ftn_put16(out + 20, header->orig.net);
    ftn_put16(out + 22, header->dest.net);
    out[24] = (uint8_t)(FTN_PRODUCT_CODE & 0xFFU);
    out[25] = 1U; /* revision major */
    size_t pw_len = strnlen(header->password, FTN_PKT_PASSWORD_LEN);
    memcpy(out + 26, header->password, pw_len);
    ftn_put16(out + 34, header->orig.zone); /* Type 2 zone fields */
    ftn_put16(out + 36, header->dest.zone);
    ftn_put16(out + 38, 0U);     /* auxnet */
    ftn_put16(out + 40, 0x0100U); /* capability word, byte-swapped copy */
    out[42] = 0U;                /* product code, high byte */
    out[43] = 4U;                /* revision minor */
    ftn_put16(out + 44, 0x0001U); /* capability word: Type 2+ */
    ftn_put16(out + 46, header->orig.zone);
    ftn_put16(out + 48, header->dest.zone);
    ftn_put16(out + 50, header->orig.point);
    ftn_put16(out + 52, header->dest.point);
}

/* Read a Type 2 or Type 2+ header.  Returns false when the data is too
 * short or is not a type 2 packet. */
static bool ftn_pkt_header_read(const uint8_t *in, size_t length,
                                ftn_pkt_header_t *header)
{
    if (in == nullptr || header == nullptr || length < FTN_PKT_HEADER_LEN) {
        return false;
    }
    if (ftn_get16(in + 18) != 2U) {
        return false;
    }
    memset(header, 0, sizeof(*header));
    header->orig.node = ftn_get16(in + 0);
    header->dest.node = ftn_get16(in + 2);
    header->created.tm_year = (int)ftn_get16(in + 4) - 1900;
    header->created.tm_mon = (int)ftn_get16(in + 6);
    header->created.tm_mday = (int)ftn_get16(in + 8);
    header->created.tm_hour = (int)ftn_get16(in + 10);
    header->created.tm_min = (int)ftn_get16(in + 12);
    header->created.tm_sec = (int)ftn_get16(in + 14);
    header->orig.net = ftn_get16(in + 20);
    header->dest.net = ftn_get16(in + 22);
    header->product = (uint16_t)(in[24] | (in[42] << 8));
    memcpy(header->password, in + 26, FTN_PKT_PASSWORD_LEN);
    header->password[FTN_PKT_PASSWORD_LEN] = '\0';
    header->orig.zone = ftn_get16(in + 34);
    header->dest.zone = ftn_get16(in + 36);

    const uint16_t cwcopy = ftn_get16(in + 40);
    const uint16_t cword = ftn_get16(in + 44);
    const bool type2plus =
        (cword & 0x0001U) != 0U &&
        cword == (uint16_t)(((cwcopy & 0xFFU) << 8) | (cwcopy >> 8));
    if (type2plus) {
        if (ftn_get16(in + 46) != 0U) {
            header->orig.zone = ftn_get16(in + 46);
        }
        if (ftn_get16(in + 48) != 0U) {
            header->dest.zone = ftn_get16(in + 48);
        }
        header->orig.point = ftn_get16(in + 50);
        header->dest.point = ftn_get16(in + 52);
        /* FSC-0048: a point originator writes net -1 and its real net in
         * auxnet. */
        if (header->orig.net == 0xFFFFU && header->orig.point != 0U) {
            header->orig.net = ftn_get16(in + 38);
        }
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Date field                                                         */
/* ------------------------------------------------------------------ */

static const char *const kFtnMonths[12] = {"Jan", "Feb", "Mar", "Apr",
                                           "May", "Jun", "Jul", "Aug",
                                           "Sep", "Oct", "Nov", "Dec"};

/* "DD Mon YY  HH:MM:SS" (FTS-0001), always 19 characters plus NUL. */
static void ftn_datetime_format(time_t when, char out[FTN_DATETIME_LEN])
{
    struct tm tm_utc;
    gmtime_r(&when, &tm_utc);
    snprintf(out, FTN_DATETIME_LEN, "%02d %s %02d  %02d:%02d:%02d",
             tm_utc.tm_mday, kFtnMonths[tm_utc.tm_mon % 12],
             tm_utc.tm_year % 100, tm_utc.tm_hour, tm_utc.tm_min,
             tm_utc.tm_sec);
}

static int ftn_month_index(const char *name)
{
    for (int idx = 0; idx < 12; ++idx) {
        if (strncasecmp(name, kFtnMonths[idx], 3) == 0) {
            return idx;
        }
    }
    return -1;
}

/* Parse the FTS-0001 date, or the SEAdog form "Www DD Mon YY HH:MM".  Two
 * digit years below 80 are taken as 20xx.  The result is UTC. */
static bool ftn_datetime_parse(const char *text, time_t *out)
{
    if (text == nullptr || out == nullptr) {
        return false;
    }
    int day = 0, year = 0, hour = 0, minute = 0, second = 0;
    char month[4] = {0};
    char weekday[4] = {0};
    if (sscanf(text, "%d %3s %d %d:%d:%d", &day, month, &year, &hour,
               &minute, &second) < 5 &&
        sscanf(text, "%3s %d %3s %d %d:%d", weekday, &day, month, &year,
               &hour, &minute) < 6) {
        return false;
    }
    int mon = ftn_month_index(month);
    if (mon < 0 || day < 1 || day > 31 || hour > 23 || minute > 59 ||
        second > 60) {
        return false;
    }
    struct tm tm_utc = {0};
    tm_utc.tm_year = (year < 80 ? year + 100 : year % 100);
    tm_utc.tm_mon = mon;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = minute;
    tm_utc.tm_sec = second;
    time_t value = timegm(&tm_utc);
    if (value == (time_t)-1) {
        return false;
    }
    *out = value;
    return true;
}

/* ------------------------------------------------------------------ */
/* Packed messages                                                    */
/* ------------------------------------------------------------------ */

static void ftn_packed_msg_free(ftn_packed_msg_t *msg)
{
    if (msg != nullptr) {
        free(msg->body);
        msg->body = nullptr;
        msg->body_len = 0U;
    }
}

/* Copy a NUL-terminated field of at most limit bytes (NUL included). */
static bool ftn_read_cstring(const uint8_t *buf, size_t length, size_t *offset,
                             char *out, size_t limit)
{
    size_t start = *offset;
    size_t idx = start;
    while (idx < length && buf[idx] != 0U) {
        if (idx - start + 1U >= limit) {
            return false;
        }
        ++idx;
    }
    if (idx >= length) {
        return false;
    }
    memcpy(out, buf + start, idx - start);
    out[idx - start] = '\0';
    *offset = idx + 1U;
    return true;
}

/* Read the next packed message at *offset.  Returns 1 with msg filled
 * (caller frees with ftn_packed_msg_free), 0 at the packet terminator and
 * -1 on malformed data. */
static int ftn_packed_msg_read(const uint8_t *buf, size_t length,
                               size_t *offset, ftn_packed_msg_t *msg)
{
    if (buf == nullptr || offset == nullptr || msg == nullptr) {
        return -1;
    }
    memset(msg, 0, sizeof(*msg));
    size_t pos = *offset;
    if (pos + 2U > length) {
        return -1;
    }
    uint16_t type = ftn_get16(buf + pos);
    if (type == 0U) {
        *offset = pos + 2U;
        return 0;
    }
    if (type != 2U || pos + FTN_MSG_HEADER_LEN + FTN_DATETIME_LEN > length) {
        return -1;
    }
    msg->orig_node = ftn_get16(buf + pos + 2);
    msg->dest_node = ftn_get16(buf + pos + 4);
    msg->orig_net = ftn_get16(buf + pos + 6);
    msg->dest_net = ftn_get16(buf + pos + 8);
    msg->attr = ftn_get16(buf + pos + 10);
    pos += FTN_MSG_HEADER_LEN;
    /* The date is a fixed 20-byte field, but some tossers write it NUL
     * terminated short; FTS-0001 says 20 bytes, so take exactly that. */
    memcpy(msg->datetime, buf + pos, FTN_DATETIME_LEN);
    msg->datetime[FTN_DATETIME_LEN - 1U] = '\0';
    pos += FTN_DATETIME_LEN;
    if (!ftn_read_cstring(buf, length, &pos, msg->to, sizeof(msg->to)) ||
        !ftn_read_cstring(buf, length, &pos, msg->from, sizeof(msg->from)) ||
        !ftn_read_cstring(buf, length, &pos, msg->subject,
                          sizeof(msg->subject))) {
        return -1;
    }
    const uint8_t *text = buf + pos;
    const uint8_t *end = memchr(text, 0, length - pos);
    if (end == nullptr) {
        return -1;
    }
    msg->body_len = (size_t)(end - text);
    msg->body = malloc(msg->body_len + 1U);
    if (msg->body == nullptr) {
        return -1;
    }
    memcpy(msg->body, text, msg->body_len);
    msg->body[msg->body_len] = '\0';
    *offset = pos + msg->body_len + 1U;
    return 1;
}

static bool ftn_packed_msg_write(FILE *fp, const ftn_packed_msg_t *msg)
{
    uint8_t header[FTN_MSG_HEADER_LEN] = {0};
    ftn_put16(header + 0, 2U);
    ftn_put16(header + 2, msg->orig_node);
    ftn_put16(header + 4, msg->dest_node);
    ftn_put16(header + 6, msg->orig_net);
    ftn_put16(header + 8, msg->dest_net);
    ftn_put16(header + 10, msg->attr);
    ftn_put16(header + 12, 0U); /* cost */
    char datetime[FTN_DATETIME_LEN] = {0};
    memcpy(datetime, msg->datetime, strnlen(msg->datetime,
                                            FTN_DATETIME_LEN - 1U));
    const size_t to_len = strnlen(msg->to, FTN_NAME_LEN - 1U);
    const size_t from_len = strnlen(msg->from, FTN_NAME_LEN - 1U);
    const size_t subj_len = strnlen(msg->subject, FTN_SUBJ_LEN - 1U);
    const uint8_t zero = 0U;
    return fwrite(header, sizeof(header), 1U, fp) == 1U &&
           fwrite(datetime, FTN_DATETIME_LEN, 1U, fp) == 1U &&
           fwrite(msg->to, 1U, to_len, fp) == to_len &&
           fwrite(&zero, 1U, 1U, fp) == 1U &&
           fwrite(msg->from, 1U, from_len, fp) == from_len &&
           fwrite(&zero, 1U, 1U, fp) == 1U &&
           fwrite(msg->subject, 1U, subj_len, fp) == subj_len &&
           fwrite(&zero, 1U, 1U, fp) == 1U &&
           (msg->body_len == 0U ||
            fwrite(msg->body, 1U, msg->body_len, fp) == msg->body_len) &&
           fwrite(&zero, 1U, 1U, fp) == 1U;
}

/* ------------------------------------------------------------------ */
/* Text helpers                                                       */
/* ------------------------------------------------------------------ */

/* Drop terminal escape sequences and control bytes other than '\n' and
 * '\t' in place.  Imported mail is untrusted and goes straight to
 * terminals. */
static void ftn_text_sanitize(char *text)
{
    if (text == nullptr) {
        return;
    }
    size_t out = 0U;
    for (size_t idx = 0U; text[idx] != '\0';) {
        unsigned char ch = (unsigned char)text[idx];
        if (ch == 0x1BU) {
            ++idx;
            if (text[idx] == '[') {
                ++idx;
                while (text[idx] != '\0' &&
                       !((unsigned char)text[idx] >= 0x40U &&
                         (unsigned char)text[idx] <= 0x7EU)) {
                    ++idx;
                }
                if (text[idx] != '\0') {
                    ++idx;
                }
            } else if (text[idx] != '\0') {
                ++idx;
            }
            continue;
        }
        if ((ch < 0x20U && ch != '\n' && ch != '\t') || ch == 0x7FU) {
            ++idx;
            continue;
        }
        text[out++] = text[idx++];
    }
    text[out] = '\0';
}

/* iconv name for an FTS-5003 CHRS/CODEPAGE identifier, or nullptr when we
 * do not know it.  Only the first word counts ("CP437 2" -> "CP437"). */
static const char *ftn_charset_iconv_name(const char *chrs)
{
    static const struct {
        const char *ftn;
        const char *iconv;
    } kMap[] = {
        {"UTF-8", "UTF-8"},       {"ASCII", "ASCII"},
        {"IBMPC", "CP437"},       {"CP437", "CP437"},
        {"CP850", "CP850"},       {"CP852", "CP852"},
        {"CP865", "CP865"},       {"CP866", "CP866"},
        {"CP1250", "CP1250"},     {"CP1251", "CP1251"},
        {"CP1252", "CP1252"},     {"LATIN-1", "ISO-8859-1"},
        {"LATIN-2", "ISO-8859-2"}, {"LATIN-5", "ISO-8859-9"},
        {"LATIN-9", "ISO-8859-15"}, {"KOI8-R", "KOI8-R"},
        {"KOI8-U", "KOI8-U"},     {"CP949", "CP949"},
        {"EUC-KR", "EUC-KR"},     {"CP932", "CP932"},
        {"SJIS", "SHIFT_JIS"},    {"CP936", "GBK"},
        {"GBK", "GBK"},           {"BIG5", "BIG5"},
    };
    if (chrs == nullptr) {
        return nullptr;
    }
    char word[24];
    size_t len = 0U;
    while (chrs[len] != '\0' && chrs[len] != ' ' && len + 1U < sizeof(word)) {
        word[len] = chrs[len];
        ++len;
    }
    word[len] = '\0';
    for (size_t idx = 0U; idx < sizeof(kMap) / sizeof(kMap[0]); ++idx) {
        if (strcasecmp(word, kMap[idx].ftn) == 0) {
            return kMap[idx].iconv;
        }
    }
    return nullptr;
}

/* Convert input (in_len bytes, charset is an iconv name) to a malloc'd
 * UTF-8 string.  Bytes the converter rejects become '?'. */
static char *ftn_to_utf8(const char *input, size_t in_len, const char *charset)
{
    size_t cap = in_len * 4U + 1U;
    char *out = malloc(cap);
    if (out == nullptr) {
        return nullptr;
    }
    iconv_t cd = (iconv_t)-1;
    if (charset != nullptr && strcasecmp(charset, "UTF-8") != 0) {
        cd = iconv_open("UTF-8", charset);
    }
    if (cd == (iconv_t)-1) {
        /* UTF-8 (or unknown): copy, replacing invalid sequences. */
        size_t o = 0U;
        for (size_t i = 0U; i < in_len;) {
            unsigned char c = (unsigned char)input[i];
            size_t need = c < 0x80U ? 1U
                          : (c & 0xE0U) == 0xC0U ? 2U
                          : (c & 0xF0U) == 0xE0U ? 3U
                          : (c & 0xF8U) == 0xF0U ? 4U
                                                 : 0U;
            bool ok = need > 0U && i + need <= in_len;
            for (size_t k = 1U; ok && k < need; ++k) {
                ok = ((unsigned char)input[i + k] & 0xC0U) == 0x80U;
            }
            if (ok) {
                memcpy(out + o, input + i, need);
                o += need;
                i += need;
            } else {
                out[o++] = '?';
                ++i;
            }
        }
        out[o] = '\0';
        return out;
    }
    char *in_ptr = (char *)input;
    size_t in_left = in_len;
    char *out_ptr = out;
    size_t out_left = cap - 1U;
    while (in_left > 0U) {
        size_t rc = iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left);
        if (rc != (size_t)-1) {
            break;
        }
        if ((errno == EILSEQ || errno == EINVAL) && out_left > 0U) {
            *out_ptr++ = '?';
            --out_left;
            ++in_ptr;
            --in_left;
            continue;
        }
        break;
    }
    iconv_close(cd);
    *out_ptr = '\0';
    return out;
}

/* Convert a short header field into dst (UTF-8). */
static void ftn_field_to_utf8(char *dst, size_t size, const char *src,
                              const char *charset)
{
    char *converted = ftn_to_utf8(src, strlen(src), charset);
    snprintf(dst, size, "%s", converted != nullptr ? converted : src);
    free(converted);
    ftn_text_sanitize(dst);
}

/* ------------------------------------------------------------------ */
/* Body parsing                                                       */
/* ------------------------------------------------------------------ */

static void ftn_message_free(ftn_message_t *msg)
{
    if (msg != nullptr) {
        free(msg->body);
        msg->body = nullptr;
    }
}

static void ftn_copy_value(char *dst, size_t size, const char *src,
                           size_t len)
{
    while (len > 0U && (*src == ' ' || *src == '\t')) {
        ++src;
        --len;
    }
    while (len > 0U && (src[len - 1U] == ' ' || src[len - 1U] == '\t')) {
        --len;
    }
    if (len >= size) {
        len = size - 1U;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Pull the address out of an Origin line: the last "(...)" group, with an
 * optional domain removed. */
static void ftn_origin_address(const char *line, size_t len, char *out,
                               size_t size)
{
    out[0] = '\0';
    const char *close = nullptr;
    for (size_t idx = len; idx > 0U; --idx) {
        if (line[idx - 1U] == ')') {
            close = &line[idx - 1U];
            break;
        }
    }
    if (close == nullptr) {
        return;
    }
    const char *open = close;
    while (open > line && *open != '(') {
        --open;
    }
    if (*open != '(') {
        return;
    }
    char candidate[FTN_ADDR_TEXT_LEN];
    ftn_copy_value(candidate, sizeof(candidate), open + 1,
                   (size_t)(close - open - 1));
    char *at = strchr(candidate, '@');
    if (at != nullptr) {
        *at = '\0';
    }
    ftn_addr_t addr;
    if (ftn_addr_parse(candidate, &addr)) {
        ftn_addr_format(&addr, out, size);
    }
}

/*
 * Turn a packed message into an ftn_message_t: the AREA line, kludges
 * (MSGID, REPLY, CHRS/CODEPAGE), SEEN-BY and PATH are removed from the text
 * and the rest is converted to UTF-8 with '\n' line ends.  Tear and Origin
 * lines stay in the text, as readers expect to see them.  Returns false only
 * when memory runs out.
 */
static bool ftn_message_from_packed(const ftn_packed_msg_t *packed,
                                    ftn_message_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *raw = packed->body != nullptr ? packed->body : "";
    const size_t raw_len = packed->body != nullptr ? packed->body_len : 0U;

    char *text = malloc(raw_len + 1U);
    if (text == nullptr) {
        return false;
    }
    size_t text_len = 0U;
    char chrs[24] = {0};
    bool first_line = true;

    for (size_t pos = 0U; pos < raw_len;) {
        size_t end = pos;
        while (end < raw_len && raw[end] != '\r' && raw[end] != '\n') {
            ++end;
        }
        const char *line = raw + pos;
        const size_t len = end - pos;
        size_t next = end;
        if (next < raw_len && raw[next] == '\r') {
            ++next;
        }
        if (next < raw_len && raw[next] == '\n') {
            ++next;
        }

        bool keep = true;
        if (first_line && len > 5U && strncmp(line, "AREA:", 5) == 0) {
            ftn_copy_value(out->area, sizeof(out->area), line + 5, len - 5U);
            keep = false;
        } else if (len > 0U && line[0] == '\x01') {
            const char *kludge = line + 1;
            const size_t klen = len - 1U;
            if (klen > 6U && strncmp(kludge, "MSGID:", 6) == 0) {
                ftn_copy_value(out->msgid, sizeof(out->msgid), kludge + 6,
                               klen - 6U);
            } else if (klen > 6U && strncmp(kludge, "REPLY:", 6) == 0) {
                ftn_copy_value(out->reply, sizeof(out->reply), kludge + 6,
                               klen - 6U);
            } else if (klen > 5U && strncmp(kludge, "CHRS:", 5) == 0) {
                ftn_copy_value(chrs, sizeof(chrs), kludge + 5, klen - 5U);
            } else if (klen > 9U && strncmp(kludge, "CODEPAGE:", 9) == 0 &&
                       chrs[0] == '\0') {
                char page[16];
                ftn_copy_value(page, sizeof(page), kludge + 9, klen - 9U);
                snprintf(chrs, sizeof(chrs), "CP%s", page);
            }
            keep = false;
        } else if (len >= 8U && strncmp(line, "SEEN-BY:", 8) == 0) {
            keep = false;
        } else if (len >= 11U && strncmp(line, " * Origin: ", 11) == 0) {
            ftn_origin_address(line, len, out->origin_addr,
                               sizeof(out->origin_addr));
        }
        first_line = false;

        if (keep) {
            memcpy(text + text_len, line, len);
            text_len += len;
            text[text_len++] = '\n';
        }
        pos = next;
    }
    while (text_len > 0U && text[text_len - 1U] == '\n') {
        --text_len;
    }
    text[text_len] = '\0';

    /* FTS-5003: no CHRS means IBM PC (CP437); plain ASCII reads the same. */
    const char *charset = ftn_charset_iconv_name(chrs);
    if (charset == nullptr) {
        charset = "CP437";
    }
    snprintf(out->charset, sizeof(out->charset), "%s", charset);

    out->body = ftn_to_utf8(text, text_len, charset);
    free(text);
    if (out->body == nullptr) {
        return false;
    }
    ftn_text_sanitize(out->body);
    ftn_field_to_utf8(out->from, sizeof(out->from), packed->from, charset);
    ftn_field_to_utf8(out->to, sizeof(out->to), packed->to, charset);
    ftn_field_to_utf8(out->subject, sizeof(out->subject), packed->subject,
                      charset);
    ftn_text_sanitize(out->area);
    ftn_text_sanitize(out->msgid);
    ftn_text_sanitize(out->reply);
    if (!ftn_datetime_parse(packed->datetime, &out->written)) {
        out->written = 0;
    }
    if (out->area[0] == '\0') {
        out->flags |= FTN_MSG_FLAG_NETMAIL;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Body composition                                                   */
/* ------------------------------------------------------------------ */

typedef struct ftn_compose {
    const char *area;      /* empty or nullptr for netmail */
    const char *msgid;     /* "addr serial" */
    const char *reply;     /* optional */
    const char *text;      /* UTF-8, '\n' line ends */
    const char *origin;    /* origin line text, without the address */
    ftn_addr_t self;
    ftn_addr_t uplink;
    bool netmail;
    ftn_addr_t netmail_dest; /* for INTL/FMPT/TOPT */
    time_t when;
} ftn_compose_t;

static bool ftn_buf_append(char **buf, size_t *len, size_t *cap,
                           const char *text, size_t text_len)
{
    if (*len + text_len + 1U > *cap) {
        size_t next = (*cap == 0U ? 256U : *cap * 2U);
        while (next < *len + text_len + 1U) {
            next *= 2U;
        }
        char *grown = realloc(*buf, next);
        if (grown == nullptr) {
            return false;
        }
        *buf = grown;
        *cap = next;
    }
    memcpy(*buf + *len, text, text_len);
    *len += text_len;
    (*buf)[*len] = '\0';
    return true;
}

static bool ftn_buf_printf(char **buf, size_t *len, size_t *cap,
                           const char *format, ...)
    __attribute__((format(printf, 4, 5)));

static bool ftn_buf_printf(char **buf, size_t *len, size_t *cap,
                           const char *format, ...)
{
    char line[512];
    va_list args;
    va_start(args, format);
    int written = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (written < 0) {
        return false;
    }
    size_t used = (size_t)written < sizeof(line) ? (size_t)written
                                                 : sizeof(line) - 1U;
    return ftn_buf_append(buf, len, cap, line, used);
}

/*
 * Build the raw body of an outgoing message: AREA line (echomail), kludges,
 * the text with CR line ends, tear and Origin lines, and for a node (not a
 * point) SEEN-BY and PATH.  Returns a malloc'd string and its length.
 */
static char *ftn_body_compose(const ftn_compose_t *in, size_t *out_len)
{
    char *buf = nullptr;
    size_t len = 0U;
    size_t cap = 0U;
    char self_text[FTN_ADDR_TEXT_LEN];
    ftn_addr_format(&in->self, self_text, sizeof(self_text));
    struct tm tm_local;
    localtime_r(&in->when, &tm_local);
    long offset = tm_local.tm_gmtoff / 60L;
    const bool negative = offset < 0;
    if (negative) {
        offset = -offset;
    }

    bool ok = true;
    if (!in->netmail && in->area != nullptr && in->area[0] != '\0') {
        ok = ok && ftn_buf_printf(&buf, &len, &cap, "AREA:%s\r", in->area);
    }
    if (in->netmail) {
        ok = ok && ftn_buf_printf(&buf, &len, &cap,
                                  "\x01INTL %u:%u/%u %u:%u/%u\r",
                                  in->netmail_dest.zone, in->netmail_dest.net,
                                  in->netmail_dest.node, in->self.zone,
                                  in->self.net, in->self.node);
        if (in->self.point != 0U) {
            ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01" "FMPT %u\r",
                                      in->self.point);
        }
        if (in->netmail_dest.point != 0U) {
            ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01TOPT %u\r",
                                      in->netmail_dest.point);
        }
    }
    ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01MSGID: %s\r", in->msgid);
    if (in->reply != nullptr && in->reply[0] != '\0') {
        ok = ok &&
             ftn_buf_printf(&buf, &len, &cap, "\x01REPLY: %s\r", in->reply);
    }
    ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01PID: %s %s\r",
                              FTN_PRODUCT_NAME, FTN_PRODUCT_VERSION);
    ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01" "CHRS: UTF-8 4\r");
    /* TZUTC is "HHMM" or "-HHMM", never with a '+'. */
    ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01TZUTC: %s%02ld%02ld\r",
                              negative ? "-" : "", offset / 60L,
                              offset % 60L);

    const char *text = in->text != nullptr ? in->text : "";
    for (const char *p = text; ok && *p != '\0'; ++p) {
        char ch = *p == '\n' ? '\r' : *p;
        if (*p == '\r') {
            continue;
        }
        ok = ftn_buf_append(&buf, &len, &cap, &ch, 1U);
    }
    if (ok && len > 0U && buf[len - 1U] != '\r') {
        ok = ftn_buf_append(&buf, &len, &cap, "\r", 1U);
    }
    ok = ok && ftn_buf_printf(&buf, &len, &cap, "--- %s %s\r",
                              FTN_PRODUCT_NAME, FTN_PRODUCT_VERSION);
    if (!in->netmail) {
        const char *origin =
            in->origin != nullptr && in->origin[0] != '\0' ? in->origin
                                                           : "SSH-Chatter";
        ok = ok && ftn_buf_printf(&buf, &len, &cap, " * Origin: %.*s (%s)\r",
                                  (int)(79 - 14 - strlen(self_text)), origin,
                                  self_text);
        if (in->self.point == 0U) {
            /* A point leaves SEEN-BY and PATH to its boss node. */
            if (in->uplink.net == in->self.net) {
                ok = ok && ftn_buf_printf(&buf, &len, &cap,
                                          "SEEN-BY: %u/%u %u\r", in->self.net,
                                          in->self.node < in->uplink.node
                                              ? in->self.node
                                              : in->uplink.node,
                                          in->self.node < in->uplink.node
                                              ? in->uplink.node
                                              : in->self.node);
            } else {
                ok = ok && ftn_buf_printf(&buf, &len, &cap,
                                          "SEEN-BY: %u/%u %u/%u\r",
                                          in->self.net, in->self.node,
                                          in->uplink.net, in->uplink.node);
            }
            ok = ok && ftn_buf_printf(&buf, &len, &cap, "\x01PATH: %u/%u\r",
                                      in->self.net, in->self.node);
        }
    }
    if (!ok) {
        free(buf);
        return nullptr;
    }
    *out_len = len;
    return buf;
}

/* "zone:net/node[.point] serial" with an 8-digit hex serial (FTS-0009). */
static void ftn_msgid_make(const ftn_addr_t *self, uint32_t serial, char *out,
                           size_t size)
{
    char addr[FTN_ADDR_TEXT_LEN];
    ftn_addr_format(self, addr, sizeof(addr));
    snprintf(out, size, "%s %08x", addr, serial);
}

/* Transliterate a UTF-8 name for the 36-byte header field.  The body
 * carries CHRS UTF-8, but header names are matched by readers on other
 * systems, so they stay within the field and are cut on a character
 * boundary. */
static void ftn_header_field(char *dst, size_t size, const char *src)
{
    size_t len = strlen(src);
    if (len >= size) {
        len = size - 1U;
        while (len > 0U && ((unsigned char)src[len] & 0xC0U) == 0x80U) {
            --len;
        }
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}
