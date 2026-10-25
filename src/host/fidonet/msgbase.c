/**
 * @file msgbase.c
 * @desc FidoNet message storage, kept apart from bbs_state.dat under the
 *       node's own directory:
 *
 *         areas/<tag>.msgs  append-only message base, one per echo area
 *                           (NETMAIL for netmail); a message's number is its
 *                           position in the file, starting at 1
 *         dupes.dat         recent dupe keys ("AREA msgid"), newest last
 *         hidden.dat        operator-hidden messages ("AREA number")
 *
 *       A record is "FTM1", a 32-bit payload length and the payload: eight
 *       length-prefixed strings (area, from, to, subject, msgid, reply,
 *       origin address, charset), the length-prefixed body, then written,
 *       imported (64-bit) and flags (32-bit), all little-endian.  Each record
 *       goes out in one write() on an O_APPEND descriptor; a torn tail left
 *       by a crash is skipped on read.  Only libc is used so the unit test
 *       can include this file.
 */

#include "ftn.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define FTN_MSGBASE_MAGIC "FTM1"
#define FTN_MSGBASE_MAX_RECORD (1024U * 1024U)
#define FTN_DUPES_KEEP 10000U
#define FTN_NETMAIL_AREA "NETMAIL"

/* fopen() for the node's small state files, created 0600 like the rest of
 * the server's data instead of with the process umask. */
static FILE *ftn_fopen_private(const char *path, const char *mode)
{
    int flags = O_NOFOLLOW;
    if (mode[0] == 'r') {
        flags |= O_RDONLY;
    } else {
        flags |= O_WRONLY | O_CREAT | (mode[0] == 'a' ? O_APPEND : O_TRUNC);
    }
    int fd = open(path, flags, 0600);
    if (fd < 0) {
        return nullptr;
    }
    FILE *fp = fdopen(fd, mode);
    if (fp == nullptr) {
        close(fd);
    }
    return fp;
}

/* Area tags become file names, so only a safe subset is accepted. */
static bool ftn_area_tag_valid(const char *tag)
{
    if (tag == nullptr || tag[0] == '\0' ||
        strlen(tag) >= FTN_AREATAG_LEN) {
        return false;
    }
    if (tag[0] == '.') {
        return false;
    }
    for (const char *p = tag; *p != '\0'; ++p) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' &&
            *p != '-') {
            return false;
        }
    }
    return true;
}

static void ftn_area_tag_upper(char *tag)
{
    for (char *p = tag; *p != '\0'; ++p) {
        *p = (char)toupper((unsigned char)*p);
    }
}

static bool ftn_mkdir_p(const char *path)
{
    char buffer[PATH_MAX];
    if (snprintf(buffer, sizeof(buffer), "%s", path) >= (int)sizeof(buffer)) {
        return false;
    }
    for (char *p = buffer + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buffer, 0700) != 0 && errno != EEXIST) {
                return false;
            }
            *p = '/';
        }
    }
    return mkdir(buffer, 0700) == 0 || errno == EEXIST;
}

static bool ftn_msgbase_path(const char *dir, const char *area, char *out,
                             size_t size)
{
    if (!ftn_area_tag_valid(area)) {
        return false;
    }
    char lower[FTN_AREATAG_LEN];
    size_t idx = 0U;
    for (; area[idx] != '\0'; ++idx) {
        lower[idx] = (char)tolower((unsigned char)area[idx]);
    }
    lower[idx] = '\0';
    int written = snprintf(out, size, "%s/areas/%s.msgs", dir, lower);
    return written > 0 && (size_t)written < size;
}

/* ---- record encoding ---- */

typedef struct ftn_writer {
    uint8_t *data;
    size_t len;
    size_t cap;
    bool ok;
} ftn_writer_t;

static void ftn_writer_put(ftn_writer_t *w, const void *src, size_t len)
{
    if (!w->ok) {
        return;
    }
    if (w->len + len > w->cap) {
        size_t next = w->cap == 0U ? 512U : w->cap;
        while (next < w->len + len) {
            next *= 2U;
        }
        uint8_t *grown = realloc(w->data, next);
        if (grown == nullptr) {
            w->ok = false;
            return;
        }
        w->data = grown;
        w->cap = next;
    }
    memcpy(w->data + w->len, src, len);
    w->len += len;
}

static void ftn_writer_u32(ftn_writer_t *w, uint32_t value)
{
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8),
                        (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    ftn_writer_put(w, bytes, sizeof(bytes));
}

static void ftn_writer_i64(ftn_writer_t *w, int64_t value)
{
    uint64_t raw = (uint64_t)value;
    uint8_t bytes[8];
    for (size_t idx = 0U; idx < 8U; ++idx) {
        bytes[idx] = (uint8_t)(raw >> (8U * idx));
    }
    ftn_writer_put(w, bytes, sizeof(bytes));
}

static void ftn_writer_str(ftn_writer_t *w, const char *text)
{
    size_t len = text != nullptr ? strlen(text) : 0U;
    if (len > 0xFFFFU) {
        len = 0xFFFFU;
    }
    uint8_t bytes[2] = {(uint8_t)len, (uint8_t)(len >> 8)};
    ftn_writer_put(w, bytes, sizeof(bytes));
    if (len > 0U) {
        ftn_writer_put(w, text, len);
    }
}

typedef struct ftn_reader {
    const uint8_t *data;
    size_t len;
    size_t pos;
    bool ok;
} ftn_reader_t;

static uint32_t ftn_reader_u32(ftn_reader_t *r)
{
    if (!r->ok || r->pos + 4U > r->len) {
        r->ok = false;
        return 0U;
    }
    const uint8_t *b = r->data + r->pos;
    r->pos += 4U;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static int64_t ftn_reader_i64(ftn_reader_t *r)
{
    if (!r->ok || r->pos + 8U > r->len) {
        r->ok = false;
        return 0;
    }
    uint64_t raw = 0U;
    for (size_t idx = 0U; idx < 8U; ++idx) {
        raw |= (uint64_t)r->data[r->pos + idx] << (8U * idx);
    }
    r->pos += 8U;
    return (int64_t)raw;
}

static void ftn_reader_str(ftn_reader_t *r, char *out, size_t size)
{
    out[0] = '\0';
    if (!r->ok || r->pos + 2U > r->len) {
        r->ok = false;
        return;
    }
    size_t len = (size_t)r->data[r->pos] | ((size_t)r->data[r->pos + 1] << 8);
    r->pos += 2U;
    if (r->pos + len > r->len) {
        r->ok = false;
        return;
    }
    size_t copy = len < size ? len : size - 1U;
    memcpy(out, r->data + r->pos, copy);
    out[copy] = '\0';
    r->pos += len;
}

static uint8_t *ftn_record_encode(const ftn_message_t *msg, size_t *out_len)
{
    ftn_writer_t w = {.ok = true};
    ftn_writer_put(&w, FTN_MSGBASE_MAGIC, 4U);
    ftn_writer_u32(&w, 0U); /* payload length, patched below */
    ftn_writer_str(&w, msg->area);
    ftn_writer_str(&w, msg->from);
    ftn_writer_str(&w, msg->to);
    ftn_writer_str(&w, msg->subject);
    ftn_writer_str(&w, msg->msgid);
    ftn_writer_str(&w, msg->reply);
    ftn_writer_str(&w, msg->origin_addr);
    ftn_writer_str(&w, msg->charset);
    const size_t body_len = msg->body != nullptr ? strlen(msg->body) : 0U;
    ftn_writer_u32(&w, (uint32_t)body_len);
    if (body_len > 0U) {
        ftn_writer_put(&w, msg->body, body_len);
    }
    ftn_writer_i64(&w, (int64_t)msg->written);
    ftn_writer_i64(&w, (int64_t)msg->imported);
    ftn_writer_u32(&w, msg->flags);
    if (!w.ok || w.len - 8U > FTN_MSGBASE_MAX_RECORD) {
        free(w.data);
        return nullptr;
    }
    const uint32_t payload = (uint32_t)(w.len - 8U);
    w.data[4] = (uint8_t)payload;
    w.data[5] = (uint8_t)(payload >> 8);
    w.data[6] = (uint8_t)(payload >> 16);
    w.data[7] = (uint8_t)(payload >> 24);
    *out_len = w.len;
    return w.data;
}

/* Decode one payload; with_body false leaves msg->body nullptr. */
static bool ftn_record_decode(const uint8_t *payload, size_t len,
                              ftn_message_t *msg, bool with_body)
{
    memset(msg, 0, sizeof(*msg));
    ftn_reader_t r = {.data = payload, .len = len, .ok = true};
    ftn_reader_str(&r, msg->area, sizeof(msg->area));
    ftn_reader_str(&r, msg->from, sizeof(msg->from));
    ftn_reader_str(&r, msg->to, sizeof(msg->to));
    ftn_reader_str(&r, msg->subject, sizeof(msg->subject));
    ftn_reader_str(&r, msg->msgid, sizeof(msg->msgid));
    ftn_reader_str(&r, msg->reply, sizeof(msg->reply));
    ftn_reader_str(&r, msg->origin_addr, sizeof(msg->origin_addr));
    ftn_reader_str(&r, msg->charset, sizeof(msg->charset));
    const uint32_t body_len = ftn_reader_u32(&r);
    if (!r.ok || r.pos + body_len > r.len) {
        return false;
    }
    if (with_body) {
        msg->body = malloc((size_t)body_len + 1U);
        if (msg->body == nullptr) {
            return false;
        }
        memcpy(msg->body, r.data + r.pos, body_len);
        msg->body[body_len] = '\0';
    }
    r.pos += body_len;
    msg->written = (time_t)ftn_reader_i64(&r);
    msg->imported = (time_t)ftn_reader_i64(&r);
    msg->flags = ftn_reader_u32(&r);
    if (!r.ok) {
        free(msg->body);
        msg->body = nullptr;
        return false;
    }
    return true;
}

/* ---- message base ---- */

static bool ftn_msgbase_append(const char *dir, const ftn_message_t *msg)
{
    const char *area = msg->area[0] != '\0' ? msg->area : FTN_NETMAIL_AREA;
    char path[PATH_MAX];
    char areas_dir[PATH_MAX];
    if (!ftn_msgbase_path(dir, area, path, sizeof(path)) ||
        snprintf(areas_dir, sizeof(areas_dir), "%s/areas", dir) >=
            (int)sizeof(areas_dir) ||
        !ftn_mkdir_p(areas_dir)) {
        return false;
    }
    size_t record_len = 0U;
    uint8_t *record = ftn_record_encode(msg, &record_len);
    if (record == nullptr) {
        return false;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) {
        free(record);
        return false;
    }
    ssize_t written = write(fd, record, record_len);
    bool ok = written == (ssize_t)record_len && fsync(fd) == 0;
    close(fd);
    free(record);
    return ok;
}

/* Visit every message of an area in order; the callback gets the 1-based
 * number and returns false to stop.  Bodies are loaded only when asked
 * for, and are freed after the callback returns. */
typedef bool (*ftn_msgbase_visit_fn)(size_t number, const ftn_message_t *msg,
                                     void *user);

static size_t ftn_msgbase_each(const char *dir, const char *area,
                               bool with_body, ftn_msgbase_visit_fn visit,
                               void *user)
{
    char path[PATH_MAX];
    if (!ftn_msgbase_path(dir, area, path, sizeof(path))) {
        return 0U;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == nullptr) {
        return 0U;
    }
    size_t number = 0U;
    uint8_t *payload = nullptr;
    size_t payload_cap = 0U;
    for (;;) {
        uint8_t head[8];
        if (fread(head, 1U, sizeof(head), fp) != sizeof(head) ||
            memcmp(head, FTN_MSGBASE_MAGIC, 4U) != 0) {
            break;
        }
        const size_t len = (size_t)head[4] | ((size_t)head[5] << 8) |
                           ((size_t)head[6] << 16) | ((size_t)head[7] << 24);
        if (len > FTN_MSGBASE_MAX_RECORD) {
            break;
        }
        if (len > payload_cap) {
            uint8_t *grown = realloc(payload, len);
            if (grown == nullptr) {
                break;
            }
            payload = grown;
            payload_cap = len;
        }
        if (fread(payload, 1U, len, fp) != len) {
            break;
        }
        ftn_message_t msg;
        if (!ftn_record_decode(payload, len, &msg, with_body)) {
            break;
        }
        ++number;
        bool keep_going = visit == nullptr || visit(number, &msg, user);
        free(msg.body);
        if (!keep_going) {
            break;
        }
    }
    free(payload);
    fclose(fp);
    return number;
}

static size_t ftn_msgbase_count(const char *dir, const char *area)
{
    return ftn_msgbase_each(dir, area, false, nullptr, nullptr);
}

typedef struct ftn_msgbase_pick {
    size_t want;
    ftn_message_t *out;
    bool found;
} ftn_msgbase_pick_t;

static bool ftn_msgbase_pick_visit(size_t number, const ftn_message_t *msg,
                                   void *user)
{
    ftn_msgbase_pick_t *pick = user;
    if (number != pick->want) {
        return true;
    }
    *pick->out = *msg;
    if (msg->body != nullptr) {
        pick->out->body = strdup(msg->body);
    }
    pick->found = msg->body == nullptr || pick->out->body != nullptr;
    return false;
}

/* Load message number (1-based) with its body; free with
 * ftn_message_free. */
static bool ftn_msgbase_read(const char *dir, const char *area, size_t number,
                             ftn_message_t *out)
{
    ftn_msgbase_pick_t pick = {.want = number, .out = out, .found = false};
    memset(out, 0, sizeof(*out));
    ftn_msgbase_each(dir, area, true, ftn_msgbase_pick_visit, &pick);
    return pick.found;
}

/* ---- dupe keys ---- */

/* 64-bit FNV-1a, used when a message has no MSGID. */
static uint64_t ftn_fnv1a(uint64_t hash, const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text;
         p != nullptr && *p != '\0'; ++p) {
        hash ^= *p;
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* "AREA msgid", or "AREA #<hash>" built from the header and body. */
static void ftn_dupe_key(const ftn_message_t *msg, const char *raw_datetime,
                         char *out, size_t size)
{
    const char *area = msg->area[0] != '\0' ? msg->area : FTN_NETMAIL_AREA;
    if (msg->msgid[0] != '\0') {
        snprintf(out, size, "%s %s", area, msg->msgid);
        return;
    }
    uint64_t hash = 14695981039346656037ULL;
    hash = ftn_fnv1a(hash, msg->from);
    hash = ftn_fnv1a(hash, msg->to);
    hash = ftn_fnv1a(hash, msg->subject);
    hash = ftn_fnv1a(hash, raw_datetime);
    hash = ftn_fnv1a(hash, msg->body);
    snprintf(out, size, "%s #%016llx", area, (unsigned long long)hash);
}

static bool ftn_dupe_seen(const char *dir, const char *key)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/dupes.dat", dir);
    FILE *fp = fopen(path, "rb");
    if (fp == nullptr) {
        return false;
    }
    char line[FTN_AREATAG_LEN + FTN_MSGID_LEN + 8U];
    bool seen = false;
    while (!seen && fgets(line, sizeof(line), fp) != nullptr) {
        line[strcspn(line, "\r\n")] = '\0';
        seen = strcmp(line, key) == 0;
    }
    fclose(fp);
    return seen;
}

/* Record a dupe key; past twice FTN_DUPES_KEEP lines the file is rewritten
 * with the newest FTN_DUPES_KEEP. */
static void ftn_dupe_add(const char *dir, const char *key)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/dupes.dat", dir);
    FILE *fp = ftn_fopen_private(path, "ab");
    if (fp == nullptr) {
        return;
    }
    fprintf(fp, "%s\n", key);
    long size = ftell(fp);
    fclose(fp);
    if (size < (long)(FTN_DUPES_KEEP * 2U * 48U)) {
        return;
    }

    fp = fopen(path, "rb");
    if (fp == nullptr) {
        return;
    }
    size_t count = 0U;
    char line[FTN_AREATAG_LEN + FTN_MSGID_LEN + 8U];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        ++count;
    }
    if (count <= FTN_DUPES_KEEP * 2U) {
        fclose(fp);
        return;
    }
    rewind(fp);
    char temp[PATH_MAX + 8];
    snprintf(temp, sizeof(temp), "%s.tmp", path);
    FILE *out = ftn_fopen_private(temp, "wb");
    if (out == nullptr) {
        fclose(fp);
        return;
    }
    size_t skip = count - FTN_DUPES_KEEP;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (skip > 0U) {
            --skip;
            continue;
        }
        fputs(line, out);
    }
    fclose(fp);
    fclose(out);
    rename(temp, path);
}

/* ---- hidden messages ---- */

static bool ftn_hidden_contains(const char *dir, const char *area,
                                size_t number)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/hidden.dat", dir);
    FILE *fp = fopen(path, "rb");
    if (fp == nullptr) {
        return false;
    }
    char tag[FTN_AREATAG_LEN];
    unsigned long value = 0UL;
    bool found = false;
    char line[FTN_AREATAG_LEN + 32U];
    while (!found && fgets(line, sizeof(line), fp) != nullptr) {
        if (sscanf(line, "%60s %lu", tag, &value) == 2 &&
            strcasecmp(tag, area) == 0 && value == (unsigned long)number) {
            found = true;
        }
    }
    fclose(fp);
    return found;
}

static bool ftn_hidden_set(const char *dir, const char *area, size_t number,
                           bool hidden)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/hidden.dat", dir);
    char temp[PATH_MAX + 8];
    snprintf(temp, sizeof(temp), "%s.tmp", path);
    FILE *out = ftn_fopen_private(temp, "wb");
    if (out == nullptr) {
        return false;
    }
    FILE *fp = fopen(path, "rb");
    if (fp != nullptr) {
        char tag[FTN_AREATAG_LEN];
        unsigned long value = 0UL;
        char line[FTN_AREATAG_LEN + 32U];
        while (fgets(line, sizeof(line), fp) != nullptr) {
            if (sscanf(line, "%60s %lu", tag, &value) != 2) {
                continue;
            }
            if (strcasecmp(tag, area) == 0 &&
                value == (unsigned long)number) {
                continue;
            }
            fprintf(out, "%s %lu\n", tag, value);
        }
        fclose(fp);
    }
    if (hidden) {
        fprintf(out, "%s %zu\n", area, number);
    }
    bool ok = fclose(out) == 0;
    return ok && rename(temp, path) == 0;
}
