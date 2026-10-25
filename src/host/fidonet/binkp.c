/**
 * @file binkp.c
 * @desc BinkP session engine (FTS-1026, binkp/1.0 semantics) for one
 *       connected socket, in either role:
 *
 *         originator  sends its M_NUL/M_ADR, waits for the remote M_ADR,
 *                     answers with M_PWD (CRAM-MD5 when the answerer offers
 *                     a challenge, FTS-1027) and waits for M_OK.
 *         answerer    offers "OPT CRAM-MD5-<challenge>" when a password is
 *                     set, sends M_NUL/M_ADR, checks the remote address and
 *                     password and replies M_OK or M_ERR.
 *
 *       Then both sides send their queued files (M_FILE + data frames, each
 *       acknowledged by M_GOT), receive the other side's, and close once
 *       both have sent M_EOB with nothing outstanding.  Received files are
 *       written as ".<name>.part" in the inbound directory and renamed when
 *       complete.  Built on the discarded fidonet_client.c framing (commit
 *       f25bfcd^) with Synchronet's binkp.js as the behavioural reference.
 *       Only libc and libcrypto are used so the unit test can include it.
 */

#include "ftn.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BINKP_DEFAULT_PORT 24554
#define BINKP_MAX_FRAME 32767U
#define BINKP_DATA_CHUNK 4096U
#define BINKP_MAX_FILES 256U

enum {
    BINKP_M_NUL = 0,
    BINKP_M_ADR = 1,
    BINKP_M_PWD = 2,
    BINKP_M_FILE = 3,
    BINKP_M_OK = 4,
    BINKP_M_EOB = 5,
    BINKP_M_GOT = 6,
    BINKP_M_ERR = 7,
    BINKP_M_BSY = 8,
    BINKP_M_GET = 9,
    BINKP_M_SKIP = 10,
};

/* One file offered to the remote. */
typedef struct ftn_binkp_file {
    char path[PATH_MAX];
    char name[64]; /* name sent in M_FILE */
    long long size;
    long long mtime;
} ftn_binkp_file_t;

typedef void (*ftn_binkp_sent_fn)(const char *path, void *user);
typedef void (*ftn_binkp_log_fn)(void *user, const char *line);

typedef struct ftn_binkp_config {
    bool originator;
    ftn_addr_t self;
    ftn_addr_t remote;    /* the uplink: expected (originator) or accepted
                             (answerer) */
    const char *password; /* "" or nullptr: unsecured session */
    const char *inbound_dir;
    const ftn_binkp_file_t *files; /* sent only on a secured session */
    size_t file_count;
    const char *system_name;
    const char *sysop;
    const char *location;
    int timeout_seconds;
    const volatile bool *stop;
    ftn_binkp_sent_fn on_sent; /* after M_GOT for a file we sent */
    ftn_binkp_log_fn log;
    void *user;
} ftn_binkp_config_t;

typedef struct ftn_binkp_result {
    bool authenticated;
    bool secure;
    size_t files_sent;
    size_t files_received;
    char remote_addrs[256];
    char error[160];
} ftn_binkp_result_t;

typedef struct ftn_binkp_frame {
    bool command;
    uint8_t cmd;
    size_t len; /* argument / data length */
    char data[BINKP_MAX_FRAME + 1U];
} ftn_binkp_frame_t;

typedef struct ftn_binkp_session {
    int fd;
    const ftn_binkp_config_t *cfg;
    ftn_binkp_result_t *res;
    uint8_t rbuf[BINKP_MAX_FRAME + 2U];
    size_t rlen;
    time_t last_activity;
    char challenge_hex[33]; /* answerer: our challenge; originator: theirs */
    /* transfer state */
    size_t next_file;
    int send_fd;
    const ftn_binkp_file_t *sending;
    long long send_offset;
    bool pending[BINKP_MAX_FILES];
    size_t pending_count;
    int recv_fd;
    char recv_name[64];
    char recv_part[PATH_MAX];
    long long recv_size;
    long long recv_mtime;
    long long recv_done;
    bool sent_eob;
    bool got_eob;
} ftn_binkp_session_t;

static void binkp_log(ftn_binkp_session_t *s, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void binkp_log(ftn_binkp_session_t *s, const char *format, ...)
{
    if (s->cfg->log == nullptr) {
        return;
    }
    char line[256];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    s->cfg->log(s->cfg->user, line);
}

static void binkp_fail(ftn_binkp_session_t *s, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void binkp_fail(ftn_binkp_session_t *s, const char *format, ...)
{
    if (s->res->error[0] != '\0') {
        return;
    }
    va_list args;
    va_start(args, format);
    vsnprintf(s->res->error, sizeof(s->res->error), format, args);
    va_end(args);
    binkp_log(s, "error: %s", s->res->error);
}

/* ---- frames ---- */

static bool binkp_write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0U) {
        ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                if (poll(&pfd, 1, 30000) <= 0) {
                    return false;
                }
                continue;
            }
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

/* Header: 15-bit length, top bit set for a command frame.  A command frame
 * carries the command byte, then its arguments. */
static bool binkp_send_frame(ftn_binkp_session_t *s, bool command,
                             uint8_t cmd, const void *data, size_t len)
{
    size_t total = len + (command ? 1U : 0U);
    if (total > BINKP_MAX_FRAME) {
        return false;
    }
    uint8_t frame[BINKP_MAX_FRAME + 2U];
    frame[0] = (uint8_t)(((total >> 8) & 0x7FU) | (command ? 0x80U : 0U));
    frame[1] = (uint8_t)(total & 0xFFU);
    size_t pos = 2U;
    if (command) {
        frame[pos++] = cmd;
    }
    if (len > 0U) {
        memcpy(frame + pos, data, len);
    }
    if (!binkp_write_all(s->fd, frame, total + 2U)) {
        return false;
    }
    s->last_activity = time(nullptr);
    return true;
}

static bool binkp_send_cmd(ftn_binkp_session_t *s, uint8_t cmd,
                           const char *format, ...)
    __attribute__((format(printf, 3, 4)));

static bool binkp_send_cmd(ftn_binkp_session_t *s, uint8_t cmd,
                           const char *format, ...)
{
    char args[1024] = {0};
    if (format != nullptr) {
        va_list ap;
        va_start(ap, format);
        vsnprintf(args, sizeof(args), format, ap);
        va_end(ap);
    }
    if (cmd == BINKP_M_EOB) {
        s->sent_eob = true;
    }
    return binkp_send_frame(s, true, cmd, args, strlen(args));
}

/* Read one frame, waiting at most timeout_ms.  Returns 1 with a frame, 0
 * on timeout and -1 when the connection is gone. */
static int binkp_read_frame(ftn_binkp_session_t *s, int timeout_ms,
                            ftn_binkp_frame_t *frame)
{
    for (;;) {
        if (s->rlen >= 2U) {
            size_t len = ((size_t)(s->rbuf[0] & 0x7FU) << 8) | s->rbuf[1];
            if (s->rlen >= len + 2U) {
                frame->command = (s->rbuf[0] & 0x80U) != 0U;
                const uint8_t *payload = s->rbuf + 2U;
                if (frame->command) {
                    if (len == 0U) {
                        return -1;
                    }
                    frame->cmd = payload[0];
                    ++payload;
                    --len;
                }
                memcpy(frame->data, payload, len);
                frame->data[len] = '\0';
                frame->len = len;
                size_t used = (size_t)(payload - s->rbuf) + len;
                memmove(s->rbuf, s->rbuf + used, s->rlen - used);
                s->rlen -= used;
                s->last_activity = time(nullptr);
                return 1;
            }
        }
        struct pollfd pfd = {.fd = s->fd, .events = POLLIN};
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            return ready == 0 ? 0 : -1;
        }
        ssize_t n = recv(s->fd, s->rbuf + s->rlen, sizeof(s->rbuf) - s->rlen,
                         0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        s->rlen += (size_t)n;
        timeout_ms = 1000;
    }
}

/* ---- CRAM-MD5 (FTS-1027) ---- */

static bool binkp_hex_decode(const char *hex, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    size_t len = strlen(hex);
    if (len == 0U || len % 2U != 0U || len / 2U > cap) {
        return false;
    }
    for (size_t idx = 0U; idx < len / 2U; ++idx) {
        unsigned int byte = 0U;
        if (!isxdigit((unsigned char)hex[2U * idx]) ||
            !isxdigit((unsigned char)hex[2U * idx + 1U]) ||
            sscanf(hex + 2U * idx, "%2x", &byte) != 1) {
            return false;
        }
        out[idx] = (uint8_t)byte;
    }
    *out_len = len / 2U;
    return true;
}

/* "CRAM-MD5-" + hex(HMAC-MD5(password, challenge bytes)). */
static bool binkp_cram_response(const char *password,
                                const char *challenge_hex, char *out,
                                size_t size)
{
    uint8_t challenge[64];
    size_t challenge_len = 0U;
    if (!binkp_hex_decode(challenge_hex, challenge, sizeof(challenge),
                          &challenge_len)) {
        return false;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0U;
    if (HMAC(EVP_md5(), password, (int)strlen(password), challenge,
             challenge_len, digest, &digest_len) == nullptr ||
        digest_len != 16U || size < 9U + 33U) {
        return false;
    }
    int pos = snprintf(out, size, "CRAM-MD5-");
    for (unsigned int idx = 0U; idx < digest_len; ++idx) {
        pos += snprintf(out + pos, size - (size_t)pos, "%02x", digest[idx]);
    }
    return true;
}

/* ---- file names ---- */

/* Undo binkp's "\xHH" escaping and keep only a safe base name. */
static bool binkp_safe_name(const char *wire, char *out, size_t size)
{
    size_t o = 0U;
    for (size_t i = 0U; wire[i] != '\0' && o + 1U < size; ++i) {
        char ch = wire[i];
        if (ch == '\\' && wire[i + 1U] == 'x' &&
            isxdigit((unsigned char)wire[i + 2U]) &&
            isxdigit((unsigned char)wire[i + 3U])) {
            unsigned int byte = 0U;
            sscanf(wire + i + 2U, "%2x", &byte);
            ch = (char)byte;
            i += 3U;
        }
        if (ch == '/' || ch == '\\') {
            o = 0U; /* keep only the last path component */
            continue;
        }
        if (!isalnum((unsigned char)ch) && ch != '.' && ch != '_' &&
            ch != '-') {
            ch = '_';
        }
        out[o++] = ch;
    }
    out[o] = '\0';
    while (out[0] == '.') {
        memmove(out, out + 1, strlen(out));
    }
    return out[0] != '\0';
}

/* "name size mtime [offset]" (M_FILE) or "name size mtime" (M_GOT etc). */
static int binkp_parse_file_args(const char *args, char *name, size_t size,
                                 long long *length, long long *mtime,
                                 long long *offset)
{
    char wire[256];
    *offset = 0;
    int fields = sscanf(args, "%255s %lld %lld %lld", wire, length, mtime,
                        offset);
    if (fields < 3 || *length < 0) {
        return 0;
    }
    snprintf(name, size, "%s", wire);
    return fields;
}

/* ---- receiving ---- */

static void binkp_recv_abort(ftn_binkp_session_t *s)
{
    if (s->recv_fd >= 0) {
        close(s->recv_fd);
        s->recv_fd = -1;
        unlink(s->recv_part);
    }
}

static bool binkp_recv_finish(ftn_binkp_session_t *s)
{
    close(s->recv_fd);
    s->recv_fd = -1;
    char safe[64];
    if (!binkp_safe_name(s->recv_name, safe, sizeof(safe))) {
        snprintf(safe, sizeof(safe), "unnamed");
    }
    char final_path[PATH_MAX];
    snprintf(final_path, sizeof(final_path), "%s/%s", s->cfg->inbound_dir,
             safe);
    for (unsigned int n = 1U; access(final_path, F_OK) == 0 && n < 1000U;
         ++n) {
        snprintf(final_path, sizeof(final_path), "%s/%u_%s",
                 s->cfg->inbound_dir, n, safe);
    }
    if (rename(s->recv_part, final_path) != 0) {
        unlink(s->recv_part);
        binkp_fail(s, "cannot store %s", safe);
        return false;
    }
    ++s->res->files_received;
    binkp_log(s, "received %s (%lld bytes)", safe, s->recv_size);
    return binkp_send_cmd(s, BINKP_M_GOT, "%s %lld %lld", s->recv_name,
                          s->recv_size, s->recv_mtime);
}

static bool binkp_recv_begin(ftn_binkp_session_t *s, const char *args)
{
    binkp_recv_abort(s);
    char name[64];
    long long length = 0, mtime = 0, offset = 0;
    if (binkp_parse_file_args(args, name, sizeof(name), &length, &mtime,
                              &offset) < 3) {
        binkp_send_cmd(s, BINKP_M_ERR, "Invalid M_FILE");
        binkp_fail(s, "invalid M_FILE \"%s\"", args);
        return false;
    }
    if (offset != 0) {
        /* We never keep partial files across sessions: ask for the
         * start. */
        return binkp_send_cmd(s, BINKP_M_GET, "%s %lld %lld 0", name, length,
                              mtime);
    }
    char safe[64];
    if (!binkp_safe_name(name, safe, sizeof(safe))) {
        return binkp_send_cmd(s, BINKP_M_SKIP, "%s %lld %lld", name, length,
                              mtime);
    }
    snprintf(s->recv_part, sizeof(s->recv_part), "%s/.%s.part",
             s->cfg->inbound_dir, safe);
    s->recv_fd = open(s->recv_part, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                      0600);
    if (s->recv_fd < 0) {
        return binkp_send_cmd(s, BINKP_M_SKIP, "%s %lld %lld", name, length,
                              mtime);
    }
    snprintf(s->recv_name, sizeof(s->recv_name), "%s", name);
    s->recv_size = length;
    s->recv_mtime = mtime;
    s->recv_done = 0;
    if (length == 0) {
        return binkp_recv_finish(s);
    }
    return true;
}

static bool binkp_recv_data(ftn_binkp_session_t *s, const ftn_binkp_frame_t *f)
{
    if (s->recv_fd < 0) {
        return true; /* data after a skip: ignore */
    }
    size_t len = f->len;
    if ((long long)len > s->recv_size - s->recv_done) {
        binkp_recv_abort(s);
        binkp_send_cmd(s, BINKP_M_ERR, "Data past end of file");
        binkp_fail(s, "remote sent more data than announced");
        return false;
    }
    if (write(s->recv_fd, f->data, len) != (ssize_t)len) {
        binkp_recv_abort(s);
        binkp_fail(s, "write failed: %s", strerror(errno));
        return false;
    }
    s->recv_done += (long long)len;
    if (s->recv_done == s->recv_size) {
        return binkp_recv_finish(s);
    }
    return true;
}

/* ---- sending ---- */

static long binkp_find_file(const ftn_binkp_session_t *s, const char *name)
{
    for (size_t idx = 0U; idx < s->cfg->file_count; ++idx) {
        if (strcmp(s->cfg->files[idx].name, name) == 0) {
            return (long)idx;
        }
    }
    return -1;
}

static bool binkp_start_file(ftn_binkp_session_t *s, size_t idx,
                             long long offset)
{
    const ftn_binkp_file_t *file = &s->cfg->files[idx];
    if (s->send_fd >= 0) {
        close(s->send_fd);
    }
    s->send_fd = open(file->path, O_RDONLY | O_NOFOLLOW);
    if (s->send_fd < 0 || lseek(s->send_fd, (off_t)offset, SEEK_SET) < 0) {
        if (s->send_fd >= 0) {
            close(s->send_fd);
            s->send_fd = -1;
        }
        binkp_log(s, "skipping %s: %s", file->path, strerror(errno));
        return true;
    }
    s->sending = file;
    s->send_offset = offset;
    if (!s->pending[idx]) {
        s->pending[idx] = true;
        ++s->pending_count;
    }
    return binkp_send_cmd(s, BINKP_M_FILE, "%s %lld %lld %lld", file->name,
                          file->size, file->mtime, offset);
}

/* Send the next data block, start the next file, or say M_EOB. */
static bool binkp_pump_send(ftn_binkp_session_t *s)
{
    if (s->sending != nullptr) {
        uint8_t chunk[BINKP_DATA_CHUNK];
        ssize_t n = read(s->send_fd, chunk, sizeof(chunk));
        if (n < 0) {
            binkp_fail(s, "read failed: %s", strerror(errno));
            return false;
        }
        if (n > 0) {
            s->send_offset += n;
            if (!binkp_send_frame(s, false, 0U, chunk, (size_t)n)) {
                return false;
            }
        }
        if (n == 0 || s->send_offset >= s->sending->size) {
            close(s->send_fd);
            s->send_fd = -1;
            s->sending = nullptr;
        }
        return true;
    }
    if (s->res->secure && s->next_file < s->cfg->file_count) {
        return binkp_start_file(s, s->next_file++, 0);
    }
    if (!s->sent_eob) {
        return binkp_send_cmd(s, BINKP_M_EOB, nullptr);
    }
    return true;
}

static void binkp_file_acked(ftn_binkp_session_t *s, const char *args,
                             bool delivered)
{
    char name[64];
    long long length = 0, mtime = 0, offset = 0;
    if (binkp_parse_file_args(args, name, sizeof(name), &length, &mtime,
                              &offset) < 1) {
        return;
    }
    long idx = binkp_find_file(s, name);
    if (idx < 0 || !s->pending[idx]) {
        return;
    }
    s->pending[idx] = false;
    --s->pending_count;
    if (s->sending == &s->cfg->files[idx]) {
        close(s->send_fd);
        s->send_fd = -1;
        s->sending = nullptr;
    }
    if (delivered) {
        ++s->res->files_sent;
        binkp_log(s, "sent %s", name);
        if (s->cfg->on_sent != nullptr) {
            s->cfg->on_sent(s->cfg->files[idx].path, s->cfg->user);
        }
    } else {
        binkp_log(s, "remote skipped %s", name);
    }
}

/* ---- handshake ---- */

static bool binkp_addr_list_has(const char *list, const ftn_addr_t *want)
{
    char copy[256];
    snprintf(copy, sizeof(copy), "%s", list);
    char *save = nullptr;
    for (char *tok = strtok_r(copy, " ", &save); tok != nullptr;
         tok = strtok_r(nullptr, " ", &save)) {
        ftn_addr_t addr;
        if (ftn_addr_parse(tok, &addr) && ftn_addr_equal(&addr, want)) {
            return true;
        }
    }
    return false;
}

static bool binkp_send_banner(ftn_binkp_session_t *s)
{
    const ftn_binkp_config_t *cfg = s->cfg;
    char self_text[FTN_ADDR_TEXT_LEN];
    ftn_addr_format(&cfg->self, self_text, sizeof(self_text));
    time_t now = time(nullptr);
    char when[64];
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    strftime(when, sizeof(when), "%a, %d %b %Y %H:%M:%S +0000", &tm_utc);
    return binkp_send_cmd(s, BINKP_M_NUL, "SYS %s",
                          cfg->system_name != nullptr ? cfg->system_name
                                                      : "SSH-Chatter") &&
           binkp_send_cmd(s, BINKP_M_NUL, "ZYZ %s",
                          cfg->sysop != nullptr ? cfg->sysop : "Sysop") &&
           binkp_send_cmd(s, BINKP_M_NUL, "LOC %s",
                          cfg->location != nullptr ? cfg->location
                                                   : "Internet") &&
           binkp_send_cmd(s, BINKP_M_NUL, "NDL 115200,TCP,BINKP") &&
           binkp_send_cmd(s, BINKP_M_NUL, "TIME %s", when) &&
           binkp_send_cmd(s, BINKP_M_NUL, "VER %s/%s binkp/1.0",
                          FTN_PRODUCT_NAME, FTN_PRODUCT_VERSION) &&
           binkp_send_cmd(s, BINKP_M_ADR, "%s", self_text);
}

/* Wait for a frame during the handshake; M_NUL lines are handled here
 * (an "OPT CRAM-MD5-..." challenge is remembered). */
static int binkp_handshake_frame(ftn_binkp_session_t *s,
                                 ftn_binkp_frame_t *frame)
{
    const int timeout = s->cfg->timeout_seconds > 0 ? s->cfg->timeout_seconds
                                                    : 60;
    for (;;) {
        if (s->cfg->stop != nullptr && *s->cfg->stop) {
            binkp_fail(s, "stopped");
            return -1;
        }
        int rc = binkp_read_frame(s, 1000, frame);
        if (rc < 0) {
            binkp_fail(s, "connection closed during handshake");
            return -1;
        }
        if (rc == 0) {
            if (time(nullptr) - s->last_activity > timeout) {
                binkp_fail(s, "handshake timed out");
                return -1;
            }
            continue;
        }
        if (!frame->command) {
            continue;
        }
        if (frame->cmd == BINKP_M_NUL) {
            const char *opt = strstr(frame->data, "OPT ");
            const char *cram =
                opt != nullptr ? strstr(opt, "CRAM-MD5-") : nullptr;
            if (cram != nullptr && !s->cfg->originator) {
                cram = nullptr; /* only the answerer issues challenges */
            }
            if (cram != nullptr) {
                cram += 9;
                size_t len = strspn(cram, "0123456789abcdefABCDEF");
                if (len > 0U && len < sizeof(s->challenge_hex)) {
                    memcpy(s->challenge_hex, cram, len);
                    s->challenge_hex[len] = '\0';
                }
            }
            binkp_log(s, "remote: %s", frame->data);
            continue;
        }
        if (frame->cmd == BINKP_M_ERR || frame->cmd == BINKP_M_BSY) {
            binkp_fail(s, "remote %s: %s",
                       frame->cmd == BINKP_M_ERR ? "error" : "busy",
                       frame->data);
            return -1;
        }
        return 1;
    }
}

static bool binkp_handshake_originator(ftn_binkp_session_t *s)
{
    const char *password =
        s->cfg->password != nullptr ? s->cfg->password : "";
    if (!binkp_send_banner(s)) {
        binkp_fail(s, "send failed");
        return false;
    }
    ftn_binkp_frame_t *frame = malloc(sizeof(*frame));
    if (frame == nullptr) {
        return false;
    }
    bool ok = false;
    for (;;) {
        if (binkp_handshake_frame(s, frame) < 0) {
            break;
        }
        if (frame->cmd != BINKP_M_ADR) {
            continue;
        }
        snprintf(s->res->remote_addrs, sizeof(s->res->remote_addrs), "%s",
                 frame->data);
        if (!binkp_addr_list_has(frame->data, &s->cfg->remote)) {
            binkp_send_cmd(s, BINKP_M_ERR, "Wrong address");
            binkp_fail(s, "remote presented %s, not our uplink", frame->data);
            break;
        }
        char response[64];
        if (password[0] == '\0') {
            ok = binkp_send_cmd(s, BINKP_M_PWD, "-");
        } else if (s->challenge_hex[0] != '\0' &&
                   binkp_cram_response(password, s->challenge_hex, response,
                                       sizeof(response))) {
            ok = binkp_send_cmd(s, BINKP_M_PWD, "%s", response);
        } else {
            ok = binkp_send_cmd(s, BINKP_M_PWD, "%s", password);
        }
        if (!ok) {
            break;
        }
        ok = false;
        while (binkp_handshake_frame(s, frame) > 0) {
            if (frame->cmd == BINKP_M_OK) {
                ok = true;
                s->res->authenticated = true;
                s->res->secure = password[0] != '\0' &&
                                 strncasecmp(frame->data, "non-secure",
                                             10) != 0;
                break;
            }
        }
        break;
    }
    free(frame);
    return ok;
}

static bool binkp_handshake_answerer(ftn_binkp_session_t *s)
{
    const char *password =
        s->cfg->password != nullptr ? s->cfg->password : "";
    if (password[0] != '\0') {
        uint8_t challenge[16];
        if (RAND_bytes(challenge, sizeof(challenge)) != 1) {
            binkp_fail(s, "no randomness for the CRAM challenge");
            return false;
        }
        for (size_t idx = 0U; idx < sizeof(challenge); ++idx) {
            snprintf(s->challenge_hex + 2U * idx, 3U, "%02x", challenge[idx]);
        }
        if (!binkp_send_cmd(s, BINKP_M_NUL, "OPT CRAM-MD5-%s",
                            s->challenge_hex)) {
            return false;
        }
    }
    if (!binkp_send_banner(s)) {
        binkp_fail(s, "send failed");
        return false;
    }
    ftn_binkp_frame_t *frame = malloc(sizeof(*frame));
    if (frame == nullptr) {
        return false;
    }
    bool ok = false;
    bool have_adr = false;
    while (binkp_handshake_frame(s, frame) > 0) {
        if (frame->cmd == BINKP_M_ADR) {
            snprintf(s->res->remote_addrs, sizeof(s->res->remote_addrs), "%s",
                     frame->data);
            have_adr = binkp_addr_list_has(frame->data, &s->cfg->remote);
            if (!have_adr) {
                binkp_send_cmd(s, BINKP_M_ERR, "Unknown address");
                binkp_fail(s, "refused %s: not our uplink", frame->data);
                break;
            }
            continue;
        }
        if (frame->cmd != BINKP_M_PWD || !have_adr) {
            continue;
        }
        bool good = false;
        if (password[0] == '\0') {
            good = true;
        } else if (strncmp(frame->data, "CRAM-MD5-", 9) == 0) {
            char expected[64];
            good = binkp_cram_response(password, s->challenge_hex, expected,
                                       sizeof(expected)) &&
                   strcasecmp(expected, frame->data) == 0;
        } else {
            good = strcmp(frame->data, password) == 0;
        }
        if (!good) {
            binkp_send_cmd(s, BINKP_M_ERR, "Bad password");
            binkp_fail(s, "bad password from %s", s->res->remote_addrs);
            break;
        }
        s->res->authenticated = true;
        s->res->secure = password[0] != '\0';
        ok = binkp_send_cmd(s, BINKP_M_OK, "%s",
                            s->res->secure ? "secure" : "non-secure");
        break;
    }
    free(frame);
    return ok;
}

/* ---- session ---- */

/* Run a whole session on a connected socket.  Returns true when it ended
 * cleanly (both sides done); res says what was moved and why it failed. */
static bool ftn_binkp_run(int fd, const ftn_binkp_config_t *cfg,
                          ftn_binkp_result_t *res)
{
    memset(res, 0, sizeof(*res));
    ftn_binkp_session_t *s = calloc(1U, sizeof(*s));
    ftn_binkp_frame_t *frame = malloc(sizeof(*frame));
    if (s == nullptr || frame == nullptr || cfg->file_count > BINKP_MAX_FILES) {
        free(s);
        free(frame);
        snprintf(res->error, sizeof(res->error), "out of memory");
        return false;
    }
    s->fd = fd;
    s->cfg = cfg;
    s->res = res;
    s->send_fd = -1;
    s->recv_fd = -1;
    s->last_activity = time(nullptr);

    bool ok = cfg->originator ? binkp_handshake_originator(s)
                              : binkp_handshake_answerer(s);
    const int timeout = cfg->timeout_seconds > 0 ? cfg->timeout_seconds : 60;
    while (ok) {
        if (cfg->stop != nullptr && *cfg->stop) {
            binkp_fail(s, "stopped");
            ok = false;
            break;
        }
        if (s->sent_eob && s->got_eob && s->pending_count == 0U &&
            s->recv_fd < 0) {
            break;
        }
        const bool busy = s->sending != nullptr ||
                          (s->res->secure && s->next_file < cfg->file_count) ||
                          !s->sent_eob;
        int rc = binkp_read_frame(s, busy ? 0 : 1000, frame);
        if (rc < 0) {
            /* A remote that hangs up right after the last M_EOB/M_GOT has
             * still completed the session. */
            if (!(s->sent_eob && s->got_eob && s->pending_count == 0U &&
                  s->recv_fd < 0)) {
                binkp_fail(s, "connection closed");
                ok = false;
            }
            break;
        }
        if (rc > 0) {
            if (!frame->command) {
                ok = binkp_recv_data(s, frame);
            } else {
                switch (frame->cmd) {
                case BINKP_M_NUL:
                    break;
                case BINKP_M_FILE:
                    ok = binkp_recv_begin(s, frame->data);
                    break;
                case BINKP_M_EOB:
                    s->got_eob = true;
                    break;
                case BINKP_M_GOT:
                    binkp_file_acked(s, frame->data, true);
                    break;
                case BINKP_M_SKIP:
                    binkp_file_acked(s, frame->data, false);
                    break;
                case BINKP_M_GET: {
                    char name[64];
                    long long length = 0, mtime = 0, offset = 0;
                    if (binkp_parse_file_args(frame->data, name, sizeof(name),
                                              &length, &mtime, &offset) == 4) {
                        long idx = binkp_find_file(s, name);
                        if (idx >= 0 && offset >= 0 &&
                            offset <= cfg->files[idx].size) {
                            ok = binkp_start_file(s, (size_t)idx, offset);
                        }
                    }
                    break;
                }
                case BINKP_M_ERR:
                case BINKP_M_BSY:
                    binkp_fail(s, "remote %s: %s",
                               frame->cmd == BINKP_M_ERR ? "error" : "busy",
                               frame->data);
                    ok = false;
                    break;
                default:
                    break;
                }
            }
            continue;
        }
        if (busy) {
            ok = binkp_pump_send(s);
        } else if (time(nullptr) - s->last_activity > timeout) {
            binkp_send_cmd(s, BINKP_M_ERR, "Timeout");
            binkp_fail(s, "session timed out");
            ok = false;
        }
    }

    binkp_recv_abort(s);
    if (s->send_fd >= 0) {
        close(s->send_fd);
    }
    free(frame);
    free(s);
    return ok;
}
