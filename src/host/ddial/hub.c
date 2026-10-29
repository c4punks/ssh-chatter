/**
 * @file hub.c
 * @desc Inbound station links: other DDial stations join THIS station.
 *
 * client.c dials out and joins another station (a hub such as MagViz).
 * This file is the same join sequence seen from the other end, so a
 * station running ssh-chatter (or any DDial that links the same way) can
 * use this station as its hub:
 *
 *   1. The station connects to CHATTER_DDIAL_HUB_LISTEN ([addr:]port).
 *   2. We print "Enter Password or [RETURN]: ".
 *   3. The station sends a station key: nine digits generated here with
 *      /ddial key new <label> or /ddial approve <request-id> and handed to
 *      that station's operator. A station without a key can instead send
 *      @request:<name>, which is persisted in ddial_station_requests.dat.
 *      Keys are stored as PBKDF2 hashes in ddial_station_keys.tsv; the
 *      plain key is shown only once, when it is created.
 *   4. On a valid key we answer "Welcome to <station> station link", the
 *      status line " #<slot>(T1:?)" naming the station's link line, and a
 *      "-->" prompt -- the markers client.c waits for.  A wrong key gets
 *      "Invalid password" and the connection is closed; an address that
 *      keeps failing is refused for a while.
 *   5. The station names itself with /H<name> and from then on speaks the
 *      link wire forms.
 *
 * Traffic from a station:
 *   "#n[T1:handle) msg"   chat from one of its users.  Stored and shown
 *                         with the station's link line in front,
 *                         "<slot>#n[T1:handle) msg", exactly like chat
 *                         relayed by our own upstream hub, and handed to
 *                         the room, local dial-ins and the other linked
 *                         stations.
 *   "/P<line> #n[T1:h) m" private message to a line on this station.
 *   "/E~..."              link e-mail to a member of this station.
 *   "}", "}}", "}}}"      login/logout events and user lists.  Their slot
 *                         numbers are relative to the sender, so they are
 *                         not replayed; who is there is learned from chat.
 *   "/Q"                  hang up.
 *
 * Traffic to the stations: everything this station sends its own upstream
 * hub (public chat from Chatter members, dial-ins and AI members, login and
 * logout events, the }}} user list), chat relayed down from our upstream
 * hub, and chat from the other linked stations.  Station traffic is not
 * passed up to our own upstream hub.
 */

#include "ssh_chatter/ddial_protocol.h"
#include "ssh_chatter/host.h"
#include "ssh_chatter/memory_manager.h"
#include "ssh_chatter/security_layer.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DDIAL_HUB_MAX_STATIONS 16U
/* Link lines handed to stations start here, well above dial-in lines. */
#define DDIAL_HUB_FIRST_SLOT 60U
#define DDIAL_HUB_MAX_KEYS 64U
#define DDIAL_HUB_MAX_REQUESTS 64U
#define DDIAL_HUB_REQUEST_REFRESH_SEC 60
#define DDIAL_HUB_LOGIN_TIMEOUT_SEC 30
#define DDIAL_HUB_POLL_MS 1000
/* Brute-force guard: after this many bad keys from one address within the
 * window, that address is refused until the window has passed. */
#define DDIAL_HUB_FAIL_LIMIT 5U
#define DDIAL_HUB_FAIL_WINDOW_SEC 600
#define DDIAL_HUB_FAIL_TRACK 32U
#define DDIAL_HUB_INPUT_BUF 4096U

typedef struct ddial_hub_key {
    unsigned id;
    char label[DDIAL_MAX_HANDLE_LEN];
    uint8_t salt[SECURITY_LAYER_SALT_LEN];
    uint8_t hash[SECURITY_LAYER_HASH_LEN];
    int64_t created;
    int64_t last_used;
} ddial_hub_key_t;

typedef struct ddial_hub_request {
    unsigned id;
    char name[DDIAL_MAX_HANDLE_LEN];
    char ip[SSH_CHATTER_IP_LEN];
    int64_t created;
    int64_t last_seen;
} ddial_hub_request_t;

typedef enum ddial_hub_request_result {
    DDIAL_HUB_REQUEST_ERROR = -1,
    DDIAL_HUB_REQUEST_NOT_FOUND = 0,
    DDIAL_HUB_REQUEST_OK = 1,
} ddial_hub_request_result_t;

typedef struct ddial_hub_station {
    struct ddial_hub_station *next;
    host_t *host;
    int fd;
    uint16_t slot;
    unsigned key_id;
    _Atomic bool closing;
    time_t connected_at;
    char name[DDIAL_MAX_HANDLE_LEN];
    char ip[SSH_CHATTER_IP_LEN];
    pthread_mutex_t out_lock;
    char input[DDIAL_HUB_INPUT_BUF];
    size_t input_len;
    time_t last_list_sent;
} ddial_hub_station_t;

typedef struct ddial_hub_failure {
    char ip[SSH_CHATTER_IP_LEN];
    unsigned count;
    time_t first;
} ddial_hub_failure_t;

static pthread_mutex_t g_ddial_hub_lock = PTHREAD_MUTEX_INITIALIZER;
static ddial_hub_station_t *g_ddial_hub_stations = nullptr;

static pthread_mutex_t g_ddial_hub_key_lock = PTHREAD_MUTEX_INITIALIZER;
static ddial_hub_key_t g_ddial_hub_keys[DDIAL_HUB_MAX_KEYS];
static size_t g_ddial_hub_key_count = 0U;
/* Ids are never reused, so "#3" always means the same station. */
static unsigned g_ddial_hub_next_key_id = 1U;
static bool g_ddial_hub_keys_loaded = false;
static char g_ddial_hub_key_path[PATH_MAX];
static ddial_hub_request_t g_ddial_hub_requests[DDIAL_HUB_MAX_REQUESTS];
static size_t g_ddial_hub_request_count = 0U;
static unsigned g_ddial_hub_next_request_id = 1U;
static bool g_ddial_hub_requests_loaded = false;
static char g_ddial_hub_request_path[PATH_MAX];
static ddial_hub_failure_t g_ddial_hub_failures[DDIAL_HUB_FAIL_TRACK];

typedef struct ddial_hub_listener {
    int fd;
    _Atomic bool stop;
    _Atomic bool running;
    bool started;
    char bind_address[256];
    char port[16];
} ddial_hub_listener_t;

static ddial_hub_listener_t g_ddial_hub_listener = {.fd = -1};

/* ---- station keys ------------------------------------------------------ */

static void ddial_hub_hex(const uint8_t *src, size_t len, char *dst)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0U; i < len; ++i) {
        dst[i * 2U] = digits[src[i] >> 4];
        dst[i * 2U + 1U] = digits[src[i] & 0x0FU];
    }
    dst[len * 2U] = '\0';
}

static bool ddial_hub_unhex(const char *src, uint8_t *dst, size_t len)
{
    if (src == nullptr || strlen(src) != len * 2U) {
        return false;
    }
    for (size_t i = 0U; i < len; ++i) {
        unsigned value = 0U;
        for (size_t k = 0U; k < 2U; ++k) {
            char c = src[i * 2U + k];
            value <<= 4;
            if (c >= '0' && c <= '9') {
                value |= (unsigned)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                value |= (unsigned)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                value |= (unsigned)(c - 'A' + 10);
            } else {
                return false;
            }
        }
        dst[i] = (uint8_t)value;
    }
    return true;
}

static void ddial_hub_keys_load_locked(host_t *host)
{
    if (g_ddial_hub_keys_loaded || host == nullptr) {
        return;
    }
    g_ddial_hub_keys_loaded = true;

    const char *root =
        host->user_data_root[0] != '\0' ? host->user_data_root : ".";
    const char *override = getenv("CHATTER_DDIAL_MEMBERS_DIR");
    if (override != nullptr && override[0] != '\0') {
        root = override;
    }
    snprintf(g_ddial_hub_key_path, sizeof(g_ddial_hub_key_path),
             "%s/ddial_station_keys.tsv", root);

    FILE *fp = fopen(g_ddial_hub_key_path, "r");
    if (fp == nullptr) {
        return;
    }
    /* "# next_id N", then one key per line:
     * id \t label \t salt_hex \t hash_hex \t created \t last_used */
    char line[512];
    while (fgets(line, sizeof(line), fp) != nullptr &&
           g_ddial_hub_key_count < DDIAL_HUB_MAX_KEYS) {
        line[strcspn(line, "\r\n")] = '\0';
        unsigned next_id = 0U;
        if (sscanf(line, "# next_id %u", &next_id) == 1) {
            if (next_id > g_ddial_hub_next_key_id) {
                g_ddial_hub_next_key_id = next_id;
            }
            continue;
        }
        char *fields[6] = {nullptr};
        char *save = nullptr;
        size_t n = 0U;
        for (char *tok = strtok_r(line, "\t", &save); tok != nullptr && n < 6U;
             tok = strtok_r(nullptr, "\t", &save)) {
            fields[n++] = tok;
        }
        if (n < 4U) {
            continue;
        }
        ddial_hub_key_t key;
        memset(&key, 0, sizeof(key));
        key.id = (unsigned)strtoul(fields[0], nullptr, 10);
        snprintf(key.label, sizeof(key.label), "%s", fields[1]);
        if (key.id == 0U ||
            !ddial_hub_unhex(fields[2], key.salt, sizeof(key.salt)) ||
            !ddial_hub_unhex(fields[3], key.hash, sizeof(key.hash))) {
            continue;
        }
        key.created = n > 4U ? strtoll(fields[4], nullptr, 10) : 0;
        key.last_used = n > 5U ? strtoll(fields[5], nullptr, 10) : 0;
        g_ddial_hub_keys[g_ddial_hub_key_count++] = key;
        if (key.id >= g_ddial_hub_next_key_id) {
            g_ddial_hub_next_key_id = key.id + 1U;
        }
    }
    fclose(fp);
}

/* Rewrite the key file atomically, private to the server user. */
static bool ddial_hub_keys_save_locked(void)
{
    if (g_ddial_hub_key_path[0] == '\0') {
        return false;
    }
    char temp_path[PATH_MAX];
    int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp",
                           g_ddial_hub_key_path);
    if (written < 0 || (size_t)written >= sizeof(temp_path)) {
        return false;
    }
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    FILE *fp = fdopen(fd, "w");
    if (fp == nullptr) {
        close(fd);
        unlink(temp_path);
        return false;
    }
    bool ok = fprintf(fp, "# next_id %u\n", g_ddial_hub_next_key_id) > 0;
    for (size_t i = 0U; i < g_ddial_hub_key_count && ok; ++i) {
        const ddial_hub_key_t *key = &g_ddial_hub_keys[i];
        char salt_hex[SECURITY_LAYER_SALT_LEN * 2U + 1U];
        char hash_hex[SECURITY_LAYER_HASH_LEN * 2U + 1U];
        ddial_hub_hex(key->salt, sizeof(key->salt), salt_hex);
        ddial_hub_hex(key->hash, sizeof(key->hash), hash_hex);
        ok = fprintf(fp, "%u\t%s\t%s\t%s\t%lld\t%lld\n", key->id, key->label,
                     salt_hex, hash_hex, (long long)key->created,
                     (long long)key->last_used) > 0;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        ok = false;
    }
    if (fclose(fp) != 0) {
        ok = false;
    }
    if (!ok || rename(temp_path, g_ddial_hub_key_path) != 0) {
        unlink(temp_path);
        return false;
    }
    return true;
}

/* Nine uniformly random digits (leading zeros allowed). */
static bool ddial_hub_random_key(char out[DDIAL_STATION_KEY_LEN + 1U])
{
    for (int attempt = 0; attempt < 64; ++attempt) {
        uint32_t value = 0U;
        if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) {
            return false;
        }
        /* Reject the tail so every 9-digit key is equally likely. */
        if (value >= 4000000000U) {
            continue;
        }
        snprintf(out, DDIAL_STATION_KEY_LEN + 1U, "%09u",
                 (unsigned)(value % 1000000000U));
        return true;
    }
    return false;
}

/* Create a key for a station.  out_key receives the plain key, which is
 * not stored and cannot be shown again. */
static bool ddial_hub_key_create_locked(
    host_t *host, const char *label,
    char out_key[DDIAL_STATION_KEY_LEN + 1U], unsigned *out_id)
{
    if (host == nullptr || out_key == nullptr) {
        return false;
    }
    char clean_label[DDIAL_MAX_HANDLE_LEN];
    if (label == nullptr ||
        ddial_sanitize_handle(label, strlen(label), clean_label,
                              sizeof(clean_label)) == 0U) {
        snprintf(clean_label, sizeof(clean_label), "%s", "station");
    }
    for (char *p = clean_label; *p != '\0'; ++p) {
        if (*p == '\t' || *p == '\r' || *p == '\n') {
            *p = ' ';
        }
    }

    ddial_hub_keys_load_locked(host);
    if (g_ddial_hub_key_count >= DDIAL_HUB_MAX_KEYS ||
        !ddial_hub_random_key(out_key)) {
        return false;
    }
    ddial_hub_key_t key;
    memset(&key, 0, sizeof(key));
    key.id = g_ddial_hub_next_key_id++;
    snprintf(key.label, sizeof(key.label), "%s", clean_label);
    security_layer_generate_salt(key.salt);
    security_layer_hash_password_strong(out_key, key.salt, key.hash);
    key.created = (int64_t)time(nullptr);
    g_ddial_hub_keys[g_ddial_hub_key_count++] = key;
    bool saved = ddial_hub_keys_save_locked();
    if (!saved) {
        --g_ddial_hub_key_count;
        --g_ddial_hub_next_key_id;
    } else if (out_id != nullptr) {
        *out_id = key.id;
    }
    return saved;
}

static bool host_ddial_hub_key_create(host_t *host, const char *label,
                                      char out_key[DDIAL_STATION_KEY_LEN + 1U],
                                      unsigned *out_id)
{
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    bool created =
        ddial_hub_key_create_locked(host, label, out_key, out_id);
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return created;
}

/* ---- station link requests ---------------------------------------------- */

static void ddial_hub_requests_load_locked(host_t *host)
{
    if (g_ddial_hub_requests_loaded || host == nullptr) {
        return;
    }
    g_ddial_hub_requests_loaded = true;

    const char *root =
        host->user_data_root[0] != '\0' ? host->user_data_root : ".";
    const char *override = getenv("CHATTER_DDIAL_MEMBERS_DIR");
    if (override != nullptr && override[0] != '\0') {
        root = override;
    }
    snprintf(g_ddial_hub_request_path, sizeof(g_ddial_hub_request_path),
             "%s/ddial_station_requests.dat", root);

    FILE *fp = fopen(g_ddial_hub_request_path, "r");
    if (fp == nullptr) {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp) != nullptr &&
           g_ddial_hub_request_count < DDIAL_HUB_MAX_REQUESTS) {
        line[strcspn(line, "\r\n")] = '\0';
        unsigned next_id = 0U;
        if (sscanf(line, "# next_id %u", &next_id) == 1) {
            if (next_id > g_ddial_hub_next_request_id) {
                g_ddial_hub_next_request_id = next_id;
            }
            continue;
        }
        char *fields[5] = {nullptr};
        char *save = nullptr;
        size_t count = 0U;
        for (char *tok = strtok_r(line, "\t", &save);
             tok != nullptr && count < 5U;
             tok = strtok_r(nullptr, "\t", &save)) {
            fields[count++] = tok;
        }
        if (count < 5U) {
            continue;
        }
        ddial_hub_request_t request;
        memset(&request, 0, sizeof(request));
        request.id = (unsigned)strtoul(fields[0], nullptr, 10);
        if (request.id == 0U ||
            ddial_sanitize_handle(fields[1], strlen(fields[1]), request.name,
                                  sizeof(request.name)) == 0U ||
            fields[2][0] == '\0') {
            continue;
        }
        snprintf(request.ip, sizeof(request.ip), "%s", fields[2]);
        request.created = strtoll(fields[3], nullptr, 10);
        request.last_seen = strtoll(fields[4], nullptr, 10);
        g_ddial_hub_requests[g_ddial_hub_request_count++] = request;
        if (request.id >= g_ddial_hub_next_request_id) {
            g_ddial_hub_next_request_id = request.id + 1U;
        }
    }
    fclose(fp);
}

static bool ddial_hub_requests_save_locked(void)
{
    if (g_ddial_hub_request_path[0] == '\0') {
        return false;
    }
    char temp_path[PATH_MAX];
    int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp",
                           g_ddial_hub_request_path);
    if (written < 0 || (size_t)written >= sizeof(temp_path)) {
        return false;
    }
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    FILE *fp = fdopen(fd, "w");
    if (fp == nullptr) {
        close(fd);
        unlink(temp_path);
        return false;
    }
    bool ok = fprintf(fp, "# next_id %u\n", g_ddial_hub_next_request_id) > 0;
    for (size_t i = 0U; i < g_ddial_hub_request_count && ok; ++i) {
        const ddial_hub_request_t *request = &g_ddial_hub_requests[i];
        ok = fprintf(fp, "%u\t%s\t%s\t%lld\t%lld\n", request->id, request->name,
                     request->ip, (long long)request->created,
                     (long long)request->last_seen) > 0;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        ok = false;
    }
    if (fclose(fp) != 0) {
        ok = false;
    }
    if (!ok || rename(temp_path, g_ddial_hub_request_path) != 0) {
        unlink(temp_path);
        return false;
    }
    return true;
}

static bool host_ddial_hub_request_register(host_t *host, const char *name,
                                            const char *ip, unsigned *out_id)
{
    if (host == nullptr || name == nullptr) {
        return false;
    }
    char clean_name[DDIAL_MAX_HANDLE_LEN];
    snprintf(clean_name, sizeof(clean_name), "%s", name);
    for (char *p = clean_name; *p != '\0'; ++p) {
        if (*p == '\t' || *p == '\r' || *p == '\n') {
            *p = ' ';
        }
    }
    trim_whitespace_inplace(clean_name);
    char sanitized[DDIAL_MAX_HANDLE_LEN];
    if (ddial_sanitize_handle(clean_name, strlen(clean_name), sanitized,
                              sizeof(sanitized)) == 0U) {
        return false;
    }

    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_requests_load_locked(host);
    int64_t now = (int64_t)time(nullptr);
    for (size_t i = 0U; i < g_ddial_hub_request_count; ++i) {
        ddial_hub_request_t *request = &g_ddial_hub_requests[i];
        if (strcmp(request->ip, ip != nullptr ? ip : "") == 0 &&
            ddial_handles_equal(request->name, sanitized)) {
            if (out_id != nullptr) {
                *out_id = request->id;
            }
            bool saved = true;
            if (now - request->last_seen >= DDIAL_HUB_REQUEST_REFRESH_SEC) {
                int64_t previous = request->last_seen;
                request->last_seen = now;
                saved = ddial_hub_requests_save_locked();
                if (!saved) {
                    request->last_seen = previous;
                }
            }
            pthread_mutex_unlock(&g_ddial_hub_key_lock);
            return saved;
        }
    }
    if (g_ddial_hub_request_count >= DDIAL_HUB_MAX_REQUESTS) {
        pthread_mutex_unlock(&g_ddial_hub_key_lock);
        return false;
    }

    ddial_hub_request_t request;
    memset(&request, 0, sizeof(request));
    request.id = g_ddial_hub_next_request_id++;
    snprintf(request.name, sizeof(request.name), "%s", sanitized);
    snprintf(request.ip, sizeof(request.ip), "%s", ip != nullptr ? ip : "");
    request.created = now;
    request.last_seen = now;
    g_ddial_hub_requests[g_ddial_hub_request_count++] = request;
    bool saved = ddial_hub_requests_save_locked();
    if (!saved) {
        --g_ddial_hub_request_count;
        --g_ddial_hub_next_request_id;
    } else if (out_id != nullptr) {
        *out_id = request.id;
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return saved;
}

static size_t host_ddial_hub_request_list(host_t *host, char *out, size_t cap)
{
    if (out == nullptr || cap == 0U) {
        return 0U;
    }
    out[0] = '\0';
    size_t used = 0U;
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_requests_load_locked(host);
    size_t count = g_ddial_hub_request_count;
    for (size_t i = 0U; i < count && used + 1U < cap; ++i) {
        const ddial_hub_request_t *request = &g_ddial_hub_requests[i];
        int n = snprintf(out + used, cap - used, "%s#%u %s [%s]",
                         used > 0U ? "\n" : "", request->id, request->name,
                         request->ip);
        if (n < 0 || (size_t)n >= cap - used) {
            break;
        }
        used += (size_t)n;
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return count;
}

static size_t ddial_hub_request_find_locked(unsigned id)
{
    for (size_t i = 0U; i < g_ddial_hub_request_count; ++i) {
        if (g_ddial_hub_requests[i].id == id) {
            return i;
        }
    }
    return g_ddial_hub_request_count;
}

static void ddial_hub_request_restore_locked(size_t idx,
                                             const ddial_hub_request_t *request)
{
    memmove(&g_ddial_hub_requests[idx + 1U], &g_ddial_hub_requests[idx],
            (g_ddial_hub_request_count - idx) *
                sizeof(g_ddial_hub_requests[0]));
    g_ddial_hub_requests[idx] = *request;
    ++g_ddial_hub_request_count;
}

static ddial_hub_request_result_t
host_ddial_hub_request_deny(host_t *host, unsigned id)
{
    if (host == nullptr) {
        return DDIAL_HUB_REQUEST_ERROR;
    }
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_requests_load_locked(host);
    size_t idx = ddial_hub_request_find_locked(id);
    if (idx == g_ddial_hub_request_count) {
        pthread_mutex_unlock(&g_ddial_hub_key_lock);
        return DDIAL_HUB_REQUEST_NOT_FOUND;
    }
    ddial_hub_request_t request = g_ddial_hub_requests[idx];
    memmove(&g_ddial_hub_requests[idx], &g_ddial_hub_requests[idx + 1U],
            (g_ddial_hub_request_count - idx - 1U) *
                sizeof(g_ddial_hub_requests[0]));
    --g_ddial_hub_request_count;
    bool saved = ddial_hub_requests_save_locked();
    if (!saved) {
        ddial_hub_request_restore_locked(idx, &request);
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return saved ? DDIAL_HUB_REQUEST_OK : DDIAL_HUB_REQUEST_ERROR;
}

static ddial_hub_request_result_t host_ddial_hub_request_approve(
    host_t *host, unsigned id, char out_name[DDIAL_MAX_HANDLE_LEN],
    char out_key[DDIAL_STATION_KEY_LEN + 1U], unsigned *out_key_id)
{
    if (host == nullptr || out_name == nullptr || out_key == nullptr) {
        return DDIAL_HUB_REQUEST_ERROR;
    }
    out_name[0] = '\0';
    out_key[0] = '\0';

    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_requests_load_locked(host);
    size_t idx = ddial_hub_request_find_locked(id);
    if (idx == g_ddial_hub_request_count) {
        pthread_mutex_unlock(&g_ddial_hub_key_lock);
        return DDIAL_HUB_REQUEST_NOT_FOUND;
    }
    ddial_hub_request_t request = g_ddial_hub_requests[idx];
    if (!ddial_hub_key_create_locked(host, request.name, out_key, out_key_id)) {
        pthread_mutex_unlock(&g_ddial_hub_key_lock);
        return DDIAL_HUB_REQUEST_ERROR;
    }

    memmove(&g_ddial_hub_requests[idx], &g_ddial_hub_requests[idx + 1U],
            (g_ddial_hub_request_count - idx - 1U) *
                sizeof(g_ddial_hub_requests[0]));
    --g_ddial_hub_request_count;
    if (!ddial_hub_requests_save_locked()) {
        ddial_hub_request_restore_locked(idx, &request);
        --g_ddial_hub_key_count;
        --g_ddial_hub_next_key_id;
        if (!ddial_hub_keys_save_locked()) {
            printf("[ddial-hub] failed to roll back approved station key\n");
        }
        memset(out_key, 0, DDIAL_STATION_KEY_LEN + 1U);
        pthread_mutex_unlock(&g_ddial_hub_key_lock);
        return DDIAL_HUB_REQUEST_ERROR;
    }
    snprintf(out_name, DDIAL_MAX_HANDLE_LEN, "%s", request.name);
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return DDIAL_HUB_REQUEST_OK;
}

/* Id of the key matching candidate, or 0. Every key is checked so the time
 * taken does not reveal which one matched. */
static unsigned ddial_hub_key_match(host_t *host, const char *candidate,
                                    char *label, size_t label_cap)
{
    if (!ddial_station_key_is_wellformed(candidate)) {
        return 0U;
    }
    unsigned matched = 0U;
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_keys_load_locked(host);
    for (size_t i = 0U; i < g_ddial_hub_key_count; ++i) {
        ddial_hub_key_t *key = &g_ddial_hub_keys[i];
        uint8_t computed[SECURITY_LAYER_HASH_LEN];
        security_layer_hash_password_strong(candidate, key->salt, computed);
        if (CRYPTO_memcmp(computed, key->hash, sizeof(computed)) == 0 &&
            matched == 0U) {
            matched = key->id;
            key->last_used = (int64_t)time(nullptr);
            if (label != nullptr && label_cap > 0U) {
                snprintf(label, label_cap, "%s", key->label);
            }
        }
    }
    if (matched != 0U) {
        (void)ddial_hub_keys_save_locked();
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return matched;
}

static size_t host_ddial_hub_key_list(host_t *host, char *out, size_t cap)
{
    if (out == nullptr || cap == 0U) {
        return 0U;
    }
    out[0] = '\0';
    size_t used = 0U;
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_keys_load_locked(host);
    size_t count = g_ddial_hub_key_count;
    for (size_t i = 0U; i < count && used + 1U < cap; ++i) {
        const ddial_hub_key_t *key = &g_ddial_hub_keys[i];
        char created[32] = "-";
        char last[32] = "never";
        time_t t = (time_t)key->created;
        struct tm tm_buf;
        if (key->created > 0 && gmtime_r(&t, &tm_buf) != nullptr) {
            strftime(created, sizeof(created), "%Y-%m-%d", &tm_buf);
        }
        t = (time_t)key->last_used;
        if (key->last_used > 0 && gmtime_r(&t, &tm_buf) != nullptr) {
            strftime(last, sizeof(last), "%Y-%m-%d %H:%M", &tm_buf);
        }
        int n = snprintf(out + used, cap - used,
                         "%s#%u %s (created %s, last used %s)",
                         used > 0U ? "\n" : "", key->id, key->label, created,
                         last);
        if (n < 0 || (size_t)n >= cap - used) {
            break;
        }
        used += (size_t)n;
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return count;
}

static bool host_ddial_hub_key_revoke(host_t *host, unsigned id)
{
    bool removed = false;
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_keys_load_locked(host);
    for (size_t i = 0U; i < g_ddial_hub_key_count; ++i) {
        if (g_ddial_hub_keys[i].id == id) {
            memmove(&g_ddial_hub_keys[i], &g_ddial_hub_keys[i + 1U],
                    (g_ddial_hub_key_count - i - 1U) *
                        sizeof(g_ddial_hub_keys[0]));
            --g_ddial_hub_key_count;
            removed = ddial_hub_keys_save_locked();
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    if (removed) {
        /* A revoked key no longer holds a link open. */
        pthread_mutex_lock(&g_ddial_hub_lock);
        for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
             st = st->next) {
            if (st->key_id == id) {
                st->closing = true;
                shutdown(st->fd, SHUT_RDWR);
            }
        }
        pthread_mutex_unlock(&g_ddial_hub_lock);
    }
    return removed;
}

/* ---- failed-login guard ------------------------------------------------- */

static bool ddial_hub_ip_blocked(const char *ip)
{
    bool blocked = false;
    time_t now = time(nullptr);
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    for (size_t i = 0U; i < DDIAL_HUB_FAIL_TRACK; ++i) {
        ddial_hub_failure_t *f = &g_ddial_hub_failures[i];
        if (f->ip[0] != '\0' && strcmp(f->ip, ip) == 0) {
            if (now - f->first > DDIAL_HUB_FAIL_WINDOW_SEC) {
                memset(f, 0, sizeof(*f));
            } else {
                blocked = f->count >= DDIAL_HUB_FAIL_LIMIT;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
    return blocked;
}

static void ddial_hub_note_failure(const char *ip)
{
    time_t now = time(nullptr);
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    ddial_hub_failure_t *slot = nullptr;
    ddial_hub_failure_t *oldest = &g_ddial_hub_failures[0];
    for (size_t i = 0U; i < DDIAL_HUB_FAIL_TRACK; ++i) {
        ddial_hub_failure_t *f = &g_ddial_hub_failures[i];
        if (f->ip[0] != '\0' && strcmp(f->ip, ip) == 0) {
            slot = f;
            break;
        }
        if (f->ip[0] == '\0' || f->first < oldest->first) {
            oldest = f;
        }
    }
    if (slot == nullptr) {
        slot = oldest;
        memset(slot, 0, sizeof(*slot));
        snprintf(slot->ip, sizeof(slot->ip), "%s", ip);
        slot->first = now;
    } else if (now - slot->first > DDIAL_HUB_FAIL_WINDOW_SEC) {
        slot->count = 0U;
        slot->first = now;
    }
    ++slot->count;
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
}

static void ddial_hub_clear_failures(const char *ip)
{
    pthread_mutex_lock(&g_ddial_hub_key_lock);
    for (size_t i = 0U; i < DDIAL_HUB_FAIL_TRACK; ++i) {
        if (strcmp(g_ddial_hub_failures[i].ip, ip) == 0) {
            memset(&g_ddial_hub_failures[i], 0,
                   sizeof(g_ddial_hub_failures[i]));
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_key_lock);
}

/* ---- station registry and output --------------------------------------- */

/* Called by the slot allocator in integration.c, which holds
 * g_ddial_registry_lock (lock order: registry, then hub). */
static bool ddial_hub_slot_in_use(uint16_t slot)
{
    bool used = false;
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        if (st->slot == slot) {
            used = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    return used;
}

static void ddial_hub_station_write(ddial_hub_station_t *st, const char *data,
                                    size_t len)
{
    if (st == nullptr || st->fd < 0 || st->closing || len == 0U) {
        return;
    }
    pthread_mutex_lock(&st->out_lock);
    size_t sent = 0U;
    while (sent < len) {
        ssize_t n = send(st->fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            /* SO_SNDTIMEO expired or the peer went away: drop the link
             * rather than stall everyone else's traffic. */
            st->closing = true;
            break;
        }
        sent += (size_t)n;
    }
    pthread_mutex_unlock(&st->out_lock);
}

/* Send one wire line (with CR/LF) to every linked station except the one on
 * exclude_slot (0 = none). */
static void ddial_hub_broadcast(host_t *host, const char *wire,
                                uint16_t exclude_slot)
{
    if (host == nullptr || wire == nullptr || wire[0] == '\0') {
        return;
    }
    size_t len = strlen(wire);
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        if (st->host == host && st->slot != exclude_slot) {
            ddial_hub_station_write(st, wire, len);
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
}

static bool ddial_hub_has_stations(host_t *host)
{
    bool any = false;
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        if (st->host == host) {
            any = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    return any;
}

static size_t ddial_client_normalize_outbound_text(const char *src,
                                                   size_t src_len, char *dst,
                                                   size_t dst_cap);

/* Public chat said on this station (by a Chatter member, a dial-in or an AI
 * member) goes to the linked stations in link form. */
static void ddial_hub_send_chat(host_t *host, uint16_t from_slot,
                                const char *handle, uint8_t channel,
                                const char *message)
{
    if (host == nullptr || handle == nullptr || handle[0] == '\0' ||
        message == nullptr || !ddial_hub_has_stations(host)) {
        return;
    }
    char clean_msg[SSH_CHATTER_MESSAGE_LIMIT];
    if (ddial_client_normalize_outbound_text(message, strlen(message),
                                             clean_msg,
                                             sizeof(clean_msg)) == 0U) {
        return;
    }
    if (channel < DDIAL_MIN_CHANNEL || channel > DDIAL_MAX_CHANNEL) {
        channel = DDIAL_DEFAULT_CHANNEL;
    }
    char wire[SSH_CHATTER_MESSAGE_LIMIT + 64];
    bool formatted =
        channel == DDIAL_DEFAULT_CHANNEL
            ? ddial_format_link_chat(wire, sizeof(wire), from_slot, channel,
                                     DDIAL_TIER_PASSWORD, handle, clean_msg)
            : ddial_format_link_dual_chat(wire, sizeof(wire), from_slot,
                                          channel, DDIAL_TIER_PASSWORD, handle,
                                          clean_msg);
    if (formatted) {
        ddial_hub_broadcast(host, wire, 0U);
    }
}

/* Login/logout of a user on this station. */
static void ddial_hub_send_event(host_t *host, uint16_t slot, uint8_t channel,
                                 ddial_user_tier_t tier, const char *handle,
                                 uint16_t account, bool is_login)
{
    if (host == nullptr || handle == nullptr || handle[0] == '\0' ||
        !ddial_hub_has_stations(host)) {
        return;
    }
    char wire[SSH_CHATTER_MESSAGE_LIMIT + 64];
    bool formatted =
        is_login ? ddial_format_link_login(wire, sizeof(wire), slot, channel,
                                           tier, handle, account, false, false)
                 : ddial_format_link_logout(wire, sizeof(wire), slot, channel,
                                            tier, handle, account, false,
                                            false);
    if (formatted) {
        ddial_hub_broadcast(host, wire, 0U);
    }
}

/* Chat relayed down from our own upstream hub ("71#4[T1:X) msg") is passed
 * on as it is: the link line in front already says where it came from. */
static void ddial_hub_forward_upstream_line(host_t *host, const char *line)
{
    if (host == nullptr || line == nullptr ||
        !ddial_parse_incoming_chat(line, nullptr, nullptr, nullptr, nullptr,
                                   nullptr, nullptr, 0U, nullptr) ||
        !ddial_hub_has_stations(host)) {
        return;
    }
    char wire[SSH_CHATTER_MESSAGE_LIMIT + 4];
    int n = snprintf(wire, sizeof(wire), "%s\r\n", line);
    if (n > 0 && (size_t)n < sizeof(wire)) {
        ddial_hub_broadcast(host, wire, 0U);
    }
}

static size_t host_ddial_build_station_broadcast(host_t *host, char *list,
                                                 size_t cap);

static void ddial_hub_send_user_list(ddial_hub_station_t *st)
{
    char list[SSH_CHATTER_MESSAGE_LIMIT];
    size_t len = host_ddial_build_station_broadcast(st->host, list,
                                                    sizeof(list));
    if (len > 0U) {
        ddial_hub_station_write(st, list, len);
    }
    st->last_list_sent = time(nullptr);
}

/* ---- inbound traffic from a station ------------------------------------ */

static void ddial_client_normalize_line(const char *src, char *dst,
                                        size_t dst_cap);
static void ddial_roster_note_line(const char *line);
static void host_ddial_mail_link_inbound(host_t *host, unsigned from_station,
                                         unsigned to_id,
                                         const char *from_handle,
                                         const char *text);

/* Put the station's link line in front of its chat line:
 * "#4[T1:Bob) hi" -> "60#4[T1:Bob) hi", "~#4[T2:..." -> "~60#4[T2:...". */
static bool ddial_hub_prefix_chat(uint16_t station_slot, const char *line,
                                  char *dst, size_t cap)
{
    const char *p = line;
    bool dual = false;
    if (*p == (char)DDIAL_LINK_ESCAPE) {
        dual = true;
        ++p;
    }
    if (*p != '#') {
        return false;
    }
    int n = snprintf(dst, cap, "%s%u%s", dual ? "~" : "",
                     (unsigned)station_slot, p);
    return n > 0 && (size_t)n < cap;
}

static void ddial_hub_handle_line(ddial_hub_station_t *st, const char *raw)
{
    host_t *host = st->host;
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    ddial_client_normalize_line(raw, line, sizeof(line));
    if (line[0] == '\0') {
        return;
    }

    if (line[0] == '/' && (line[1] == 'H' || line[1] == 'h') &&
        line[2] != '\0') {
        char name[DDIAL_MAX_HANDLE_LEN];
        if (ddial_sanitize_handle(line + 2, strlen(line + 2), name,
                                  sizeof(name)) > 0U) {
            pthread_mutex_lock(&g_ddial_hub_lock);
            snprintf(st->name, sizeof(st->name), "%s", name);
            pthread_mutex_unlock(&g_ddial_hub_lock);
            printf("[ddial-hub] station on line %u is '%s'\n",
                   (unsigned)st->slot, name);
        }
        return;
    }
    if ((line[0] == '/' && (line[1] == 'Q' || line[1] == 'q') &&
         line[2] == '\0')) {
        st->closing = true;
        return;
    }

    unsigned mail_station = 0U;
    unsigned mail_to = 0U;
    char mail_handle[DDIAL_MAX_HANDLE_LEN];
    const char *mail_text = nullptr;
    if (ddial_parse_incoming_email(line, &mail_station, &mail_to, nullptr,
                                   mail_handle, sizeof(mail_handle),
                                   &mail_text)) {
        host_ddial_mail_link_inbound(host, st->slot, mail_to, mail_handle,
                                     mail_text);
        return;
    }

    uint16_t pm_target = 0U;
    uint16_t pm_from = 0U;
    uint8_t pm_channel = DDIAL_DEFAULT_CHANNEL;
    char pm_handle[DDIAL_MAX_HANDLE_LEN];
    const char *pm_msg = nullptr;
    if (ddial_parse_incoming_private(line, &pm_target, &pm_from, &pm_channel,
                                     pm_handle, sizeof(pm_handle), &pm_msg)) {
        host_ddial_deliver_link_private(host, pm_target, pm_from, pm_channel,
                                        pm_handle, pm_msg);
        return;
    }

    /* Events and user lists ("[LINK] ...", "[SYSOP] ...") number lines on
     * the sending station, not here; they are not replayed. */
    char prefixed[SSH_CHATTER_MESSAGE_LIMIT + 16];
    if (!ddial_hub_prefix_chat(st->slot, line, prefixed, sizeof(prefixed))) {
        return;
    }
    char handle[DDIAL_MAX_HANDLE_LEN];
    const char *body = nullptr;
    bool is_link = false;
    if (!ddial_parse_incoming_chat(prefixed, nullptr, nullptr, nullptr,
                                   &is_link, nullptr, handle, sizeof(handle),
                                   &body) ||
        is_link || handle[0] == '\0' || body == nullptr || body[0] == '\0') {
        return;
    }
    /* A name that is on this station already is an echo, not new chat. */
    if (host_ddial_handle_is_local(host, handle, true)) {
        return;
    }

    ddial_roster_note_line(prefixed);
    host_ddial_relay_upstream_line(host, prefixed);

    char wire[SSH_CHATTER_MESSAGE_LIMIT + 32];
    int n = snprintf(wire, sizeof(wire), "%s\r\n", prefixed);
    if (n > 0 && (size_t)n < sizeof(wire)) {
        ddial_hub_broadcast(host, wire, st->slot);
    }

    chat_history_entry_t stored = {0};
    if (host_history_record_system(host, prefixed, &stored)) {
        chat_room_broadcast_entry(&host->room, &stored, nullptr);
    }
    host_ai_route_public(host, handle, body);
}

/* ---- per-station thread ------------------------------------------------- */

static void ddial_hub_write_text(int fd, const char *text)
{
    size_t len = strlen(text);
    size_t sent = 0U;
    while (sent < len) {
        ssize_t n = send(fd, text + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return;
        }
        sent += (size_t)n;
    }
}

/* Read one line during login (telnet negotiation filtered out).  Returns
 * false on timeout or hang-up. */
static bool ddial_hub_read_login_line(int fd, char *out, size_t cap)
{
    size_t len = 0U;
    time_t start = time(nullptr);
    while (time(nullptr) - start < DDIAL_HUB_LOGIN_TIMEOUT_SEC) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pfd, 1, DDIAL_HUB_POLL_MS);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        if (rc < 0 || (rc > 0 && (pfd.revents & (POLLERR | POLLHUP)) != 0 &&
                       (pfd.revents & POLLIN) == 0)) {
            return false;
        }
        if (rc == 0) {
            continue;
        }
        char chunk[256];
        ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) {
            return false;
        }
        char filtered[256];
        size_t flen =
            ddial_filter_telnet_iac(chunk, (size_t)n, filtered, sizeof(filtered));
        for (size_t i = 0U; i < flen; ++i) {
            char c = filtered[i];
            if (c == '\r' || c == '\n') {
                if (len == 0U && c == '\n') {
                    continue; /* LF after the CR of a previous line */
                }
                out[len] = '\0';
                return true;
            }
            if ((unsigned char)c >= 0x20U && len + 1U < cap) {
                out[len++] = c;
            }
        }
    }
    return false;
}

static void ddial_hub_station_name(char *dst, size_t cap)
{
    const char *env = getenv("CHATTER_DDIAL_STATION");
    if (env != nullptr && env[0] != '\0') {
        ddial_sanitize_handle(env, strlen(env), dst, cap);
    } else {
        snprintf(dst, cap, "%s", "Chatter");
    }
}

/* Reserve a link line and add the station to the registry. */
static bool ddial_hub_register(ddial_hub_station_t *st)
{
    bool ok = false;
    pthread_mutex_lock(&g_ddial_registry_lock);
    pthread_mutex_lock(&g_ddial_hub_lock);
    size_t count = 0U;
    for (ddial_hub_station_t *cur = g_ddial_hub_stations; cur != nullptr;
         cur = cur->next) {
        ++count;
    }
    if (count < DDIAL_HUB_MAX_STATIONS) {
        for (uint16_t candidate = DDIAL_HUB_FIRST_SLOT; candidate < 9999U;
             ++candidate) {
            if (!ddial_slot_is_valid(candidate)) {
                continue;
            }
            bool used = false;
            for (ddial_hub_station_t *cur = g_ddial_hub_stations;
                 cur != nullptr && !used; cur = cur->next) {
                used = cur->slot == candidate;
            }
            for (ddial_session_registry_node_t *cur = g_ddial_sessions;
                 cur != nullptr && !used; cur = cur->next) {
                used = cur->session != nullptr &&
                       cur->session->slot == candidate;
            }
            for (ddial_chat_link_entry_t *cur = g_ddial_chat_links;
                 cur != nullptr && !used; cur = cur->next) {
                used = cur->slot == candidate;
            }
            if (!used) {
                st->slot = candidate;
                st->next = g_ddial_hub_stations;
                g_ddial_hub_stations = st;
                ok = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    pthread_mutex_unlock(&g_ddial_registry_lock);
    return ok;
}

static void ddial_hub_unregister(ddial_hub_station_t *st)
{
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t **pp = &g_ddial_hub_stations; *pp != nullptr;
         pp = &(*pp)->next) {
        if (*pp == st) {
            *pp = st->next;
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
}

static bool ddial_hub_key_in_use(unsigned key_id)
{
    bool used = false;
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        if (st->key_id == key_id && !st->closing) {
            used = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    return used;
}

static void ddial_hub_process_input(ddial_hub_station_t *st)
{
    for (;;) {
        char *eol = memchr(st->input, '\n', st->input_len);
        char *cr = memchr(st->input, '\r', st->input_len);
        if (eol == nullptr || (cr != nullptr && cr < eol)) {
            eol = cr;
        }
        if (eol == nullptr) {
            if (st->input_len == sizeof(st->input)) {
                st->input_len = 0U; /* runaway line */
            }
            return;
        }
        size_t line_len = (size_t)(eol - st->input);
        char line[DDIAL_MAX_LINE_LEN];
        size_t copy = line_len < sizeof(line) - 1U ? line_len
                                                   : sizeof(line) - 1U;
        memcpy(line, st->input, copy);
        line[copy] = '\0';
        size_t consumed = line_len + 1U;
        if (consumed < st->input_len && *eol == '\r' &&
            st->input[consumed] == '\n') {
            ++consumed;
        }
        memmove(st->input, st->input + consumed, st->input_len - consumed);
        st->input_len -= consumed;
        if (line[0] != '\0') {
            ddial_hub_handle_line(st, line);
        }
    }
}

static void *ddial_hub_station_thread(void *arg)
{
    ddial_hub_station_t *st = (ddial_hub_station_t *)arg;
    sshc_epoch_thread_enter();
    host_t *host = st->host;
    bool registered = false;

    SSHC_SAFE_BLOCK_BEGIN() {
        do {
            if (ddial_hub_ip_blocked(st->ip)) {
                ddial_hub_write_text(st->fd,
                                     "Too many failed attempts. Try later.\r\n");
                break;
            }
            ddial_hub_write_text(st->fd, "Enter Password or [RETURN]: ");
            char key[64];
            if (!ddial_hub_read_login_line(st->fd, key, sizeof(key))) {
                break;
            }
            trim_whitespace_inplace(key);
            if (strncasecmp(key, "@request:", 9U) == 0) {
                unsigned request_id = 0U;
                bool recorded = host_ddial_hub_request_register(
                    host, key + 9, st->ip, &request_id);
                memset(key, 0, sizeof(key));
                if (!recorded) {
                    ddial_hub_write_text(
                        st->fd, "\r\nCould not record station link request.\r\n");
                    break;
                }
                char response[128];
                snprintf(response, sizeof(response),
                         "\r\nStation link request #%u recorded; wait for "
                         "operator approval.\r\n",
                         request_id);
                ddial_hub_write_text(st->fd, response);
                printf("[ddial-hub] station request #%u recorded from %s\n",
                       request_id, st->ip);
                break;
            }
            char label[DDIAL_MAX_HANDLE_LEN] = "";
            unsigned key_id = ddial_hub_key_match(host, key, label,
                                                  sizeof(label));
            memset(key, 0, sizeof(key));
            if (key_id == 0U) {
                ddial_hub_note_failure(st->ip);
                printf("[ddial-hub] rejected station key from %s\n", st->ip);
                struct timespec pause = {.tv_sec = 2, .tv_nsec = 0};
                host_sleep_uninterruptible(&pause);
                ddial_hub_write_text(st->fd, "\r\nInvalid password\r\n");
                break;
            }
            if (ddial_hub_key_in_use(key_id)) {
                ddial_hub_write_text(
                    st->fd, "\r\nThat station is already linked.\r\n");
                break;
            }
            ddial_hub_clear_failures(st->ip);
            st->key_id = key_id;
            snprintf(st->name, sizeof(st->name), "%s", label);
            if (!ddial_hub_register(st)) {
                ddial_hub_write_text(st->fd,
                                     "\r\nNo free station lines.\r\n");
                break;
            }
            registered = true;

            char station[DDIAL_MAX_HANDLE_LEN];
            ddial_hub_station_name(station, sizeof(station));
            char banner[256];
            snprintf(banner, sizeof(banner),
                     "\r\nWelcome to %s station link\r\n #%u(T1:?)\r\n-->",
                     station, (unsigned)st->slot);
            ddial_hub_station_write(st, banner, strlen(banner));
            printf("[ddial-hub] station key #%u (%s) linked from %s on line "
                   "%u\n",
                   key_id, label, st->ip, (unsigned)st->slot);
            ddial_hub_send_user_list(st);

            while (!st->closing && !atomic_load(&g_ddial_hub_listener.stop) &&
                   (host->shutdown_flag == nullptr ||
                    *host->shutdown_flag == 0)) {
                struct pollfd pfd = {.fd = st->fd, .events = POLLIN};
                int rc = poll(&pfd, 1, DDIAL_HUB_POLL_MS);
                if (rc < 0 && errno == EINTR) {
                    continue;
                }
                if (rc < 0) {
                    break;
                }
                if (time(nullptr) - st->last_list_sent >=
                    (time_t)DDIAL_STATION_BROADCAST_INTERVAL_SEC) {
                    ddial_hub_send_user_list(st);
                }
                if (rc == 0) {
                    continue;
                }
                if ((pfd.revents & POLLIN) == 0) {
                    break;
                }
                char chunk[1024];
                ssize_t n = recv(st->fd, chunk, sizeof(chunk), 0);
                if (n <= 0) {
                    break;
                }
                char filtered[1024];
                size_t flen = ddial_filter_telnet_iac(chunk, (size_t)n,
                                                      filtered,
                                                      sizeof(filtered));
                size_t space = sizeof(st->input) - st->input_len;
                if (flen > space) {
                    flen = space;
                }
                memcpy(st->input + st->input_len, filtered, flen);
                st->input_len += flen;
                ddial_hub_process_input(st);
            }
        } while (false);
    } SSHC_SAFE_BLOCK_END({
        printf("[ddial-hub] SEGV/SIGBUS swallowed in station thread\n");
    });

    if (registered) {
        printf("[ddial-hub] station '%s' on line %u hung up\n", st->name,
               (unsigned)st->slot);
        ddial_hub_unregister(st);
    }
    /* Unregistered: no broadcaster can reach st any more. */
    pthread_mutex_lock(&st->out_lock);
    pthread_mutex_unlock(&st->out_lock);
    close(st->fd);
    pthread_mutex_destroy(&st->out_lock);
    sshc_gc_free(st);
    sshc_epoch_thread_exit();
    return nullptr;
}

/* ---- listener ----------------------------------------------------------- */

static int ddial_hub_open_socket(void)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    const char *bind_addr = g_ddial_hub_listener.bind_address[0] != '\0'
                                ? g_ddial_hub_listener.bind_address
                                : nullptr;
    struct addrinfo *result = nullptr;
    if (getaddrinfo(bind_addr, g_ddial_hub_listener.port, &hints, &result) !=
        0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = result; ai != nullptr && fd < 0;
         ai = ai->ai_next) {
        int candidate = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (candidate < 0) {
            continue;
        }
        int enable = 1;
        setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable));
        if (bind(candidate, ai->ai_addr, ai->ai_addrlen) != 0 ||
            listen(candidate, 8) != 0) {
            close(candidate);
            continue;
        }
        fd = candidate;
    }
    freeaddrinfo(result);
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
    }
    return fd;
}

static void *ddial_hub_listener_thread(void *arg)
{
    host_t *host = (host_t *)arg;
    sshc_epoch_thread_enter();
    pthread_detach(pthread_self());
    atomic_store(&g_ddial_hub_listener.running, true);

    SSHC_SAFE_BLOCK_BEGIN() {
        while (!atomic_load(&g_ddial_hub_listener.stop) &&
               (host->shutdown_flag == nullptr || *host->shutdown_flag == 0)) {
            if (g_ddial_hub_listener.fd < 0) {
                g_ddial_hub_listener.fd = ddial_hub_open_socket();
                if (g_ddial_hub_listener.fd < 0) {
                    printf("[ddial-hub] cannot listen on %s:%s; retrying\n",
                           g_ddial_hub_listener.bind_address[0] != '\0'
                               ? g_ddial_hub_listener.bind_address
                               : "*",
                           g_ddial_hub_listener.port);
                    struct timespec backoff = {.tv_sec = 5, .tv_nsec = 0};
                    host_sleep_uninterruptible(&backoff);
                    continue;
                }
                printf("[ddial-hub] station links accepted on %s:%s\n",
                       g_ddial_hub_listener.bind_address[0] != '\0'
                           ? g_ddial_hub_listener.bind_address
                           : "*",
                       g_ddial_hub_listener.port);
            }
            struct pollfd pfd = {.fd = g_ddial_hub_listener.fd,
                                 .events = POLLIN};
            int rc = poll(&pfd, 1, 400);
            if (rc <= 0 || (pfd.revents & POLLIN) == 0) {
                continue;
            }
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            int fd = accept(g_ddial_hub_listener.fd, (struct sockaddr *)&addr,
                            &addr_len);
            if (fd < 0) {
                continue;
            }
            host_ddial_configure_client_socket(fd);

            ddial_hub_station_t *st =
                (ddial_hub_station_t *)sshc_gc_calloc(1U, sizeof(*st));
            if (st == nullptr) {
                close(fd);
                continue;
            }
            st->host = host;
            st->fd = fd;
            st->connected_at = time(nullptr);
            pthread_mutex_init(&st->out_lock, nullptr);
            host_ddial_format_sockaddr((struct sockaddr *)&addr, addr_len,
                                       st->ip, sizeof(st->ip));
            if (st->ip[0] == '\0') {
                snprintf(st->ip, sizeof(st->ip), "%s", "unknown");
            }
            pthread_t thread;
            if (pthread_create(&thread, nullptr, ddial_hub_station_thread,
                               st) != 0) {
                close(fd);
                pthread_mutex_destroy(&st->out_lock);
                sshc_gc_free(st);
                continue;
            }
            pthread_detach(thread);
        }
    } SSHC_SAFE_BLOCK_END({
        printf("[ddial-hub] SEGV/SIGBUS swallowed in listener thread\n");
    });

    if (g_ddial_hub_listener.fd >= 0) {
        close(g_ddial_hub_listener.fd);
        g_ddial_hub_listener.fd = -1;
    }
    atomic_store(&g_ddial_hub_listener.running, false);
    sshc_epoch_thread_exit();
    return nullptr;
}

/* Start accepting station links when CHATTER_DDIAL_HUB_LISTEN is set:
 * "port" or "addr:port" ("[v6addr]:port" for IPv6). */
void host_ddial_hub_start(host_t *host)
{
    const char *spec = getenv("CHATTER_DDIAL_HUB_LISTEN");
    if (host == nullptr || spec == nullptr || spec[0] == '\0' ||
        g_ddial_hub_listener.started) {
        return;
    }
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s", spec);
    char *port = strrchr(buffer, ':');
    if (port != nullptr) {
        *port++ = '\0';
        char *addr = buffer;
        size_t alen = strlen(addr);
        if (alen >= 2U && addr[0] == '[' && addr[alen - 1U] == ']') {
            addr[alen - 1U] = '\0';
            ++addr;
        }
        snprintf(g_ddial_hub_listener.bind_address,
                 sizeof(g_ddial_hub_listener.bind_address), "%s", addr);
    } else {
        port = buffer;
    }
    char *end = nullptr;
    long value = strtol(port, &end, 10);
    if (end == port || *end != '\0' || value <= 0 || value > 65535) {
        printf("[ddial-hub] CHATTER_DDIAL_HUB_LISTEN='%s' has no valid port\n",
               spec);
        return;
    }
    snprintf(g_ddial_hub_listener.port, sizeof(g_ddial_hub_listener.port),
             "%ld", value);
    atomic_store(&g_ddial_hub_listener.stop, false);
    pthread_t thread;
    if (pthread_create(&thread, nullptr, ddial_hub_listener_thread, host) ==
        0) {
        g_ddial_hub_listener.started = true;
    }
}

void host_ddial_hub_stop(host_t *host)
{
    (void)host;
    if (!g_ddial_hub_listener.started) {
        return;
    }
    atomic_store(&g_ddial_hub_listener.stop, true);
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        st->closing = true;
        shutdown(st->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    for (int waited = 0;
         waited < 3000 && atomic_load(&g_ddial_hub_listener.running);
         waited += 10) {
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
        host_sleep_uninterruptible(&pause);
    }
    g_ddial_hub_listener.started = false;
}

/* One line per linked station, for /ddial hub. */
static size_t host_ddial_hub_status(host_t *host, char *out, size_t cap)
{
    if (out == nullptr || cap == 0U) {
        return 0U;
    }
    out[0] = '\0';
    size_t used = 0U;
    size_t count = 0U;
    time_t now = time(nullptr);
    pthread_mutex_lock(&g_ddial_hub_lock);
    for (ddial_hub_station_t *st = g_ddial_hub_stations; st != nullptr;
         st = st->next) {
        if (st->host != host) {
            continue;
        }
        ++count;
        int n = snprintf(out + used, cap - used,
                         "%sline %u: %s from %s, key #%u, up %ldm",
                         used > 0U ? "\n" : "", (unsigned)st->slot, st->name,
                         st->ip, st->key_id,
                         (long)((now - st->connected_at) / 60));
        if (n < 0 || (size_t)n >= cap - used) {
            break;
        }
        used += (size_t)n;
    }
    pthread_mutex_unlock(&g_ddial_hub_lock);
    return count;
}
