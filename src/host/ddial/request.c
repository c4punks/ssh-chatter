/**
 * @file request.c
 * @desc One-shot outbound station requests and local request tracking.
 */

#include "ssh_chatter/ddial_protocol.h"
#include "ssh_chatter/host.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DDIAL_OUTBOUND_REQUEST_TIMEOUT_SEC 10
#define DDIAL_OUTBOUND_REQUEST_HOST_LEN 256U

typedef struct ddial_outbound_request {
    char host[DDIAL_OUTBOUND_REQUEST_HOST_LEN];
    int port;
    char name[DDIAL_MAX_HANDLE_LEN];
    unsigned remote_id;
    int64_t created;
} ddial_outbound_request_t;

typedef enum ddial_outbound_request_result {
    DDIAL_OUTBOUND_REQUEST_OK = 1,
    DDIAL_OUTBOUND_REQUEST_NOT_FOUND = 0,
    DDIAL_OUTBOUND_REQUEST_PENDING_EXISTS = 2,
    DDIAL_OUTBOUND_REQUEST_BUSY = 3,
    DDIAL_OUTBOUND_REQUEST_NETWORK_ERROR = 4,
    DDIAL_OUTBOUND_REQUEST_PROTOCOL_ERROR = 5,
    DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR = 6,
    DDIAL_OUTBOUND_REQUEST_INVALID = 7,
} ddial_outbound_request_result_t;

static pthread_mutex_t g_ddial_outbound_request_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_ddial_outbound_request_busy = false;

static bool ddial_outbound_request_path(host_t *host, char *path, size_t cap)
{
    if (host == nullptr || path == nullptr || cap == 0U) {
        return false;
    }
    const char *root =
        host->user_data_root[0] != '\0' ? host->user_data_root : ".";
    const char *override = getenv("CHATTER_DDIAL_MEMBERS_DIR");
    if (override != nullptr && override[0] != '\0') {
        root = override;
    }
    int written = snprintf(path, cap, "%s/ddial_outbound_request.dat", root);
    return written >= 0 && (size_t)written < cap;
}

static int ddial_outbound_request_load(host_t *host,
                                       ddial_outbound_request_t *out)
{
    char path[PATH_MAX];
    if (!ddial_outbound_request_path(host, path, sizeof(path))) {
        return -1;
    }
    FILE *fp = fopen(path, "r");
    if (fp == nullptr) {
        return errno == ENOENT ? 0 : -1;
    }
    char line[512];
    ddial_outbound_request_t record;
    memset(&record, 0, sizeof(record));
    bool found = false;
    bool valid = true;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
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
        if (count != 5U) {
            valid = false;
            continue;
        }
        snprintf(record.host, sizeof(record.host), "%s", fields[0]);
        record.port = (int)strtol(fields[1], nullptr, 10);
        snprintf(record.name, sizeof(record.name), "%s", fields[2]);
        record.remote_id = (unsigned)strtoul(fields[3], nullptr, 10);
        record.created = strtoll(fields[4], nullptr, 10);
        found = record.host[0] != '\0' && record.name[0] != '\0' &&
                record.port > 0 && record.port <= 65535 &&
                record.remote_id > 0U;
        valid = found;
        break;
    }
    fclose(fp);
    if (!valid) {
        return -1;
    }
    if (found && out != nullptr) {
        *out = record;
    }
    return found ? 1 : 0;
}

static bool ddial_outbound_request_save(host_t *host,
                                        const ddial_outbound_request_t *record)
{
    char path[PATH_MAX];
    if (!ddial_outbound_request_path(host, path, sizeof(path))) {
        return false;
    }
    char temp_path[PATH_MAX];
    int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);
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
    bool ok = fprintf(fp, "# outbound station request v1\n") > 0;
    if (ok && record != nullptr) {
        ok = fprintf(fp, "%s\t%d\t%s\t%u\t%lld\n", record->host, record->port,
                     record->name, record->remote_id,
                     (long long)record->created) > 0;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        ok = false;
    }
    if (fclose(fp) != 0) {
        ok = false;
    }
    if (!ok || rename(temp_path, path) != 0) {
        unlink(temp_path);
        return false;
    }
    return true;
}

static int ddial_outbound_request_connect(const char *host, int port)
{
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *addresses = nullptr;
    if (getaddrinfo(host, port_text, &hints, &addresses) != 0) {
        return -1;
    }

    int connected_fd = -1;
    for (struct addrinfo *address = addresses;
         address != nullptr && connected_fd < 0; address = address->ai_next) {
        int fd = socket(address->ai_family, address->ai_socktype,
                        address->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(fd);
            continue;
        }
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
            connected_fd = fd;
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            continue;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int ready;
        do {
            ready = poll(&pfd, 1, DDIAL_OUTBOUND_REQUEST_TIMEOUT_SEC * 1000);
        } while (ready < 0 && errno == EINTR);
        int error = 0;
        socklen_t error_len = sizeof(error);
        if (ready > 0 &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
            error == 0) {
            connected_fd = fd;
            break;
        }
        close(fd);
    }
    freeaddrinfo(addresses);
    return connected_fd;
}

static const char *ddial_outbound_request_find(const char *data, size_t len,
                                               const char *marker)
{
    size_t marker_len = strlen(marker);
    if (marker_len == 0U || len < marker_len) {
        return nullptr;
    }
    for (size_t i = 0U; i + marker_len <= len; ++i) {
        if (memcmp(data + i, marker, marker_len) == 0) {
            return data + i;
        }
    }
    return nullptr;
}

static bool ddial_outbound_request_read_until(int fd, const char *marker,
                                              char *buffer, size_t cap,
                                              size_t *out_len)
{
    size_t used = 0U;
    time_t deadline = time(nullptr) + DDIAL_OUTBOUND_REQUEST_TIMEOUT_SEC;
    while (time(nullptr) <= deadline) {
        if (ddial_outbound_request_find(buffer, used, marker) != nullptr) {
            *out_len = used;
            return true;
        }
        time_t remaining = deadline - time(nullptr);
        if (remaining < 0) {
            break;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, (int)(remaining + 1) * 1000);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready <= 0) {
            break;
        }
        if (used == cap) {
            return false;
        }
        ssize_t n = recv(fd, buffer + used, cap - used, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN ||
                      errno == EWOULDBLOCK)) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
    }
    if (ddial_outbound_request_find(buffer, used, marker) != nullptr) {
        *out_len = used;
        return true;
    }
    return false;
}

static ddial_outbound_request_result_t
host_ddial_outbound_request_submit(host_t *host, const char *remote_host,
                                   int port, const char *station_name,
                                   unsigned *out_remote_id)
{
    if (host == nullptr || remote_host == nullptr || remote_host[0] == '\0' ||
        station_name == nullptr || port <= 0 || port > 65535 ||
        strpbrk(remote_host, "\t\r\n") != nullptr) {
        return DDIAL_OUTBOUND_REQUEST_INVALID;
    }
    char clean_name[DDIAL_MAX_HANDLE_LEN];
    snprintf(clean_name, sizeof(clean_name), "%s", station_name);
    for (char *p = clean_name; *p != '\0'; ++p) {
        if (*p == '\t' || *p == '\r' || *p == '\n') {
            *p = ' ';
        }
    }
    trim_whitespace_inplace(clean_name);
    ddial_outbound_request_t record;
    memset(&record, 0, sizeof(record));
    if (ddial_sanitize_handle(clean_name, strlen(clean_name), record.name,
                              sizeof(record.name)) == 0U) {
        return DDIAL_OUTBOUND_REQUEST_INVALID;
    }

    pthread_mutex_lock(&g_ddial_outbound_request_lock);
    if (g_ddial_outbound_request_busy) {
        pthread_mutex_unlock(&g_ddial_outbound_request_lock);
        return DDIAL_OUTBOUND_REQUEST_BUSY;
    }
    int loaded = ddial_outbound_request_load(host, nullptr);
    if (loaded > 0) {
        pthread_mutex_unlock(&g_ddial_outbound_request_lock);
        return DDIAL_OUTBOUND_REQUEST_PENDING_EXISTS;
    }
    if (loaded < 0) {
        pthread_mutex_unlock(&g_ddial_outbound_request_lock);
        return DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR;
    }
    g_ddial_outbound_request_busy = true;
    pthread_mutex_unlock(&g_ddial_outbound_request_lock);

    ddial_outbound_request_result_t result =
        DDIAL_OUTBOUND_REQUEST_NETWORK_ERROR;
    unsigned remote_id = 0U;
    int fd = ddial_outbound_request_connect(remote_host, port);
    if (fd >= 0) {
        char buffer[2048];
        size_t response_len = 0U;
        if (ddial_outbound_request_read_until(fd, "Enter Password", buffer,
                                              sizeof(buffer), &response_len)) {
            char wire[96];
            int wire_len = snprintf(wire, sizeof(wire), "@request:%s\r\n",
                                    record.name);
            if (wire_len > 0 && (size_t)wire_len < sizeof(wire) &&
                ddial_client_send_all(fd, wire, (size_t)wire_len) >= 0 &&
                ddial_outbound_request_read_until(
                    fd, "Station link request #", buffer, sizeof(buffer),
                    &response_len)) {
                const char *response = ddial_outbound_request_find(
                    buffer, response_len, "Station link request #");
                char line[128];
                size_t remaining = response_len - (size_t)(response - buffer);
                size_t copy = remaining < sizeof(line) - 1U
                                  ? remaining
                                  : sizeof(line) - 1U;
                memcpy(line, response, copy);
                line[copy] = '\0';
                if (sscanf(line, "Station link request #%u recorded",
                           &remote_id) == 1 &&
                    remote_id > 0U) {
                    result = DDIAL_OUTBOUND_REQUEST_OK;
                } else {
                    result = DDIAL_OUTBOUND_REQUEST_PROTOCOL_ERROR;
                }
            } else {
                result = DDIAL_OUTBOUND_REQUEST_PROTOCOL_ERROR;
            }
        }
        close(fd);
    }

    pthread_mutex_lock(&g_ddial_outbound_request_lock);
    g_ddial_outbound_request_busy = false;
    if (result == DDIAL_OUTBOUND_REQUEST_OK) {
        snprintf(record.host, sizeof(record.host), "%s", remote_host);
        record.port = port;
        record.remote_id = remote_id;
        record.created = (int64_t)time(nullptr);
        if (!ddial_outbound_request_save(host, &record)) {
            result = DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR;
        }
    }
    pthread_mutex_unlock(&g_ddial_outbound_request_lock);
    if (remote_id > 0U && out_remote_id != nullptr) {
        *out_remote_id = remote_id;
    }
    return result;
}

static ddial_outbound_request_result_t
host_ddial_outbound_request_status(host_t *host, char *out, size_t cap)
{
    if (out == nullptr || cap == 0U) {
        return DDIAL_OUTBOUND_REQUEST_INVALID;
    }
    out[0] = '\0';
    pthread_mutex_lock(&g_ddial_outbound_request_lock);
    ddial_outbound_request_t record;
    int loaded = ddial_outbound_request_load(host, &record);
    if (loaded > 0) {
        snprintf(out, cap, "#%u %s (%s:%d)", record.remote_id, record.name,
                 record.host, record.port);
    }
    pthread_mutex_unlock(&g_ddial_outbound_request_lock);
    return loaded > 0 ? DDIAL_OUTBOUND_REQUEST_OK
                      : loaded == 0 ? DDIAL_OUTBOUND_REQUEST_NOT_FOUND
                                    : DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR;
}

static ddial_outbound_request_result_t
host_ddial_outbound_request_cancel(host_t *host)
{
    pthread_mutex_lock(&g_ddial_outbound_request_lock);
    int loaded = ddial_outbound_request_load(host, nullptr);
    ddial_outbound_request_result_t result = DDIAL_OUTBOUND_REQUEST_NOT_FOUND;
    if (loaded > 0) {
        result = ddial_outbound_request_save(host, nullptr)
                     ? DDIAL_OUTBOUND_REQUEST_OK
                     : DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR;
    } else if (loaded < 0) {
        result = DDIAL_OUTBOUND_REQUEST_STORAGE_ERROR;
    }
    pthread_mutex_unlock(&g_ddial_outbound_request_lock);
    return result;
}
