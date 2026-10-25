/**
 * @file node.c
 * @desc The FidoNet node: configuration, the poll scheduler, the tosser
 *       (inbound packets and bundles into the area message bases), the
 *       scanner (local posts into outbound packets) and an optional BinkP
 *       listener for the uplink to deliver to us.
 *
 *       Everything lives under its own directory (CHATTER_FIDO_DIR, default
 *       "fidonet" next to bbs_state.dat) and never touches the BBS state:
 *
 *         inbound/   files received over BinkP, tossed after each session
 *         outbound/  packets waiting for the next poll, one per message
 *         bad/       packets that could not be tossed
 *         areas/, dupes.dat, hidden.dat  see msgbase.c
 *         serial.dat last MSGID serial
 *
 *       The uplink is polled once inside each Zone Mail Hour of our zone
 *       (see zmh.c), retried every ten minutes within the window after a
 *       failure; CHATTER_FIDO_ZMH overrides the window and
 *       CHATTER_FIDO_POLL_MINUTES adds polling outside it.  Operators can
 *       force a poll with "/fido poll".
 *
 *       Configuration (environment):
 *         CHATTER_FIDO_ADDRESS     our address, e.g. 2:5020/1042.7 (required)
 *         CHATTER_FIDO_UPLINK      uplink address (required)
 *         CHATTER_FIDO_UPLINK_HOST host[:port] of the uplink's BinkP server
 *         CHATTER_FIDO_PASSWORD    session password (packet password uses
 *                                  its first 8 characters)
 *         CHATTER_FIDO_AREAS       comma-separated echo tags to carry
 *         CHATTER_FIDO_DIR         node directory
 *         CHATTER_FIDO_ZMH         "HH:MM-HH:MM" UTC poll window override
 *         CHATTER_FIDO_POLL_MINUTES extra poll interval, 0 = ZMH only
 *         CHATTER_FIDO_BINKP_PORT  listen for the uplink on this port
 *         CHATTER_FIDO_SYSTEM, CHATTER_FIDO_SYSOP, CHATTER_FIDO_LOCATION,
 *         CHATTER_FIDO_ORIGIN      M_NUL banner fields and the Origin line
 */

#include "ftn.h"

#include <dirent.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

#define FIDO_MAX_AREAS 64U
#define FIDO_RETRY_SECONDS 600
#define FIDO_TICK_SECONDS 5
#define FIDO_MAX_PACKET (16U * 1024U * 1024U)
#define FIDO_CONNECT_TIMEOUT_MS 20000

typedef struct host_fidonet {
    ftn_addr_t self;
    ftn_addr_t uplink;
    char uplink_host[256];
    char uplink_port[8];
    char password[64];
    char dir[PATH_MAX];
    char inbound[PATH_MAX];
    char outbound[PATH_MAX];
    char bad[PATH_MAX];
    char areas[FIDO_MAX_AREAS][FTN_AREATAG_LEN];
    size_t area_count;
    char system_name[64];
    char sysop[64];
    char location[64];
    char origin[80];
    char listen_port[8];
    ftn_zmh_t zmh;
    bool zmh_custom;
    unsigned int poll_minutes;

    pthread_mutex_t lock; /* status fields, serial, toss/scan */
    volatile bool stop;
    _Atomic bool poll_requested;
    _Atomic bool worker_running;
    _Atomic bool listener_running;
    int listen_fd;
    time_t last_attempt;
    time_t last_success;
    char last_result[192];
    size_t imported_total;
    size_t exported_pending;
} host_fidonet_t;

static void fido_log(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void fido_log(const char *format, ...)
{
    char line[512];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    printf("[fidonet] %s\n", line);
    fflush(stdout);
}

static void fido_binkp_log(void *user, const char *line)
{
    (void)user;
    fido_log("binkp: %s", line);
}

static const char *fido_env(const char *name)
{
    const char *value = getenv(name);
    return value != nullptr && value[0] != '\0' ? value : nullptr;
}

static void fido_env_copy(char *dst, size_t size, const char *name,
                          const char *fallback)
{
    const char *value = fido_env(name);
    snprintf(dst, size, "%s", value != nullptr ? value : fallback);
    ftn_text_sanitize(dst);
}

/* ------------------------------------------------------------------ */
/* Areas                                                              */
/* ------------------------------------------------------------------ */

/* Canonical (configured) spelling of an area tag, or nullptr when we do
 * not carry it.  NETMAIL is always known. */
static const char *fido_area_lookup(const host_fidonet_t *fido,
                                    const char *tag)
{
    if (tag == nullptr) {
        return nullptr;
    }
    if (strcasecmp(tag, FTN_NETMAIL_AREA) == 0) {
        return FTN_NETMAIL_AREA;
    }
    for (size_t idx = 0U; idx < fido->area_count; ++idx) {
        if (strcasecmp(fido->areas[idx], tag) == 0) {
            return fido->areas[idx];
        }
    }
    return nullptr;
}

static void fido_parse_areas(host_fidonet_t *fido, const char *list)
{
    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", list != nullptr ? list : "");
    char *save = nullptr;
    for (char *tok = strtok_r(copy, ", \t", &save);
         tok != nullptr && fido->area_count < FIDO_MAX_AREAS;
         tok = strtok_r(nullptr, ", \t", &save)) {
        if (!ftn_area_tag_valid(tok) ||
            strcasecmp(tok, FTN_NETMAIL_AREA) == 0 ||
            fido_area_lookup(fido, tok) != nullptr) {
            continue;
        }
        snprintf(fido->areas[fido->area_count], FTN_AREATAG_LEN, "%s", tok);
        ftn_area_tag_upper(fido->areas[fido->area_count]);
        ++fido->area_count;
    }
}

/* ------------------------------------------------------------------ */
/* Setup                                                              */
/* ------------------------------------------------------------------ */

static void host_fidonet_init(host_t *host)
{
    if (host == nullptr) {
        return;
    }
    host->fidonet = nullptr;
    const char *address = fido_env("CHATTER_FIDO_ADDRESS");
    const char *uplink = fido_env("CHATTER_FIDO_UPLINK");
    if (address == nullptr) {
        return;
    }
    host_fidonet_t *fido = calloc(1U, sizeof(*fido));
    if (fido == nullptr) {
        return;
    }
    if (!ftn_addr_parse(address, &fido->self) || fido->self.zone == 0U ||
        uplink == nullptr || !ftn_addr_parse(uplink, &fido->uplink) ||
        fido->uplink.zone == 0U) {
        fido_log("disabled: CHATTER_FIDO_ADDRESS and CHATTER_FIDO_UPLINK "
                 "must be full zone:net/node[.point] addresses");
        free(fido);
        return;
    }

    const char *target = fido_env("CHATTER_FIDO_UPLINK_HOST");
    if (target != nullptr) {
        char copy[300];
        snprintf(copy, sizeof(copy), "%s", target);
        char *colon = strrchr(copy, ':');
        /* host:port, keeping bare IPv6 literals ("[::1]:24554") intact */
        if (colon != nullptr && strchr(colon, ']') == nullptr &&
            (strchr(copy, ':') == colon || copy[0] == '[')) {
            *colon = '\0';
            snprintf(fido->uplink_port, sizeof(fido->uplink_port), "%s",
                     colon + 1);
        }
        char *host_part = copy;
        if (host_part[0] == '[') {
            ++host_part;
            char *close = strchr(host_part, ']');
            if (close != nullptr) {
                *close = '\0';
            }
        }
        snprintf(fido->uplink_host, sizeof(fido->uplink_host), "%s",
                 host_part);
    }
    if (fido->uplink_port[0] == '\0') {
        snprintf(fido->uplink_port, sizeof(fido->uplink_port), "%d",
                 BINKP_DEFAULT_PORT);
    }

    fido_env_copy(fido->password, sizeof(fido->password),
                  "CHATTER_FIDO_PASSWORD", "");
    fido_env_copy(fido->system_name, sizeof(fido->system_name),
                  "CHATTER_FIDO_SYSTEM", "SSH-Chatter");
    fido_env_copy(fido->sysop, sizeof(fido->sysop), "CHATTER_FIDO_SYSOP",
                  "Sysop");
    fido_env_copy(fido->location, sizeof(fido->location),
                  "CHATTER_FIDO_LOCATION", "Internet");
    fido_env_copy(fido->origin, sizeof(fido->origin), "CHATTER_FIDO_ORIGIN",
                  "SSH-Chatter BBS");
    fido_parse_areas(fido, fido_env("CHATTER_FIDO_AREAS"));

    fido->zmh = ftn_zmh_for_zone(fido->self.zone);
    const char *zmh = fido_env("CHATTER_FIDO_ZMH");
    if (zmh != nullptr) {
        ftn_zmh_t custom;
        if (ftn_zmh_parse(zmh, &custom)) {
            fido->zmh = custom;
            fido->zmh_custom = true;
        } else {
            fido_log("ignoring CHATTER_FIDO_ZMH=\"%s\" (want HH:MM-HH:MM)",
                     zmh);
        }
    }
    const char *minutes = fido_env("CHATTER_FIDO_POLL_MINUTES");
    if (minutes != nullptr) {
        long value = strtol(minutes, nullptr, 10);
        fido->poll_minutes =
            value > 0 && value <= 7 * 24 * 60 ? (unsigned int)value : 0U;
    }
    const char *port = fido_env("CHATTER_FIDO_BINKP_PORT");
    if (port != nullptr && strcasecmp(port, "off") != 0) {
        snprintf(fido->listen_port, sizeof(fido->listen_port), "%s", port);
    }

    const char *dir = fido_env("CHATTER_FIDO_DIR");
    if (dir != nullptr) {
        snprintf(fido->dir, sizeof(fido->dir), "%s", dir);
    } else {
        char base[PATH_MAX];
        snprintf(base, sizeof(base), "%s",
                 host->bbs_state_file_path[0] != '\0'
                     ? host->bbs_state_file_path
                     : "/var/lib/ssh-chatter/bbs_state.dat");
        char *slash = strrchr(base, '/');
        if (slash != nullptr) {
            *slash = '\0';
        } else {
            snprintf(base, sizeof(base), ".");
        }
        snprintf(fido->dir, sizeof(fido->dir), "%s/fidonet", base);
    }
    snprintf(fido->inbound, sizeof(fido->inbound), "%s/inbound", fido->dir);
    snprintf(fido->outbound, sizeof(fido->outbound), "%s/outbound",
             fido->dir);
    snprintf(fido->bad, sizeof(fido->bad), "%s/bad", fido->dir);

    pthread_mutex_init(&fido->lock, nullptr);
    fido->listen_fd = -1;
    snprintf(fido->last_result, sizeof(fido->last_result), "not polled yet");
    host->fidonet = fido;

    char self_text[FTN_ADDR_TEXT_LEN], uplink_text[FTN_ADDR_TEXT_LEN];
    char zmh_text[32];
    ftn_addr_format(&fido->self, self_text, sizeof(self_text));
    ftn_addr_format(&fido->uplink, uplink_text, sizeof(uplink_text));
    ftn_zmh_format(&fido->zmh, zmh_text, sizeof(zmh_text));
    fido_log("node %s, uplink %s (%s:%s), %zu area(s), mail hour %s%s",
             self_text, uplink_text,
             fido->uplink_host[0] != '\0' ? fido->uplink_host : "no host",
             fido->uplink_port, fido->area_count, zmh_text,
             fido->zmh_custom ? " (custom)" : "");
}

/* ------------------------------------------------------------------ */
/* Scanner: local posts to outbound packets                           */
/* ------------------------------------------------------------------ */

/* Next MSGID serial: seconds since the epoch, bumped past the last one
 * used, kept in serial.dat so restarts never repeat one.  Caller holds
 * fido->lock. */
static uint32_t fido_next_serial_locked(host_fidonet_t *fido)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/serial.dat", fido->dir);
    unsigned long last = 0UL;
    FILE *fp = fopen(path, "rb");
    if (fp != nullptr) {
        if (fscanf(fp, "%lx", &last) != 1) {
            last = 0UL;
        }
        fclose(fp);
    }
    uint32_t serial = (uint32_t)time(nullptr);
    if (serial <= (uint32_t)last) {
        serial = (uint32_t)last + 1U;
    }
    fp = ftn_fopen_private(path, "wb");
    if (fp != nullptr) {
        fprintf(fp, "%08x\n", serial);
        fclose(fp);
    }
    return serial;
}

/* Write one message as a packet in outbound/.  Caller holds fido->lock. */
static bool fido_write_packet_locked(host_fidonet_t *fido,
                                     const ftn_packed_msg_t *msg,
                                     uint32_t serial)
{
    char final_path[PATH_MAX], temp_path[PATH_MAX + 8];
    snprintf(final_path, sizeof(final_path), "%s/%08x.pkt", fido->outbound,
             serial);
    snprintf(temp_path, sizeof(temp_path), "%s/.%08x.tmp", fido->outbound,
             serial);
    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return false;
    }
    FILE *fp = fdopen(fd, "wb");
    if (fp == nullptr) {
        close(fd);
        unlink(temp_path);
        return false;
    }
    ftn_pkt_header_t header = {0};
    header.orig = fido->self;
    header.dest = fido->uplink;
    time_t now = time(nullptr);
    gmtime_r(&now, &header.created);
    snprintf(header.password, sizeof(header.password), "%.8s",
             fido->password);
    uint8_t raw[FTN_PKT_HEADER_LEN];
    ftn_pkt_header_write(raw, &header);
    const uint8_t terminator[2] = {0U, 0U};
    bool ok = fwrite(raw, sizeof(raw), 1U, fp) == 1U &&
              ftn_packed_msg_write(fp, msg) &&
              fwrite(terminator, sizeof(terminator), 1U, fp) == 1U &&
              fflush(fp) == 0 && fsync(fileno(fp)) == 0;
    ok = fclose(fp) == 0 && ok;
    if (!ok || rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        return false;
    }
    return true;
}

/*
 * Post a message from this system: store it in the area base, remember its
 * dupe key so the copy echoed back by the uplink is dropped, and queue a
 * packet for the next poll.  reply_msgid links it to the message it
 * answers.  Returns the new message number, or 0 on failure.
 */
static size_t host_fidonet_post(host_t *host, const char *area,
                                const char *from, const char *to,
                                const char *subject, const char *text,
                                const char *reply_msgid)
{
    host_fidonet_t *fido = host != nullptr ? host->fidonet : nullptr;
    if (fido == nullptr) {
        return 0U;
    }
    const char *tag = fido_area_lookup(fido, area);
    if (tag == nullptr || strcmp(tag, FTN_NETMAIL_AREA) == 0) {
        return 0U;
    }

    pthread_mutex_lock(&fido->lock);
    ftn_mkdir_p(fido->outbound);
    const uint32_t serial = fido_next_serial_locked(fido);
    const time_t now = time(nullptr);

    ftn_message_t local = {0};
    snprintf(local.area, sizeof(local.area), "%s", tag);
    ftn_header_field(local.from, FTN_NAME_LEN, from);
    ftn_header_field(local.to, FTN_NAME_LEN, to);
    ftn_header_field(local.subject, FTN_SUBJ_LEN, subject);
    ftn_msgid_make(&fido->self, serial, local.msgid, sizeof(local.msgid));
    snprintf(local.reply, sizeof(local.reply), "%s",
             reply_msgid != nullptr ? reply_msgid : "");
    ftn_addr_format(&fido->self, local.origin_addr,
                    sizeof(local.origin_addr));
    snprintf(local.charset, sizeof(local.charset), "UTF-8");
    local.written = now;
    local.imported = now;
    local.flags = FTN_MSG_FLAG_LOCAL;

    ftn_compose_t compose = {
        .area = tag,
        .msgid = local.msgid,
        .reply = local.reply,
        .text = text,
        .origin = fido->origin,
        .self = fido->self,
        .uplink = fido->uplink,
        .when = now,
    };
    size_t raw_len = 0U;
    char *raw = ftn_body_compose(&compose, &raw_len);

    ftn_packed_msg_t packed = {0};
    packed.orig_node = fido->self.node;
    packed.orig_net = fido->self.net;
    packed.dest_node = fido->uplink.node;
    packed.dest_net = fido->uplink.net;
    packed.attr = FTN_ATTR_LOCAL;
    ftn_datetime_format(now, packed.datetime);
    snprintf(packed.to, sizeof(packed.to), "%s", local.to);
    snprintf(packed.from, sizeof(packed.from), "%s", local.from);
    snprintf(packed.subject, sizeof(packed.subject), "%s", local.subject);
    packed.body = raw;
    packed.body_len = raw_len;

    /* What readers here see: the text plus the tear and Origin lines, as
     * an imported copy would show them. */
    size_t number = 0U;
    if (raw != nullptr && fido_write_packet_locked(fido, &packed, serial)) {
        ftn_message_t shown;
        if (ftn_message_from_packed(&packed, &shown)) {
            local.body = shown.body;
            if (ftn_msgbase_append(fido->dir, &local)) {
                number = ftn_msgbase_count(fido->dir, tag);
                char key[FTN_AREATAG_LEN + FTN_MSGID_LEN + 4U];
                ftn_dupe_key(&local, packed.datetime, key, sizeof(key));
                ftn_dupe_add(fido->dir, key);
                ++fido->exported_pending;
            }
            ftn_message_free(&shown);
        }
    }
    free(raw);
    pthread_mutex_unlock(&fido->lock);
    return number;
}

/* ------------------------------------------------------------------ */
/* Tosser: inbound packets to the message bases                       */
/* ------------------------------------------------------------------ */

static bool fido_name_has_suffix(const char *name, const char *suffix)
{
    size_t len = strlen(name);
    size_t slen = strlen(suffix);
    return len > slen && strcasecmp(name + len - slen, suffix) == 0;
}

/* ArcMail bundle names end in .su0-.sa9 style day codes (FTS-5005). */
static bool fido_is_bundle_name(const char *name)
{
    static const char *const kDays[] = {"su", "mo", "tu", "we",
                                        "th", "fr", "sa"};
    const char *dot = strrchr(name, '.');
    if (dot == nullptr || strlen(dot) != 4U) {
        return false;
    }
    for (size_t idx = 0U; idx < 7U; ++idx) {
        if (strncasecmp(dot + 1, kDays[idx], 2U) == 0 &&
            isalnum((unsigned char)dot[3])) {
            return true;
        }
    }
    return false;
}

static void fido_move_to_bad(host_fidonet_t *fido, const char *path,
                             const char *why)
{
    ftn_mkdir_p(fido->bad);
    const char *base = strrchr(path, '/');
    base = base != nullptr ? base + 1 : path;
    char target[PATH_MAX];
    snprintf(target, sizeof(target), "%s/%ld_%s", fido->bad,
             (long)time(nullptr), base);
    if (rename(path, target) != 0) {
        unlink(path);
    }
    fido_log("bad packet %s: %s", base, why);
}

typedef struct fido_toss_stats {
    size_t imported;
    size_t dupes;
    size_t unknown_area;
} fido_toss_stats_t;

/* Toss one packet.  Returns false when the packet as a whole is refused
 * (wrong destination, password, format), so it goes to bad/. */
static bool fido_toss_packet_locked(host_fidonet_t *fido, const char *path,
                                    fido_toss_stats_t *stats,
                                    const char **why)
{
    FILE *fp = fopen(path, "rb");
    if (fp == nullptr) {
        *why = "cannot open";
        return false;
    }
    uint8_t *data = malloc(FIDO_MAX_PACKET);
    size_t length = data != nullptr ? fread(data, 1U, FIDO_MAX_PACKET, fp)
                                    : 0U;
    fclose(fp);
    if (data == nullptr) {
        *why = "out of memory";
        return false;
    }

    ftn_pkt_header_t header;
    if (!ftn_pkt_header_read(data, length, &header)) {
        free(data);
        *why = "not a type 2 packet";
        return false;
    }
    if (header.dest.zone == 0U) {
        header.dest.zone = fido->self.zone;
    }
    if (!ftn_addr_equal(&header.dest, &fido->self)) {
        free(data);
        *why = "addressed to another node";
        return false;
    }
    if (fido->password[0] != '\0') {
        char want[FTN_PKT_PASSWORD_LEN + 1U];
        snprintf(want, sizeof(want), "%.8s", fido->password);
        if (strncasecmp(header.password, want, FTN_PKT_PASSWORD_LEN) != 0) {
            free(data);
            *why = "wrong packet password";
            return false;
        }
    }

    const time_t now = time(nullptr);
    size_t offset = FTN_PKT_HEADER_LEN;
    for (;;) {
        ftn_packed_msg_t packed;
        int rc = ftn_packed_msg_read(data, length, &offset, &packed);
        if (rc <= 0) {
            /* A truncated packet keeps the messages read so far, as
             * sbbsecho does. */
            break;
        }
        ftn_message_t msg;
        if (!ftn_message_from_packed(&packed, &msg)) {
            ftn_packed_msg_free(&packed);
            break;
        }
        const char *tag =
            msg.area[0] != '\0' ? fido_area_lookup(fido, msg.area)
                                : FTN_NETMAIL_AREA;
        if (tag == nullptr) {
            ++stats->unknown_area;
        } else {
            snprintf(msg.area, sizeof(msg.area), "%s",
                     strcmp(tag, FTN_NETMAIL_AREA) == 0 ? "" : tag);
            char key[FTN_AREATAG_LEN + FTN_MSGID_LEN + 4U];
            ftn_dupe_key(&msg, packed.datetime, key, sizeof(key));
            if (ftn_dupe_seen(fido->dir, key)) {
                ++stats->dupes;
            } else {
                msg.imported = now;
                if (ftn_msgbase_append(fido->dir, &msg)) {
                    ftn_dupe_add(fido->dir, key);
                    ++stats->imported;
                }
            }
        }
        ftn_message_free(&msg);
        ftn_packed_msg_free(&packed);
    }
    free(data);
    return true;
}

/* Unpack an ArcMail bundle (ZIP) into dir with the system unzip, without a
 * shell.  Returns false when unzip is missing or fails. */
static bool fido_unpack_bundle(const char *bundle, const char *dir)
{
    if (!ftn_mkdir_p(dir)) {
        return false;
    }
    char *const argv[] = {(char *)"unzip", (char *)"-o", (char *)"-qq",
                          (char *)"-j",    (char *)bundle, (char *)"-d",
                          (char *)dir,     nullptr};
    pid_t pid = 0;
    if (posix_spawnp(&pid, "unzip", nullptr, nullptr, argv, environ) != 0) {
        return false;
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void fido_toss_dir_locked(host_fidonet_t *fido, const char *dir,
                                 fido_toss_stats_t *stats, bool bundles)
{
    DIR *handle = opendir(dir);
    if (handle == nullptr) {
        return;
    }
    char names[256][256];
    size_t count = 0U;
    struct dirent *entry;
    while ((entry = readdir(handle)) != nullptr && count < 256U) {
        if (entry->d_name[0] == '.') {
            continue; /* partial transfers and our own temp files */
        }
        snprintf(names[count++], sizeof(names[0]), "%s", entry->d_name);
    }
    closedir(handle);
    qsort(names, count, sizeof(names[0]),
          (int (*)(const void *, const void *))strcmp);

    for (size_t idx = 0U; idx < count; ++idx) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, names[idx]);
        if (fido_name_has_suffix(names[idx], ".pkt")) {
            const char *why = nullptr;
            if (fido_toss_packet_locked(fido, path, stats, &why)) {
                unlink(path);
            } else {
                fido_move_to_bad(fido, path, why != nullptr ? why : "?");
            }
        } else if (bundles && fido_is_bundle_name(names[idx])) {
            char work[PATH_MAX];
            snprintf(work, sizeof(work), "%s/.unpack", fido->inbound);
            if (fido_unpack_bundle(path, work)) {
                fido_toss_dir_locked(fido, work, stats, false);
                unlink(path);
                rmdir(work);
            } else {
                fido_move_to_bad(fido, path, "cannot unpack bundle "
                                             "(is unzip installed?)");
            }
        }
        /* Anything else (TIC files, file echoes) is left for the sysop. */
    }
}

static void fido_toss_inbound(host_t *host)
{
    host_fidonet_t *fido = host->fidonet;
    fido_toss_stats_t stats = {0};
    pthread_mutex_lock(&fido->lock);
    fido_toss_dir_locked(fido, fido->inbound, &stats, true);
    fido->imported_total += stats.imported;
    pthread_mutex_unlock(&fido->lock);
    if (stats.imported + stats.dupes + stats.unknown_area == 0U) {
        return;
    }
    fido_log("tossed %zu new, %zu dupe(s), %zu for areas we do not carry",
             stats.imported, stats.dupes, stats.unknown_area);
    if (stats.imported > 0U) {
        char notice[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(notice, sizeof(notice),
                 "* [fidonet] %zu new message%s arrived. Type /fido to read.",
                 stats.imported, stats.imported == 1U ? "" : "s");
        host_history_record_system(host, notice, nullptr);
    }
}

/* ------------------------------------------------------------------ */
/* Polling                                                            */
/* ------------------------------------------------------------------ */

static int fido_connect(const char *hostname, const char *port)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *list = nullptr;
    if (getaddrinfo(hostname, port, &hints, &list) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo *ai = list; ai != nullptr && fd < 0;
         ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC,
                    ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int err = 0;
            socklen_t len = sizeof(err);
            rc = poll(&pfd, 1, FIDO_CONNECT_TIMEOUT_MS) == 1 &&
                         getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) ==
                             0 &&
                         err == 0
                     ? 0
                     : -1;
        }
        if (rc != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        fcntl(fd, F_SETFL, flags);
    }
    freeaddrinfo(list);
    return fd;
}

/* Collect outbound/ for a session; returns the count. */
static size_t fido_collect_outbound(host_fidonet_t *fido,
                                    ftn_binkp_file_t *files, size_t cap)
{
    DIR *dir = opendir(fido->outbound);
    if (dir == nullptr) {
        return 0U;
    }
    size_t count = 0U;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr && count < cap) {
        if (entry->d_name[0] == '.' ||
            strlen(entry->d_name) >= sizeof(files[0].name)) {
            continue;
        }
        ftn_binkp_file_t *file = &files[count];
        snprintf(file->path, sizeof(file->path), "%s/%s", fido->outbound,
                 entry->d_name);
        struct stat st;
        if (stat(file->path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        snprintf(file->name, sizeof(file->name), "%s", entry->d_name);
        file->size = (long long)st.st_size;
        file->mtime = (long long)st.st_mtime;
        ++count;
    }
    closedir(dir);
    return count;
}

static void fido_sent_file(const char *path, void *user)
{
    host_fidonet_t *fido = user;
    unlink(path);
    pthread_mutex_lock(&fido->lock);
    if (fido->exported_pending > 0U) {
        --fido->exported_pending;
    }
    pthread_mutex_unlock(&fido->lock);
}

static void fido_set_result(host_fidonet_t *fido, bool success,
                            const char *format, ...)
    __attribute__((format(printf, 3, 4)));

static void fido_set_result(host_fidonet_t *fido, bool success,
                            const char *format, ...)
{
    pthread_mutex_lock(&fido->lock);
    va_list args;
    va_start(args, format);
    vsnprintf(fido->last_result, sizeof(fido->last_result), format, args);
    va_end(args);
    if (success) {
        fido->last_success = time(nullptr);
    }
    pthread_mutex_unlock(&fido->lock);
    fido_log("poll: %s", fido->last_result);
}

/* One session with the uplink, then toss whatever arrived. */
static void host_fidonet_poll(host_t *host)
{
    host_fidonet_t *fido = host->fidonet;
    pthread_mutex_lock(&fido->lock);
    fido->last_attempt = time(nullptr);
    pthread_mutex_unlock(&fido->lock);

    if (fido->uplink_host[0] == '\0') {
        fido_set_result(fido, false,
                        "no CHATTER_FIDO_UPLINK_HOST; waiting for the uplink "
                        "to call in");
        fido_toss_inbound(host);
        return;
    }
    int fd = fido_connect(fido->uplink_host, fido->uplink_port);
    if (fd < 0) {
        fido_set_result(fido, false, "cannot connect to %s:%s",
                        fido->uplink_host, fido->uplink_port);
        return;
    }
    ftn_binkp_file_t *files = calloc(BINKP_MAX_FILES, sizeof(*files));
    if (files == nullptr) {
        close(fd);
        return;
    }
    ftn_binkp_config_t cfg = {
        .originator = true,
        .self = fido->self,
        .remote = fido->uplink,
        .password = fido->password,
        .inbound_dir = fido->inbound,
        .files = files,
        .file_count = fido_collect_outbound(fido, files, BINKP_MAX_FILES),
        .system_name = fido->system_name,
        .sysop = fido->sysop,
        .location = fido->location,
        .timeout_seconds = 120,
        .stop = &fido->stop,
        .on_sent = fido_sent_file,
        .log = fido_binkp_log,
        .user = fido,
    };
    ftn_binkp_result_t res;
    bool ok = ftn_binkp_run(fd, &cfg, &res);
    close(fd);
    free(files);
    if (ok) {
        fido_set_result(fido, true, "sent %zu, received %zu file(s)%s",
                        res.files_sent, res.files_received,
                        res.secure ? "" : " (unsecured session)");
    } else {
        fido_set_result(fido, false, "session failed: %s",
                        res.error[0] != '\0' ? res.error : "unknown error");
    }
    fido_toss_inbound(host);
}

/* Whether the scheduler should poll now. */
static bool fido_poll_due(host_fidonet_t *fido, time_t now)
{
    pthread_mutex_lock(&fido->lock);
    const time_t last_attempt = fido->last_attempt;
    const time_t last_success = fido->last_success;
    pthread_mutex_unlock(&fido->lock);

    if (fido->poll_minutes > 0U &&
        now - last_attempt >= (time_t)fido->poll_minutes * 60) {
        return true;
    }
    if (!ftn_zmh_contains(&fido->zmh, now)) {
        return false;
    }
    const time_t window = ftn_zmh_window_start(&fido->zmh, now);
    return last_success < window && now - last_attempt >= FIDO_RETRY_SECONDS;
}

static void *host_fidonet_worker(void *arg)
{
    host_t *host = arg;
    host_fidonet_t *fido = host->fidonet;
    sshc_epoch_thread_enter();
    pthread_detach(pthread_self());
    atomic_store(&fido->worker_running, true);

    /* Packets left over from before a restart. */
    fido_toss_inbound(host);
    while (!fido->stop) {
        const time_t now = time(nullptr);
        if (atomic_exchange(&fido->poll_requested, false) ||
            fido_poll_due(fido, now)) {
            host_fidonet_poll(host);
        }
        struct timespec pause = {.tv_sec = FIDO_TICK_SECONDS, .tv_nsec = 0L};
        host_sleep_uninterruptible(&pause);
    }

    atomic_store(&fido->worker_running, false);
    sshc_epoch_thread_exit();
    return nullptr;
}

/* ------------------------------------------------------------------ */
/* Listener: the uplink calling us                                    */
/* ------------------------------------------------------------------ */

static void *host_fidonet_listener(void *arg)
{
    host_t *host = arg;
    host_fidonet_t *fido = host->fidonet;
    sshc_epoch_thread_enter();
    pthread_detach(pthread_self());
    atomic_store(&fido->listener_running, true);

    while (!fido->stop) {
        struct pollfd pfd = {.fd = fido->listen_fd, .events = POLLIN};
        if (poll(&pfd, 1, 1000) <= 0) {
            continue;
        }
        int fd = accept(fido->listen_fd, nullptr, nullptr);
        if (fd < 0) {
            continue;
        }
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        /* One session at a time; the uplink is the only peer we accept. */
        ftn_binkp_file_t *files = calloc(BINKP_MAX_FILES, sizeof(*files));
        if (files != nullptr) {
            ftn_binkp_config_t cfg = {
                .originator = false,
                .self = fido->self,
                .remote = fido->uplink,
                .password = fido->password,
                .inbound_dir = fido->inbound,
                .files = files,
                .file_count =
                    fido_collect_outbound(fido, files, BINKP_MAX_FILES),
                .system_name = fido->system_name,
                .sysop = fido->sysop,
                .location = fido->location,
                .timeout_seconds = 120,
                .stop = &fido->stop,
                .on_sent = fido_sent_file,
                .log = fido_binkp_log,
                .user = fido,
            };
            ftn_binkp_result_t res;
            bool ok = ftn_binkp_run(fd, &cfg, &res);
            if (ok) {
                fido_set_result(fido, true,
                                "uplink called: sent %zu, received %zu "
                                "file(s)",
                                res.files_sent, res.files_received);
            } else {
                fido_log("incoming session from %s failed: %s",
                         res.remote_addrs[0] != '\0' ? res.remote_addrs
                                                     : "?",
                         res.error);
            }
            free(files);
        }
        close(fd);
        fido_toss_inbound(host);
    }

    close(fido->listen_fd);
    fido->listen_fd = -1;
    atomic_store(&fido->listener_running, false);
    sshc_epoch_thread_exit();
    return nullptr;
}

static int fido_listen(const char *port)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *list = nullptr;
    if (getaddrinfo(nullptr, port, &hints, &list) != 0) {
        hints.ai_family = AF_INET;
        if (getaddrinfo(nullptr, port, &hints, &list) != 0) {
            return -1;
        }
    }
    int fd = socket(list->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        int yes = 1;
        int no = 0;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (list->ai_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        }
        if (bind(fd, list->ai_addr, list->ai_addrlen) != 0 ||
            listen(fd, 4) != 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(list);
    return fd;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

static void host_fidonet_start(host_t *host)
{
    host_fidonet_t *fido = host != nullptr ? host->fidonet : nullptr;
    if (fido == nullptr) {
        return;
    }
    if (!ftn_mkdir_p(fido->inbound) || !ftn_mkdir_p(fido->outbound)) {
        fido_log("cannot create %s; node stays off", fido->dir);
        return;
    }
    pthread_t worker;
    if (pthread_create(&worker, nullptr, host_fidonet_worker, host) != 0) {
        fido_log("cannot start the poll worker");
        return;
    }
    if (fido->listen_port[0] != '\0') {
        fido->listen_fd = fido_listen(fido->listen_port);
        pthread_t listener;
        if (fido->listen_fd < 0) {
            fido_log("cannot listen on BinkP port %s", fido->listen_port);
        } else if (pthread_create(&listener, nullptr, host_fidonet_listener,
                                  host) != 0) {
            close(fido->listen_fd);
            fido->listen_fd = -1;
        } else {
            fido_log("BinkP listener on port %s", fido->listen_port);
        }
    }
}

/* Signal the threads; they are detached and the struct stays allocated
 * for the life of the process, so nothing is freed here. */
static void host_fidonet_shutdown(host_t *host)
{
    host_fidonet_t *fido = host != nullptr ? host->fidonet : nullptr;
    if (fido == nullptr) {
        return;
    }
    fido->stop = true;
    if (fido->listen_fd >= 0) {
        shutdown(fido->listen_fd, SHUT_RDWR);
    }
}

static void host_fidonet_request_poll(host_t *host)
{
    if (host != nullptr && host->fidonet != nullptr) {
        atomic_store(&host->fidonet->poll_requested, true);
    }
}
