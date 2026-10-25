/**
 * @file test_fidonet.c
 * @desc Unit tests for the FidoNet node's pure parts: FTN addresses, Type 2+
 *       packets and packed messages, body kludges and charsets (ftn.c), Zone
 *       Mail Hour windows (zmh.c), the append-only message base and dupe
 *       keys (msgbase.c), and a full BinkP session between an originator and
 *       an answerer over a socketpair, with CRAM-MD5 and files both ways
 *       (binkp.c).
 */
#include "../../src/host/fidonet/ftn.c"
#include "../../src/host/fidonet/zmh.c"
#include "../../src/host/fidonet/msgbase.c"
#include "../../src/host/fidonet/binkp.c"

#include <dirent.h>
#include <pthread.h>

#include "test_harness.h"

static char g_dir[PATH_MAX];

static void rm_rf(const char *path)
{
    DIR *dir = opendir(path);
    if (dir != NULL) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
            rm_rf(child);
        }
        closedir(dir);
        rmdir(path);
    } else {
        unlink(path);
    }
}

/* ---- addresses ---- */

TEST(address_parse_and_format)
{
    ftn_addr_t a;
    char text[FTN_ADDR_TEXT_LEN];
    CHECK(ftn_addr_parse("2:5020/1042", &a));
    CHECK(a.zone == 2U && a.net == 5020U && a.node == 1042U && a.point == 0U);
    CHECK(ftn_addr_parse(" 1:153/757.12@fidonet ", &a));
    CHECK(a.zone == 1U && a.point == 12U);
    ftn_addr_format(&a, text, sizeof(text));
    CHECK_STR_EQ(text, "1:153/757.12");
    CHECK(ftn_addr_parse("153/757", &a));
    CHECK(a.zone == 0U && a.net == 153U);
    CHECK(!ftn_addr_parse("2:5020", &a));
    CHECK(!ftn_addr_parse("2:5020/1042 junk", &a));
    CHECK(!ftn_addr_parse("2:99999/1", &a));
}

/* ---- packets ---- */

TEST(packet_header_round_trip)
{
    ftn_pkt_header_t in = {0};
    ftn_addr_parse("2:5020/1042.7", &in.orig);
    ftn_addr_parse("2:5020/1042", &in.dest);
    in.created.tm_year = 126;
    in.created.tm_mon = 9;
    in.created.tm_mday = 25;
    snprintf(in.password, sizeof(in.password), "SECRET");
    uint8_t raw[FTN_PKT_HEADER_LEN];
    ftn_pkt_header_write(raw, &in);

    ftn_pkt_header_t out;
    CHECK(ftn_pkt_header_read(raw, sizeof(raw), &out));
    CHECK(ftn_addr_equal(&out.orig, &in.orig));
    CHECK(ftn_addr_equal(&out.dest, &in.dest));
    CHECK_STR_EQ(out.password, "SECRET");
    CHECK(out.created.tm_year == 126 && out.created.tm_mon == 9);
    CHECK(!ftn_pkt_header_read(raw, 20U, &out));
}

TEST(packet_type2_without_capability_word)
{
    /* A plain Type 2 header: zones only in the FTS-0001 rev 12 fields. */
    uint8_t raw[FTN_PKT_HEADER_LEN] = {0};
    ftn_put16(raw + 0, 1042U);
    ftn_put16(raw + 2, 1U);
    ftn_put16(raw + 18, 2U);
    ftn_put16(raw + 20, 5020U);
    ftn_put16(raw + 22, 5020U);
    ftn_put16(raw + 34, 2U);
    ftn_put16(raw + 36, 2U);
    ftn_pkt_header_t out;
    CHECK(ftn_pkt_header_read(raw, sizeof(raw), &out));
    CHECK(out.orig.zone == 2U && out.orig.node == 1042U &&
          out.orig.point == 0U);
}

TEST(datetime_round_trip)
{
    char text[FTN_DATETIME_LEN];
    ftn_datetime_format((time_t)1792935715, text);
    CHECK_EQ(strlen(text), 19U);
    time_t back = 0;
    CHECK(ftn_datetime_parse(text, &back));
    CHECK_EQ(back, (time_t)1792935715);
    CHECK(ftn_datetime_parse("Sun 25 Oct 26 22:41", &back));
    CHECK(!ftn_datetime_parse("garbage", &back));
}

/* Build a one-message packet in memory and read it back. */
TEST(packed_message_round_trip_with_kludges)
{
    ftn_compose_t compose = {0};
    ftn_addr_parse("2:5020/1042", &compose.self);
    ftn_addr_parse("2:5020/1", &compose.uplink);
    compose.area = "FIDOTEST";
    compose.msgid = "2:5020/1042 0000abcd";
    compose.reply = "2:5020/1 12345678";
    compose.text = "Hello\nsecond line";
    compose.origin = "Test BBS";
    compose.when = (time_t)1792935715;
    size_t body_len = 0U;
    char *body = ftn_body_compose(&compose, &body_len);
    CHECK(body != NULL);
    CHECK(strstr(body, "AREA:FIDOTEST\r") == body);
    CHECK(strstr(body, "\x01MSGID: 2:5020/1042 0000abcd\r") != NULL);
    CHECK(strstr(body, "Hello\rsecond line\r") != NULL);
    CHECK(strstr(body, " * Origin: Test BBS (2:5020/1042)\r") != NULL);
    CHECK(strstr(body, "SEEN-BY: 5020/1 1042\r") != NULL);
    CHECK(strstr(body, "\x01PATH: 5020/1042\r") != NULL);

    ftn_packed_msg_t msg = {0};
    msg.orig_node = 1042U;
    msg.orig_net = 5020U;
    msg.dest_node = 1U;
    msg.dest_net = 5020U;
    ftn_datetime_format(compose.when, msg.datetime);
    snprintf(msg.to, sizeof(msg.to), "All");
    snprintf(msg.from, sizeof(msg.from), "bob");
    snprintf(msg.subject, sizeof(msg.subject), "Hi");
    msg.body = body;
    msg.body_len = body_len;

    char *mem = NULL;
    size_t mem_len = 0U;
    FILE *fp = open_memstream(&mem, &mem_len);
    CHECK(fp != NULL);
    CHECK(ftn_packed_msg_write(fp, &msg));
    fputc(0, fp);
    fputc(0, fp);
    fclose(fp);
    free(body);

    size_t offset = 0U;
    ftn_packed_msg_t read_back;
    CHECK_EQ(ftn_packed_msg_read((uint8_t *)mem, mem_len, &offset,
                                 &read_back),
             1);
    CHECK_STR_EQ(read_back.from, "bob");
    CHECK_STR_EQ(read_back.subject, "Hi");

    ftn_message_t parsed;
    CHECK(ftn_message_from_packed(&read_back, &parsed));
    CHECK_STR_EQ(parsed.area, "FIDOTEST");
    CHECK_STR_EQ(parsed.msgid, "2:5020/1042 0000abcd");
    CHECK_STR_EQ(parsed.reply, "2:5020/1 12345678");
    CHECK_STR_EQ(parsed.origin_addr, "2:5020/1042");
    CHECK_STR_EQ(parsed.charset, "UTF-8");
    CHECK(strncmp(parsed.body, "Hello\nsecond line\n--- ", 22) == 0);
    CHECK(strstr(parsed.body, "SEEN-BY") == NULL);
    CHECK(strstr(parsed.body, "\x01") == NULL);
    CHECK_EQ(parsed.written, (time_t)1792935715);
    ftn_message_free(&parsed);
    ftn_packed_msg_free(&read_back);

    CHECK_EQ(ftn_packed_msg_read((uint8_t *)mem, mem_len, &offset,
                                 &read_back),
             0);
    free(mem);
}

TEST(point_leaves_seen_by_to_its_boss)
{
    ftn_compose_t compose = {0};
    ftn_addr_parse("2:5020/1042.5", &compose.self);
    ftn_addr_parse("2:5020/1042", &compose.uplink);
    compose.area = "FIDOTEST";
    compose.msgid = "2:5020/1042.5 00000001";
    compose.text = "x";
    compose.when = 0;
    size_t len = 0U;
    char *body = ftn_body_compose(&compose, &len);
    CHECK(body != NULL);
    CHECK(strstr(body, "SEEN-BY") == NULL);
    CHECK(strstr(body, "PATH") == NULL);
    CHECK(strstr(body, "(2:5020/1042.5)") != NULL);
    free(body);
}

TEST(cp437_body_and_control_bytes)
{
    /* No CHRS: CP437.  0x82 is e-acute; ESC sequences must not survive. */
    char raw[] = "AREA:TEST\r\x01MSGID: 1:1/1 1\rcaf\x82 \x1b[2Jok\rSEEN-BY: 1/1\r";
    ftn_packed_msg_t packed = {0};
    packed.body = raw;
    packed.body_len = strlen(raw);
    snprintf(packed.from, sizeof(packed.from), "Ren\x82");
    ftn_message_t parsed;
    CHECK(ftn_message_from_packed(&packed, &parsed));
    CHECK_STR_EQ(parsed.body, "caf\xc3\xa9 ok");
    CHECK_STR_EQ(parsed.from, "Ren\xc3\xa9");
    CHECK_STR_EQ(parsed.charset, "CP437");
    ftn_message_free(&parsed);
}

TEST(netmail_has_no_area)
{
    char raw[] = "\x01INTL 2:5020/1042 2:5020/1\rhello\r";
    ftn_packed_msg_t packed = {0};
    packed.body = raw;
    packed.body_len = strlen(raw);
    ftn_message_t parsed;
    CHECK(ftn_message_from_packed(&packed, &parsed));
    CHECK_STR_EQ(parsed.area, "");
    CHECK((parsed.flags & FTN_MSG_FLAG_NETMAIL) != 0U);
    CHECK_STR_EQ(parsed.body, "hello");
    ftn_message_free(&parsed);
}

/* ---- zone mail hour ---- */

static time_t utc(int hour, int minute)
{
    struct tm tm_utc = {.tm_year = 126, .tm_mon = 9, .tm_mday = 25,
                        .tm_hour = hour, .tm_min = minute};
    return timegm(&tm_utc);
}

TEST(zmh_per_zone)
{
    ftn_zmh_t z1 = ftn_zmh_for_zone(1U);
    ftn_zmh_t z2 = ftn_zmh_for_zone(2U);
    ftn_zmh_t z6 = ftn_zmh_for_zone(6U);
    ftn_zmh_t unknown = ftn_zmh_for_zone(7U);
    CHECK(z1.start == 9 * 60 && z1.end == 10 * 60);
    CHECK(z2.start == 2 * 60 + 30 && z2.end == 3 * 60 + 30);
    CHECK(z6.start == 20 * 60);
    CHECK(unknown.start == z1.start);
    CHECK(ftn_zmh_contains(&z2, utc(2, 30)));
    CHECK(ftn_zmh_contains(&z2, utc(3, 29)));
    CHECK(!ftn_zmh_contains(&z2, utc(3, 30)));
    CHECK(!ftn_zmh_contains(&z2, utc(2, 29)));
}

TEST(zmh_window_start_and_midnight_wrap)
{
    ftn_zmh_t z2 = ftn_zmh_for_zone(2U);
    CHECK_EQ(ftn_zmh_window_start(&z2, utc(2, 45)), utc(2, 30));
    CHECK_EQ(ftn_zmh_window_start(&z2, utc(1, 0)), utc(2, 30));
    CHECK_EQ(ftn_zmh_window_start(&z2, utc(4, 0)), utc(2, 30) + 86400);

    ftn_zmh_t wrap;
    CHECK(ftn_zmh_parse("23:30-00:30", &wrap));
    CHECK(ftn_zmh_contains(&wrap, utc(0, 10)));
    CHECK(ftn_zmh_contains(&wrap, utc(23, 45)));
    CHECK(!ftn_zmh_contains(&wrap, utc(1, 0)));
    CHECK_EQ(ftn_zmh_window_start(&wrap, utc(0, 10)), utc(23, 30) - 86400);
    CHECK(!ftn_zmh_parse("25:00-26:00", &wrap));
    CHECK(!ftn_zmh_parse("10:00-10:00", &wrap));
}

/* ---- message base ---- */

static bool collect_subjects(size_t number, const ftn_message_t *msg,
                             void *user)
{
    char *out = user;
    char line[64];
    snprintf(line, sizeof(line), "%zu:%s;", number, msg->subject);
    strcat(out, line);
    return true;
}

TEST(msgbase_append_read_and_torn_tail)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/base", g_dir);
    for (int idx = 1; idx <= 3; ++idx) {
        ftn_message_t msg = {0};
        snprintf(msg.area, sizeof(msg.area), "FIDOTEST");
        snprintf(msg.subject, sizeof(msg.subject), "s%d", idx);
        snprintf(msg.from, sizeof(msg.from), "user");
        msg.body = (char *)"body text";
        msg.written = 100 + idx;
        CHECK(ftn_msgbase_append(dir, &msg));
    }
    CHECK_EQ(ftn_msgbase_count(dir, "FIDOTEST"), 3U);

    ftn_message_t got;
    CHECK(ftn_msgbase_read(dir, "FIDOTEST", 2U, &got));
    CHECK_STR_EQ(got.subject, "s2");
    CHECK_STR_EQ(got.body, "body text");
    CHECK_EQ(got.written, (time_t)102);
    ftn_message_free(&got);
    CHECK(!ftn_msgbase_read(dir, "FIDOTEST", 4U, &got));

    /* A crash mid-append leaves a partial record: it is ignored. */
    char path[PATH_MAX];
    CHECK(ftn_msgbase_path(dir, "FIDOTEST", path, sizeof(path)));
    FILE *fp = fopen(path, "ab");
    fwrite("FTM1\x40\x00", 1U, 6U, fp);
    fclose(fp);
    char seen[256] = {0};
    CHECK_EQ(ftn_msgbase_each(dir, "FIDOTEST", false, collect_subjects, seen),
             3U);
    CHECK_STR_EQ(seen, "1:s1;2:s2;3:s3;");
}

TEST(msgbase_rejects_unsafe_area_tags)
{
    char path[PATH_MAX];
    CHECK(!ftn_msgbase_path(g_dir, "../etc", path, sizeof(path)));
    CHECK(!ftn_msgbase_path(g_dir, ".hidden", path, sizeof(path)));
    CHECK(!ftn_msgbase_path(g_dir, "", path, sizeof(path)));
    CHECK(ftn_msgbase_path(g_dir, "R50.SYSOP", path, sizeof(path)));
    CHECK(strstr(path, "/areas/r50.sysop.msgs") != NULL);
}

TEST(dupes_and_hidden)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/dupes", g_dir);
    CHECK(ftn_mkdir_p(dir));
    ftn_message_t msg = {0};
    snprintf(msg.area, sizeof(msg.area), "FIDOTEST");
    snprintf(msg.msgid, sizeof(msg.msgid), "2:5020/1 abcd");
    char key[256];
    ftn_dupe_key(&msg, "", key, sizeof(key));
    CHECK_STR_EQ(key, "FIDOTEST 2:5020/1 abcd");
    CHECK(!ftn_dupe_seen(dir, key));
    ftn_dupe_add(dir, key);
    CHECK(ftn_dupe_seen(dir, key));

    msg.msgid[0] = '\0';
    msg.body = (char *)"no msgid";
    char hashed[256];
    ftn_dupe_key(&msg, "25 Oct 26  00:00:00", hashed, sizeof(hashed));
    CHECK(strncmp(hashed, "FIDOTEST #", 10) == 0);

    CHECK(!ftn_hidden_contains(dir, "FIDOTEST", 2U));
    CHECK(ftn_hidden_set(dir, "FIDOTEST", 2U, true));
    CHECK(ftn_hidden_contains(dir, "fidotest", 2U));
    CHECK(ftn_hidden_set(dir, "FIDOTEST", 2U, false));
    CHECK(!ftn_hidden_contains(dir, "FIDOTEST", 2U));
}

/* ---- binkp ---- */

TEST(cram_md5_matches_rfc2104_vector)
{
    /* RFC 2104 test 2: key "Jefe", data "what do ya want for nothing?". */
    const char *data = "what do ya want for nothing?";
    char hex[128] = {0};
    for (size_t idx = 0U; data[idx] != '\0'; ++idx) {
        snprintf(hex + 2U * idx, 3U, "%02x", (unsigned char)data[idx]);
    }
    char out[64];
    CHECK(binkp_cram_response("Jefe", hex, out, sizeof(out)));
    CHECK_STR_EQ(out, "CRAM-MD5-750c783e6ab0b503eaa86e310a5db738");
}

TEST(binkp_safe_names)
{
    char out[64];
    CHECK(binkp_safe_name("0000abcd.pkt", out, sizeof(out)));
    CHECK_STR_EQ(out, "0000abcd.pkt");
    CHECK(binkp_safe_name("../../etc/passwd", out, sizeof(out)));
    CHECK_STR_EQ(out, "passwd");
    CHECK(binkp_safe_name("a\\x20b.su0", out, sizeof(out)));
    CHECK_STR_EQ(out, "a_b.su0");
    CHECK(!binkp_safe_name("...", out, sizeof(out)));
}

typedef struct peer {
    int fd;
    ftn_binkp_config_t cfg;
    ftn_binkp_result_t res;
    bool ok;
    size_t sent_callbacks;
} peer_t;

static void count_sent(const char *path, void *user)
{
    (void)path;
    ((peer_t *)user)->sent_callbacks++;
}

static void *run_peer(void *arg)
{
    peer_t *peer = arg;
    peer->ok = ftn_binkp_run(peer->fd, &peer->cfg, &peer->res);
    return NULL;
}

static void write_file(const char *path, size_t size, char fill)
{
    FILE *fp = fopen(path, "wb");
    for (size_t idx = 0U; idx < size; ++idx) {
        fputc(fill, fp);
    }
    fclose(fp);
}

static long long file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (long long)st.st_size : -1;
}

static void make_peers(peer_t *orig, peer_t *ans, const char *orig_pw,
                       const char *ans_pw, const char *orig_in,
                       const char *ans_in)
{
    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    memset(orig, 0, sizeof(*orig));
    memset(ans, 0, sizeof(*ans));
    orig->fd = fds[0];
    ans->fd = fds[1];
    orig->cfg.originator = true;
    ftn_addr_parse("2:5020/1042.5", &orig->cfg.self);
    ftn_addr_parse("2:5020/1042", &orig->cfg.remote);
    orig->cfg.password = orig_pw;
    orig->cfg.inbound_dir = orig_in;
    orig->cfg.timeout_seconds = 5;
    orig->cfg.on_sent = count_sent;
    orig->cfg.user = orig;
    ans->cfg.originator = false;
    ftn_addr_parse("2:5020/1042", &ans->cfg.self);
    ftn_addr_parse("2:5020/1042.5", &ans->cfg.remote);
    ans->cfg.password = ans_pw;
    ans->cfg.inbound_dir = ans_in;
    ans->cfg.timeout_seconds = 5;
    ans->cfg.on_sent = count_sent;
    ans->cfg.user = ans;
}

static void run_pair(peer_t *orig, peer_t *ans)
{
    pthread_t a, b;
    pthread_create(&a, NULL, run_peer, orig);
    pthread_create(&b, NULL, run_peer, ans);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    close(orig->fd);
    close(ans->fd);
}

TEST(binkp_session_moves_files_both_ways)
{
    char out_dir[PATH_MAX], orig_in[PATH_MAX], ans_in[PATH_MAX];
    snprintf(out_dir, sizeof(out_dir), "%s/bk-out", g_dir);
    snprintf(orig_in, sizeof(orig_in), "%s/bk-orig-in", g_dir);
    snprintf(ans_in, sizeof(ans_in), "%s/bk-ans-in", g_dir);
    CHECK(ftn_mkdir_p(out_dir) && ftn_mkdir_p(orig_in) &&
          ftn_mkdir_p(ans_in));

    /* The originator sends two packets, one bigger than a data frame. */
    ftn_binkp_file_t orig_files[2] = {0};
    snprintf(orig_files[0].path, sizeof(orig_files[0].path), "%s/a.pkt",
             out_dir);
    snprintf(orig_files[0].name, sizeof(orig_files[0].name), "a.pkt");
    write_file(orig_files[0].path, 10000U, 'a');
    orig_files[0].size = 10000;
    snprintf(orig_files[1].path, sizeof(orig_files[1].path), "%s/b.pkt",
             out_dir);
    snprintf(orig_files[1].name, sizeof(orig_files[1].name), "b.pkt");
    write_file(orig_files[1].path, 0U, 'b');
    orig_files[1].size = 0;

    /* The answerer (the uplink) has one bundle for us. */
    ftn_binkp_file_t ans_files[1] = {0};
    snprintf(ans_files[0].path, sizeof(ans_files[0].path), "%s/c.su0",
             out_dir);
    snprintf(ans_files[0].name, sizeof(ans_files[0].name), "c.su0");
    write_file(ans_files[0].path, 5000U, 'c');
    ans_files[0].size = 5000;

    peer_t orig, ans;
    make_peers(&orig, &ans, "Secret1", "Secret1", orig_in, ans_in);
    orig.cfg.files = orig_files;
    orig.cfg.file_count = 2U;
    ans.cfg.files = ans_files;
    ans.cfg.file_count = 1U;
    run_pair(&orig, &ans);

    CHECK(orig.ok);
    CHECK(ans.ok);
    CHECK(orig.res.secure && ans.res.secure);
    CHECK_EQ(orig.res.files_sent, 2U);
    CHECK_EQ(orig.res.files_received, 1U);
    CHECK_EQ(ans.res.files_sent, 1U);
    CHECK_EQ(ans.res.files_received, 2U);
    CHECK_EQ(orig.sent_callbacks, 2U);
    CHECK_STR_EQ(orig.res.remote_addrs, "2:5020/1042");

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/a.pkt", ans_in);
    CHECK_EQ(file_size(path), 10000);
    snprintf(path, sizeof(path), "%s/b.pkt", ans_in);
    CHECK_EQ(file_size(path), 0);
    snprintf(path, sizeof(path), "%s/c.su0", orig_in);
    CHECK_EQ(file_size(path), 5000);
}

TEST(binkp_wrong_password_is_refused)
{
    char in_dir[PATH_MAX];
    snprintf(in_dir, sizeof(in_dir), "%s/bk-bad-in", g_dir);
    CHECK(ftn_mkdir_p(in_dir));
    peer_t orig, ans;
    make_peers(&orig, &ans, "wrong", "Secret1", in_dir, in_dir);
    run_pair(&orig, &ans);
    CHECK(!orig.ok);
    CHECK(!ans.ok);
    CHECK(!ans.res.authenticated);
    CHECK(strstr(ans.res.error, "bad password") != NULL);
}

TEST(binkp_unsecured_session_sends_nothing)
{
    char in_dir[PATH_MAX], out_dir[PATH_MAX];
    snprintf(in_dir, sizeof(in_dir), "%s/bk-open-in", g_dir);
    snprintf(out_dir, sizeof(out_dir), "%s/bk-open-out", g_dir);
    CHECK(ftn_mkdir_p(in_dir) && ftn_mkdir_p(out_dir));
    ftn_binkp_file_t files[1] = {0};
    snprintf(files[0].path, sizeof(files[0].path), "%s/x.pkt", out_dir);
    snprintf(files[0].name, sizeof(files[0].name), "x.pkt");
    write_file(files[0].path, 10U, 'x');
    files[0].size = 10;
    peer_t orig, ans;
    make_peers(&orig, &ans, "", "", in_dir, in_dir);
    orig.cfg.files = files;
    orig.cfg.file_count = 1U;
    run_pair(&orig, &ans);
    CHECK(orig.ok && ans.ok);
    CHECK(!orig.res.secure);
    CHECK_EQ(orig.res.files_sent, 0U);
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-fidonet-test-%ld",
             (long)getpid());
    mkdir(g_dir, 0700);

    RUN_TEST(address_parse_and_format);
    RUN_TEST(packet_header_round_trip);
    RUN_TEST(packet_type2_without_capability_word);
    RUN_TEST(datetime_round_trip);
    RUN_TEST(packed_message_round_trip_with_kludges);
    RUN_TEST(point_leaves_seen_by_to_its_boss);
    RUN_TEST(cp437_body_and_control_bytes);
    RUN_TEST(netmail_has_no_area);
    RUN_TEST(zmh_per_zone);
    RUN_TEST(zmh_window_start_and_midnight_wrap);
    RUN_TEST(msgbase_append_read_and_torn_tail);
    RUN_TEST(msgbase_rejects_unsafe_area_tags);
    RUN_TEST(dupes_and_hidden);
    RUN_TEST(cram_md5_matches_rfc2104_vector);
    RUN_TEST(binkp_safe_names);
    RUN_TEST(binkp_session_moves_files_both_ways);
    RUN_TEST(binkp_wrong_password_is_refused);
    RUN_TEST(binkp_unsecured_session_sends_nothing);

    rm_rf(g_dir);
    return TEST_REPORT();
}
