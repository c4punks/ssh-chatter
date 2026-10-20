/**
 * @file test_ddial_hub.c
 * @desc Tests for DDial message ids ("d<id>") and the inbound station hub
 *       (src/host/ddial/hub.c). The host aggregate is #included so static
 *       helpers can be called on a zeroed host_t; the hub test logs a
 *       station in over a real loopback TCP connection.
 */
#include "../../src/host_aggregate.c"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "test_harness.h"

static char g_dir[PATH_MAX];
static host_t *g_host = NULL;

static host_t *new_host(void)
{
    host_t *host = calloc(1U, sizeof(*host));
    if (host != NULL) {
        ttak_mutex_init(&host->lock);
        snprintf(host->user_data_root, sizeof(host->user_data_root), "%s",
                 g_dir);
        host->next_message_id = 1U;
    }
    return host;
}

/* ---- message ids for relayed DDial chat ---- */

TEST(relayed_ddial_chat_gets_a_message_id)
{
    chat_history_entry_t entry = {0};
    snprintf(entry.message, sizeof(entry.message), "%s",
             "71#4[T1:MaxMouse) hello there");
    chat_history_entry_t stored = {0};
    CHECK(host_history_commit_entry(g_host, &entry, &stored));
    CHECK(stored.message_id > 0U);
    CHECK(host_ddial_entry_is_relayed_chat(&stored));

    char label[32];
    char plain[32];
    CHECK(host_history_id_label(&stored, label, sizeof(label)));
    CHECK(host_compact_id_encode(stored.message_id, plain, sizeof(plain)));
    CHECK_EQ(label[0], 'd');
    CHECK_STR_EQ(label + 1, plain);

    /* "d<id>" names the same message as "<id>". */
    uint64_t decoded = 0U;
    CHECK(host_compact_id_decode(label, &decoded));
    CHECK_EQ(decoded, stored.message_id);

    chat_history_entry_t found = {0};
    CHECK(host_history_find_entry_by_id(g_host, decoded, &found));
    CHECK_STR_EQ(found.message, "71#4[T1:MaxMouse) hello there");
}

TEST(plain_system_lines_stay_without_id)
{
    chat_history_entry_t entry = {0};
    snprintf(entry.message, sizeof(entry.message), "%s", "* server notice");
    chat_history_entry_t stored = {0};
    CHECK(host_history_commit_entry(g_host, &entry, &stored));
    CHECK_EQ(stored.message_id, 0);
    char label[32];
    CHECK(!host_history_id_label(&stored, label, sizeof(label)));

    /* Link housekeeping is hidden, so it gets no id either. */
    chat_history_entry_t link = {0};
    snprintf(link.message, sizeof(link.message), "%s",
             "[LINK] -->. +^#5[T1:Bob");
    CHECK(host_history_commit_entry(g_host, &link, &stored));
    CHECK_EQ(stored.message_id, 0);
}

TEST(chatter_ids_keep_their_plain_label)
{
    chat_history_entry_t entry = {0};
    entry.is_user_message = true;
    snprintf(entry.username, sizeof(entry.username), "%s", "alice");
    snprintf(entry.message, sizeof(entry.message), "%s", "hi");
    chat_history_entry_t stored = {0};
    CHECK(host_history_commit_entry(g_host, &entry, &stored));
    char label[32];
    CHECK(host_history_id_label(&stored, label, sizeof(label)));
    CHECK(label[0] >= '0' && label[0] <= '9');
}

TEST(decode_accepts_d_prefix_only_before_digits)
{
    uint64_t id = 0U;
    CHECK(host_compact_id_decode("d12", &id));
    CHECK_EQ(id, 12);
    CHECK(host_compact_id_decode("D12", &id));
    CHECK_EQ(id, 12);
    CHECK(!host_compact_id_decode("d", &id));
    CHECK(!host_compact_id_decode("dd12", &id));
}

/* ---- DDial replies joining Chatter threads ---- */

static chat_history_entry_t commit_system(const char *line)
{
    chat_history_entry_t entry = {0};
    snprintf(entry.message, sizeof(entry.message), "%s", line);
    chat_history_entry_t stored = {0};
    (void)host_history_commit_entry(g_host, &entry, &stored);
    return stored;
}

static chat_history_entry_t commit_user(const char *name, const char *text)
{
    chat_history_entry_t entry = {0};
    entry.is_user_message = true;
    snprintf(entry.username, sizeof(entry.username), "%s", name);
    snprintf(entry.message, sizeof(entry.message), "%s", text);
    chat_history_entry_t stored = {0};
    (void)host_history_commit_entry(g_host, &entry, &stored);
    return stored;
}

static size_t reply_count_for(uint64_t parent_message_id)
{
    size_t n = 0U;
    ttak_mutex_lock(&g_host->lock);
    for (size_t i = 0U; i < g_host->reply_count; ++i) {
        if (g_host->replies[i].in_use &&
            g_host->replies[i].parent_message_id == parent_message_id) {
            ++n;
        }
    }
    ttak_mutex_unlock(&g_host->lock);
    return n;
}

TEST(ddial_reply_to_ddial_line_becomes_a_reply)
{
    chat_history_entry_t parent =
        commit_system("71#1[T1:MerZz) nope. here is the article on it");
    commit_system("71#2[T1:oxyosbourne) unrelated chatter in between");
    chat_history_entry_t reply = commit_system(
        "71#2[T1:oxyosbourne) Just put it on a party boat^ >>RE:[1] MerZz: "
        "nope. here is the article");

    uint64_t reply_id = 0U;
    char label[40];
    CHECK(host_ddial_reply_link_get(reply.message_id, &reply_id, label,
                                    sizeof(label)));
    char parent_label[32];
    CHECK(host_history_id_label(&parent, parent_label, sizeof(parent_label)));
    char expected[40];
    snprintf(expected, sizeof(expected), "#%s", parent_label);
    CHECK_STR_EQ(label, expected);

    chat_reply_entry_t entry = {0};
    CHECK(host_replies_find_entry_by_id(g_host, reply_id, &entry));
    CHECK_EQ(entry.parent_message_id, parent.message_id);
    CHECK_EQ(entry.parent_reply_id, 0);
    CHECK_STR_EQ(entry.username, "oxyosbourne");
    CHECK_STR_EQ(entry.message, "Just put it on a party boat");

    /* It is shown the way Chatter shows replies. */
    chat_history_entry_t scratch;
    const chat_history_entry_t *view = NULL;
    CHECK(host_ddial_display_view(&reply, &scratch, &view));
    CHECK(!view->is_user_message);
    char reply_label[32];
    CHECK(host_compact_id_encode(reply_id, reply_label, sizeof(reply_label)));
    char shown[256];
    snprintf(shown, sizeof(shown),
             "->[r#%s #%s] oxyosbourne: Just put it on a party boat",
             reply_label, parent_label);
    CHECK_STR_EQ(view->message, shown);

    /* A reply to that reply threads under it. */
    chat_history_entry_t second = commit_system(
        "71#2[T1:oxyosbourne) ok I /. vegas?^ >>RE:oxyosbourne: Just put it "
        "on a party boat");
    uint64_t second_id = 0U;
    CHECK(host_ddial_reply_link_get(second.message_id, &second_id, label,
                                    sizeof(label)));
    chat_reply_entry_t threaded = {0};
    CHECK(host_replies_find_entry_by_id(g_host, second_id, &threaded));
    CHECK_EQ(threaded.parent_message_id, parent.message_id);
    CHECK_EQ(threaded.parent_reply_id, reply_id);
    snprintf(expected, sizeof(expected), "r#%s", reply_label);
    CHECK_STR_EQ(label, expected);
}

TEST(ddial_reply_to_chatter_message_and_chatter_reply)
{
    chat_history_entry_t msg = commit_user("Lee Yunjin", "anyone up for chess?");
    chat_history_entry_t reply = commit_system(
        "71#4[T1:MaxMouse) sure, one game^ >>RE:Lee Yunjin: anyone up for "
        "chess?");
    uint64_t reply_id = 0U;
    char label[40];
    CHECK(host_ddial_reply_link_get(reply.message_id, &reply_id, label,
                                    sizeof(label)));
    char msg_label[32];
    CHECK(host_compact_id_encode(msg.message_id, msg_label, sizeof(msg_label)));
    char expected[40];
    snprintf(expected, sizeof(expected), "#%s", msg_label);
    CHECK_STR_EQ(label, expected);

    /* A Chatter reply line as the quoted parent. */
    chat_reply_entry_t chatter_reply = {0};
    chatter_reply.parent_message_id = msg.message_id;
    snprintf(chatter_reply.username, sizeof(chatter_reply.username), "%s",
             "tester");
    snprintf(chatter_reply.message, sizeof(chatter_reply.message), "%s",
             "count me in too");
    chat_reply_entry_t committed = {0};
    CHECK(host_replies_commit_entry(g_host, &chatter_reply, &committed));
    char r_label[32];
    CHECK(host_compact_id_encode(committed.reply_id, r_label, sizeof(r_label)));
    char line[256];
    snprintf(line, sizeof(line), "->[r#%s #%s] tester: count me in too",
             r_label, msg_label);
    commit_system(line);
    chat_history_entry_t answer = commit_system(
        "71#4[T1:MaxMouse) welcome!^ >>RE:tester: count me in too");
    uint64_t answer_id = 0U;
    CHECK(host_ddial_reply_link_get(answer.message_id, &answer_id, label,
                                    sizeof(label)));
    chat_reply_entry_t threaded = {0};
    CHECK(host_replies_find_entry_by_id(g_host, answer_id, &threaded));
    CHECK_EQ(threaded.parent_message_id, msg.message_id);
    CHECK_EQ(threaded.parent_reply_id, committed.reply_id);
}

TEST(unmatched_ddial_reply_stays_a_plain_line)
{
    chat_history_entry_t orphan = commit_system(
        "71#5[T1:Ghost) what?^ >>RE:Nobody: a line that never existed");
    CHECK(!host_ddial_reply_link_get(orphan.message_id, NULL, NULL, 0U));
    chat_history_entry_t scratch;
    const chat_history_entry_t *view = NULL;
    CHECK(host_ddial_display_view(&orphan, &scratch, &view));
    CHECK(view->is_user_message);
    CHECK_STR_EQ(view->username, "Ghost");
}

TEST(rebuild_is_idempotent)
{
    chat_history_entry_t parent = commit_system("71#6[T1:Ann) are you there?");
    commit_system("71#7[T1:Ben) yes^ >>RE:[6] Ann: are you there?");
    CHECK_EQ(reply_count_for(parent.message_id), 1);
    host_ddial_replies_rebuild(g_host);
    host_ddial_replies_rebuild(g_host);
    CHECK_EQ(reply_count_for(parent.message_id), 1);
}

TEST(full_reply_table_drops_the_oldest)
{
    ttak_mutex_lock(&g_host->lock);
    host_replies_ensure(g_host);
    size_t before = g_host->reply_count;
    ttak_mutex_unlock(&g_host->lock);
    chat_reply_entry_t entry = {0};
    entry.parent_message_id = 1U;
    snprintf(entry.username, sizeof(entry.username), "%s", "filler");
    for (size_t i = before; i < SSH_CHATTER_MAX_REPLIES + 5U; ++i) {
        snprintf(entry.message, sizeof(entry.message), "fill %zu", i);
        chat_reply_entry_t stored = {0};
        CHECK(host_replies_commit_entry(g_host, &entry, &stored));
    }
    ttak_mutex_lock(&g_host->lock);
    size_t count = g_host->reply_count;
    char last[64];
    snprintf(last, sizeof(last), "%s",
             g_host->replies[g_host->reply_count - 1U].message);
    ttak_mutex_unlock(&g_host->lock);
    CHECK_EQ(count, SSH_CHATTER_MAX_REPLIES);
    char expected[64];
    snprintf(expected, sizeof(expected), "fill %zu",
             (size_t)SSH_CHATTER_MAX_REPLIES + 4U);
    CHECK_STR_EQ(last, expected);
}

/* ---- station keys ---- */

TEST(station_key_create_match_revoke)
{
    char key[DDIAL_STATION_KEY_LEN + 1U];
    unsigned id = 0U;
    CHECK(host_ddial_hub_key_create(g_host, "Remote One", key, &id));
    CHECK(id > 0U);
    CHECK(ddial_station_key_is_wellformed(key));

    char label[DDIAL_MAX_HANDLE_LEN];
    CHECK_EQ(ddial_hub_key_match(g_host, key, label, sizeof(label)), id);
    CHECK_STR_EQ(label, "Remote One");

    /* Only the hash is on disk. */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ddial_station_keys.tsv", g_dir);
    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL);
    char contents[2048] = {0};
    size_t n = fread(contents, 1U, sizeof(contents) - 1U, fp);
    fclose(fp);
    contents[n] = '\0';
    CHECK(strstr(contents, key) == NULL);
    CHECK(strstr(contents, "Remote One") != NULL);

    char wrong[DDIAL_STATION_KEY_LEN + 1U];
    snprintf(wrong, sizeof(wrong), "%s", key);
    wrong[0] = wrong[0] == '0' ? '1' : '0';
    CHECK_EQ(ddial_hub_key_match(g_host, wrong, NULL, 0U), 0);
    CHECK_EQ(ddial_hub_key_match(g_host, "12345", NULL, 0U), 0);

    char listing[512];
    CHECK(host_ddial_hub_key_list(g_host, listing, sizeof(listing)) >= 1U);
    CHECK(strstr(listing, "Remote One") != NULL);

    CHECK(host_ddial_hub_key_revoke(g_host, id));
    CHECK_EQ(ddial_hub_key_match(g_host, key, NULL, 0U), 0);
    CHECK(!host_ddial_hub_key_revoke(g_host, id));

    /* A revoked id is never handed out again. */
    char next_key[DDIAL_STATION_KEY_LEN + 1U];
    unsigned next_id = 0U;
    CHECK(host_ddial_hub_key_create(g_host, "Remote Two", next_key, &next_id));
    CHECK(next_id > id);
    CHECK(host_ddial_hub_key_revoke(g_host, next_id));
}

TEST(failed_logins_block_an_address)
{
    const char *ip = "192.0.2.77";
    CHECK(!ddial_hub_ip_blocked(ip));
    for (unsigned i = 0U; i < DDIAL_HUB_FAIL_LIMIT; ++i) {
        ddial_hub_note_failure(ip);
    }
    CHECK(ddial_hub_ip_blocked(ip));
    CHECK(!ddial_hub_ip_blocked("192.0.2.78"));
    ddial_hub_clear_failures(ip);
    CHECK(!ddial_hub_ip_blocked(ip));
}

/* ---- live station login over loopback ---- */

static int connect_loopback(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            return fd;
        }
        usleep(100000);
    }
    close(fd);
    return -1;
}

/* Read until needle shows up (or timeout); collected text goes to buf. */
static bool read_until(int fd, const char *needle, char *buf, size_t cap,
                       int timeout_ms)
{
    size_t len = strlen(buf);
    for (int waited = 0; waited < timeout_ms; waited += 50) {
        if (strstr(buf, needle) != NULL) {
            return true;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 50) > 0) {
            ssize_t n = recv(fd, buf + len, cap - len - 1U, 0);
            if (n <= 0) {
                break;
            }
            len += (size_t)n;
            buf[len] = '\0';
        }
    }
    return strstr(buf, needle) != NULL;
}

static int free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(addr);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(fd, (struct sockaddr *)&addr, &len);
    int port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static bool history_contains(const char *text, uint64_t *id_out)
{
    bool found = false;
    ttak_mutex_lock(&g_host->lock);
    for (size_t i = 0U; i < g_host->history_count; ++i) {
        if (strcmp(g_host->history[i].message, text) == 0) {
            found = true;
            if (id_out != NULL) {
                *id_out = g_host->history[i].message_id;
            }
        }
    }
    ttak_mutex_unlock(&g_host->lock);
    return found;
}

TEST(station_links_with_key_and_relays_chat)
{
    int port = free_port();
    char spec[32];
    snprintf(spec, sizeof(spec), "127.0.0.1:%d", port);
    setenv("CHATTER_DDIAL_HUB_LISTEN", spec, 1);
    setenv("CHATTER_DDIAL_STATION", "TestHub", 1);
    host_ddial_hub_start(g_host);

    char key[DDIAL_STATION_KEY_LEN + 1U];
    unsigned id = 0U;
    CHECK(host_ddial_hub_key_create(g_host, "Linker", key, &id));

    /* A wrong key is turned away. */
    int bad = connect_loopback(port);
    CHECK(bad >= 0);
    char buf[4096] = {0};
    CHECK(read_until(bad, "Enter Password", buf, sizeof(buf), 3000));
    ddial_hub_write_text(bad, "000000000\r\n");
    buf[0] = '\0';
    CHECK(read_until(bad, "Invalid password", buf, sizeof(buf), 8000));
    close(bad);
    ddial_hub_clear_failures("127.0.0.1");

    /* The right key gets the banner, its link line and the user list. */
    int fd = connect_loopback(port);
    CHECK(fd >= 0);
    buf[0] = '\0';
    CHECK(read_until(fd, "Enter Password", buf, sizeof(buf), 3000));
    char line[32];
    snprintf(line, sizeof(line), "%s\r\n", key);
    ddial_hub_write_text(fd, line);
    buf[0] = '\0';
    CHECK(read_until(fd, "Welcome to TestHub station link", buf, sizeof(buf),
                     8000));
    CHECK(read_until(fd, " #60(T1:?)", buf, sizeof(buf), 3000));
    CHECK(read_until(fd, "}}}", buf, sizeof(buf), 3000));

    /* A second connection with the same key is refused. */
    int dup = connect_loopback(port);
    CHECK(dup >= 0);
    char dup_buf[1024] = {0};
    CHECK(read_until(dup, "Enter Password", dup_buf, sizeof(dup_buf), 3000));
    ddial_hub_write_text(dup, line);
    dup_buf[0] = '\0';
    CHECK(read_until(dup, "already linked", dup_buf, sizeof(dup_buf), 8000));
    close(dup);

    /* Station chat is stored with the station's line in front, with an id. */
    ddial_hub_write_text(fd, "/HRemoteSta\r\n#4[T1:Bob) hello hub\r\n");
    uint64_t msg_id = 0U;
    for (int i = 0; i < 50 && !history_contains("60#4[T1:Bob) hello hub",
                                                &msg_id);
         ++i) {
        usleep(100000);
    }
    CHECK(history_contains("60#4[T1:Bob) hello hub", &msg_id));
    CHECK(msg_id > 0U);

    char status[512];
    CHECK_EQ(host_ddial_hub_status(g_host, status, sizeof(status)), 1);
    CHECK(strstr(status, "RemoteSta") != NULL);

    /* Chat said here reaches the station in link form. */
    buf[0] = '\0';
    host_ddial_client_send(g_host, "Alice", "hi station");
    CHECK(read_until(fd, "[T1:Alice) hi station", buf, sizeof(buf), 3000));

    /* Revoking the key drops the link. */
    CHECK(host_ddial_hub_key_revoke(g_host, id));
    for (int i = 0; i < 50 && host_ddial_hub_status(g_host, status,
                                                    sizeof(status)) > 0U;
         ++i) {
        usleep(100000);
    }
    CHECK_EQ(host_ddial_hub_status(g_host, status, sizeof(status)), 0);
    close(fd);
    host_ddial_hub_stop(g_host);
}

static void remove_dir_files(const char *dir)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ddial_station_keys.tsv", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_station_keys.tsv.tmp", dir);
    unlink(path);
    rmdir(dir);
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-ddial-hub-test-%ld",
             (long)getpid());
    mkdir(g_dir, 0700);
    g_host = new_host();
    if (g_host == NULL) {
        return EXIT_FAILURE;
    }

    RUN_TEST(relayed_ddial_chat_gets_a_message_id);
    RUN_TEST(plain_system_lines_stay_without_id);
    RUN_TEST(chatter_ids_keep_their_plain_label);
    RUN_TEST(decode_accepts_d_prefix_only_before_digits);
    RUN_TEST(ddial_reply_to_ddial_line_becomes_a_reply);
    RUN_TEST(ddial_reply_to_chatter_message_and_chatter_reply);
    RUN_TEST(unmatched_ddial_reply_stays_a_plain_line);
    RUN_TEST(rebuild_is_idempotent);
    RUN_TEST(full_reply_table_drops_the_oldest);
    RUN_TEST(station_key_create_match_revoke);
    RUN_TEST(failed_logins_block_an_address);
    RUN_TEST(station_links_with_key_and_relays_chat);

    remove_dir_files(g_dir);
    return TEST_REPORT();
}
