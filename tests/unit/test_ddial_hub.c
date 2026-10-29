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

    /* A reply quoting an emote/action line without asterisks. */
    chat_history_entry_t emote_parent = commit_system(
        "65#5[T1:Stern) *is reading the changelog now to catch up*");
    chat_history_entry_t emote_reply = commit_system(
        "65#3[T1:shark) you've got a few months of scrollback ....^ "
        ">>RE:[5] Stern: is reading the changelog now to catch up");
    uint64_t emote_reply_id = 0U;
    CHECK(host_ddial_reply_link_get(emote_reply.message_id, &emote_reply_id,
                                    label, sizeof(label)));
    chat_reply_entry_t emote_entry = {0};
    CHECK(host_replies_find_entry_by_id(g_host, emote_reply_id, &emote_entry));
    CHECK_EQ(emote_entry.parent_message_id, emote_parent.message_id);
    CHECK_STR_EQ(emote_entry.username, "shark");

    /* A reply quoting wire form with link-slot prefix e.g. 65#1[T1:... */
    chat_history_entry_t wire_reply = commit_system(
        "#11<T1:Marc) tritips?^ >>RE:65#1[T1:MerZz) nope. here is the article on it");
    uint64_t wire_reply_id = 0U;
    CHECK(host_ddial_reply_link_get(wire_reply.message_id, &wire_reply_id,
                                    label, sizeof(label)));
    chat_reply_entry_t wire_entry = {0};
    CHECK(host_replies_find_entry_by_id(g_host, wire_reply_id, &wire_entry));
    CHECK_EQ(wire_entry.parent_message_id, parent.message_id);
    CHECK_STR_EQ(wire_entry.username, "Marc");
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

static bool command_output_as(const char *command, bool is_operator,
                              char *output, size_t output_cap)
{
    if (command == NULL || output == NULL || output_cap == 0U) {
        return false;
    }
    output[0] = '\0';

    int pipefd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) != 0) {
        return false;
    }

    session_ctx_t ctx = {0};
    ctx.transport_kind = SESSION_TRANSPORT_TELNET;
    ctx.telnet_fd = pipefd[1];
    ctx.owner = g_host;
    ctx.user.is_operator = is_operator;
    ctx.terminal_width = 80;
    ctx.terminal_height = 24;
    session_dispatch_command(&ctx, command);
    close(pipefd[1]);

    size_t used = 0U;
    while (used + 1U < output_cap) {
        ssize_t n = read(pipefd[0], output + used, output_cap - used - 1U);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    close(pipefd[0]);
    output[used] = '\0';
    return true;
}

static bool command_output(const char *command, char *output, size_t output_cap)
{
    return command_output_as(command, false, output, output_cap);
}

TEST(thread_command_shows_mixed_nested_tree_from_message_or_reply)
{
    chat_history_entry_t root =
        commit_user("ThreadRoot", "thread root marker");
    chat_history_entry_t ddial = commit_system(
        "71#8[T1:Dialer) ddial child marker^ >>RE:ThreadRoot: thread root "
        "marker");
    uint64_t ddial_reply_id = 0U;
    CHECK(host_ddial_reply_link_get(ddial.message_id, &ddial_reply_id, NULL,
                                    0U));

    chat_reply_entry_t nested = {0};
    nested.parent_message_id = root.message_id;
    nested.parent_reply_id = ddial_reply_id;
    snprintf(nested.username, sizeof(nested.username), "%s", "NestedUser");
    snprintf(nested.message, sizeof(nested.message), "%s",
             "nested child marker");
    chat_reply_entry_t nested_stored = {0};
    CHECK(host_replies_commit_entry(g_host, &nested, &nested_stored));

    chat_reply_entry_t direct = {0};
    direct.parent_message_id = root.message_id;
    snprintf(direct.username, sizeof(direct.username), "%s", "DirectUser");
    snprintf(direct.message, sizeof(direct.message), "%s",
             "direct child marker");
    chat_reply_entry_t direct_stored = {0};
    CHECK(host_replies_commit_entry(g_host, &direct, &direct_stored));

    char root_label[32];
    char ddial_label[32];
    char nested_label[32];
    char direct_label[32];
    CHECK(host_compact_id_encode(root.message_id, root_label,
                                 sizeof(root_label)));
    CHECK(host_compact_id_encode(ddial_reply_id, ddial_label,
                                 sizeof(ddial_label)));
    CHECK(host_compact_id_encode(nested_stored.reply_id, nested_label,
                                 sizeof(nested_label)));
    CHECK(host_compact_id_encode(direct_stored.reply_id, direct_label,
                                 sizeof(direct_label)));

    char command[128];
    snprintf(command, sizeof(command), "/thread %s", root_label);
    char output[32768];
    CHECK(command_output(command, output, sizeof(output)));

    char expected[256];
    snprintf(expected, sizeof(expected), "Thread for #%s:", root_label);
    CHECK(strstr(output, expected) != NULL);
    CHECK(strstr(output, "thread root marker") != NULL);
    snprintf(expected, sizeof(expected), "    (r#%s) ddial child marker",
             ddial_label);
    char *ddial_pos = strstr(output, expected);
    CHECK(ddial_pos != NULL);
    snprintf(expected, sizeof(expected), "        (r#%s) nested child marker",
             nested_label);
    char *nested_pos = strstr(output, expected);
    CHECK(nested_pos != NULL);
    snprintf(expected, sizeof(expected), "    (r#%s) direct child marker",
             direct_label);
    char *direct_pos = strstr(output, expected);
    CHECK(direct_pos != NULL);
    CHECK(ddial_pos < nested_pos && nested_pos < direct_pos);

    snprintf(command, sizeof(command), "/thread r#%s", nested_label);
    CHECK(command_output(command, output, sizeof(output)));
    snprintf(expected, sizeof(expected), "Thread for #%s:", root_label);
    CHECK(strstr(output, expected) != NULL);
    CHECK(strstr(output, "thread root marker") != NULL);
    CHECK(strstr(output, "ddial child marker") != NULL);
    CHECK(strstr(output, "nested child marker") != NULL);
    CHECK(strstr(output, "direct child marker") != NULL);
}

TEST(thread_command_accepts_ddial_root_id)
{
    chat_history_entry_t root =
        commit_system("71#9[T1:DialRoot) ddial root marker");
    chat_history_entry_t reply = commit_system(
        "71#8[T1:Dialer) ddial root reply marker^ >>RE:[9] DialRoot: ddial "
        "root marker");
    uint64_t reply_id = 0U;
    CHECK(host_ddial_reply_link_get(reply.message_id, &reply_id, NULL, 0U));

    char root_label[32];
    char reply_label[32];
    CHECK(host_compact_id_encode(root.message_id, root_label,
                                 sizeof(root_label)));
    CHECK(host_compact_id_encode(reply_id, reply_label, sizeof(reply_label)));
    char command[128];
    snprintf(command, sizeof(command), "/thread d%s", root_label);
    char output[16384];
    CHECK(command_output(command, output, sizeof(output)));
    CHECK(strstr(output, "ddial root marker") != NULL);
    char expected[256];
    snprintf(expected, sizeof(expected), "    (r#%s) ddial root reply marker",
             reply_label);
    CHECK(strstr(output, expected) != NULL);
}

TEST(thread_command_rejects_bad_targets_without_mutation)
{
    size_t history_before = host_history_total(g_host);
    ttak_mutex_lock(&g_host->lock);
    size_t replies_before = g_host->reply_count;
    ttak_mutex_unlock(&g_host->lock);

    const char *usage_commands[] = {
        "/thread", "/thread nonsense", "/thread 1 extra", "/thread r#",
    };
    char output[16384];
    for (size_t idx = 0U;
         idx < sizeof(usage_commands) / sizeof(usage_commands[0]); ++idx) {
        CHECK(command_output(usage_commands[idx], output, sizeof(output)));
        CHECK(strstr(output, "Usage: /thread <message-id|r#reply-id>") != NULL);
    }

    CHECK(command_output("/thread 9999", output, sizeof(output)));
    CHECK(strstr(output, "Message #9999 was not found.") != NULL);
    CHECK(command_output("/thread r#9999", output, sizeof(output)));
    CHECK(strstr(output, "Reply r#9999 was not found.") != NULL);
    CHECK_EQ(host_history_total(g_host), history_before);
    ttak_mutex_lock(&g_host->lock);
    size_t replies_after = g_host->reply_count;
    ttak_mutex_unlock(&g_host->lock);
    CHECK_EQ(replies_after, replies_before);
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

TEST(station_request_workflow_persists_and_manages_requests)
{
    char output[16384];
    CHECK(command_output("/ddial requests", output, sizeof(output)));
    CHECK(strstr(output, "Only operators can manage DDial station links.") !=
          NULL);

    unsigned approve_id = 0U;
    unsigned duplicate_id = 0U;
    unsigned deny_id = 0U;
    CHECK(host_ddial_hub_request_register(g_host, "ApprovalTarget",
                                          "192.0.2.101", &approve_id));
    CHECK(host_ddial_hub_request_register(g_host, "approvaltarget",
                                          "192.0.2.101", &duplicate_id));
    CHECK_EQ(duplicate_id, approve_id);
    CHECK(host_ddial_hub_request_register(g_host, "DenyTarget", "192.0.2.102",
                                          &deny_id));
    CHECK(deny_id != approve_id);

    CHECK(command_output_as("/ddial requests", true, output, sizeof(output)));
    CHECK(strstr(output, "Pending station requests:") != NULL);
    CHECK(strstr(output, "ApprovalTarget [192.0.2.101]") != NULL);
    CHECK(strstr(output, "DenyTarget [192.0.2.102]") != NULL);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ddial_station_requests.dat", g_dir);
    struct stat st;
    CHECK_EQ(stat(path, &st), 0);
    CHECK_EQ(st.st_mode & 0777, 0600);
    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL);
    char contents[4096] = {0};
    size_t n = fread(contents, 1U, sizeof(contents) - 1U, fp);
    fclose(fp);
    contents[n] = '\0';
    CHECK(strstr(contents, "ApprovalTarget") != NULL);
    CHECK(strstr(contents, "DenyTarget") != NULL);

    pthread_mutex_lock(&g_ddial_hub_key_lock);
    memset(g_ddial_hub_requests, 0, sizeof(g_ddial_hub_requests));
    g_ddial_hub_request_count = 0U;
    g_ddial_hub_next_request_id = 1U;
    g_ddial_hub_requests_loaded = false;
    g_ddial_hub_request_path[0] = '\0';
    pthread_mutex_unlock(&g_ddial_hub_key_lock);

    char listing[4096];
    CHECK_EQ(host_ddial_hub_request_list(g_host, listing, sizeof(listing)), 2U);
    CHECK(strstr(listing, "ApprovalTarget") != NULL);
    CHECK(strstr(listing, "DenyTarget") != NULL);

    char command[64];
    snprintf(command, sizeof(command), "/ddial approve %u", approve_id);
    CHECK(command_output_as(command, true, output, sizeof(output)));
    char *approved = strstr(output, "Station request #");
    CHECK(approved != NULL);
    unsigned parsed_request_id = 0U;
    unsigned key_id = 0U;
    char name[DDIAL_MAX_HANDLE_LEN] = {0};
    char key[16] = {0};
    CHECK_EQ(sscanf(approved,
                    "Station request #%u approved. Station key #%u for "
                    "'%31[^']': %15s",
                    &parsed_request_id, &key_id, name, key),
             4);
    CHECK_EQ(parsed_request_id, approve_id);
    CHECK_STR_EQ(name, "ApprovalTarget");
    CHECK(ddial_station_key_is_wellformed(key));
    CHECK_EQ(ddial_hub_key_match(g_host, key, NULL, 0U), key_id);

    CHECK_EQ(host_ddial_hub_request_list(g_host, listing, sizeof(listing)), 1U);
    CHECK(strstr(listing, "ApprovalTarget") == NULL);
    CHECK(strstr(listing, "DenyTarget") != NULL);

    snprintf(command, sizeof(command), "/ddial deny #%u", deny_id);
    CHECK(command_output_as(command, true, output, sizeof(output)));
    char expected[128];
    snprintf(expected, sizeof(expected), "Station request #%u denied.", deny_id);
    CHECK(strstr(output, expected) != NULL);
    CHECK(command_output_as("/ddial requests", true, output, sizeof(output)));
    CHECK(strstr(output, "No pending station requests.") != NULL);

    CHECK(command_output_as("/ddial approve nope", true, output,
                            sizeof(output)));
    CHECK(strstr(output, "Usage: /ddial approve <request-id>") != NULL);
    CHECK(command_output_as("/ddial deny 9999", true, output, sizeof(output)));
    CHECK(strstr(output, "No station request with that id.") != NULL);

    fp = fopen(path, "r");
    CHECK(fp != NULL);
    memset(contents, 0, sizeof(contents));
    n = fread(contents, 1U, sizeof(contents) - 1U, fp);
    fclose(fp);
    contents[n] = '\0';
    CHECK(strstr(contents, "ApprovalTarget") == NULL);
    CHECK(strstr(contents, "DenyTarget") == NULL);
    memset(key, 0, sizeof(key));
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

TEST(outbound_request_client_tracks_cancels_and_resubmits)
{
    int port = free_port();
    char spec[32];
    snprintf(spec, sizeof(spec), "127.0.0.1:%d", port);
    setenv("CHATTER_DDIAL_HUB_LISTEN", spec, 1);
    setenv("CHATTER_DDIAL_STATION", "RequestTestHub", 1);
    host_ddial_hub_start(g_host);
    int ready = connect_loopback(port);
    CHECK(ready >= 0);
    close(ready);

    char relay_host[sizeof(g_host->ddial_relay.host)];
    snprintf(relay_host, sizeof(relay_host), "%s", g_host->ddial_relay.host);
    int relay_port = g_host->ddial_relay.port;
    bool relay_enabled = g_host->ddial_relay.enabled;

    char output[16384];
    CHECK(command_output("/ddial request-status", output, sizeof(output)));
    CHECK(strstr(output, "Only operators can manage DDial station links.") !=
          NULL);
    CHECK(command_output_as("/ddial request-status", true, output,
                            sizeof(output)));
    CHECK(strstr(output, "No outbound station request is being tracked.") !=
          NULL);
    CHECK(command_output_as("/ddial request 127.0.0.1 nope Bad", true, output,
                            sizeof(output)));
    CHECK(strstr(output,
                 "Usage: /ddial request <host> <port> <station-name>") != NULL);

    char command[512];
    snprintf(command, sizeof(command),
             "/ddial request 127.0.0.1 %d Outbound One", port);
    CHECK(command_output_as(command, true, output, sizeof(output)));
    char *recorded = strstr(output, "Station request #");
    CHECK(recorded != NULL);
    unsigned remote_id = 0U;
    CHECK_EQ(sscanf(recorded, "Station request #%u", &remote_id), 1);
    CHECK(remote_id > 0U);
    CHECK(strstr(output, "for 'Outbound One'.") != NULL);

    char request_listing[4096];
    CHECK_EQ(host_ddial_hub_request_list(g_host, request_listing,
                                         sizeof(request_listing)),
             1U);
    CHECK(strstr(request_listing, "Outbound One [127.0.0.1]") != NULL);

    CHECK(command_output_as("/ddial request-status", true, output,
                            sizeof(output)));
    char expected[512];
    snprintf(expected, sizeof(expected), "#%u Outbound One (127.0.0.1:%d)",
             remote_id, port);
    CHECK(strstr(output, expected) != NULL);

    host_t *restarted = new_host();
    CHECK(restarted != NULL);
    char tracking[1024];
    CHECK_EQ(host_ddial_outbound_request_status(restarted, tracking,
                                                sizeof(tracking)),
             DDIAL_OUTBOUND_REQUEST_OK);
    CHECK_STR_EQ(tracking, expected);
    free(restarted);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ddial_outbound_request.dat", g_dir);
    struct stat st;
    CHECK_EQ(stat(path, &st), 0);
    CHECK_EQ(st.st_mode & 0777, 0600);
    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL);
    char contents[2048] = {0};
    size_t n = fread(contents, 1U, sizeof(contents) - 1U, fp);
    fclose(fp);
    contents[n] = '\0';
    CHECK(strstr(contents, "127.0.0.1") != NULL);
    CHECK(strstr(contents, "Outbound One") != NULL);

    CHECK(command_output_as(command, true, output, sizeof(output)));
    CHECK(strstr(output, "An outbound station request is already tracked") !=
          NULL);
    CHECK_STR_EQ(g_host->ddial_relay.host, relay_host);
    CHECK_EQ(g_host->ddial_relay.port, relay_port);
    CHECK_EQ(g_host->ddial_relay.enabled, relay_enabled);

    CHECK(command_output_as("/ddial request-cancel", true, output,
                            sizeof(output)));
    CHECK(strstr(output, "Outbound request tracking cleared") != NULL);
    CHECK(command_output_as("/ddial request-status", true, output,
                            sizeof(output)));
    CHECK(strstr(output, "No outbound station request is being tracked.") !=
          NULL);
    CHECK_EQ(host_ddial_hub_request_list(g_host, request_listing,
                                         sizeof(request_listing)),
             1U);

    CHECK(command_output_as(command, true, output, sizeof(output)));
    recorded = strstr(output, "Station request #");
    CHECK(recorded != NULL);
    unsigned resubmitted_id = 0U;
    CHECK_EQ(sscanf(recorded, "Station request #%u", &resubmitted_id), 1);
    CHECK_EQ(resubmitted_id, remote_id);
    CHECK(command_output_as("/ddial request-cancel", true, output,
                            sizeof(output)));
    CHECK_EQ(host_ddial_hub_request_deny(g_host, remote_id),
             DDIAL_HUB_REQUEST_OK);
    host_ddial_hub_stop(g_host);
}

TEST(station_links_with_key_and_relays_chat)
{
    int port = free_port();
    char spec[32];
    snprintf(spec, sizeof(spec), "127.0.0.1:%d", port);
    setenv("CHATTER_DDIAL_HUB_LISTEN", spec, 1);
    setenv("CHATTER_DDIAL_STATION", "TestHub", 1);
    host_ddial_hub_start(g_host);

    int request_fd = connect_loopback(port);
    CHECK(request_fd >= 0);
    char request_buf[1024] = {0};
    CHECK(read_until(request_fd, "Enter Password", request_buf,
                     sizeof(request_buf), 3000));
    ddial_hub_write_text(request_fd, "@request:WireRequest\r\n");
    request_buf[0] = '\0';
    CHECK(read_until(request_fd, "Station link request #", request_buf,
                     sizeof(request_buf), 3000));
    close(request_fd);
    char request_listing[1024];
    CHECK_EQ(host_ddial_hub_request_list(g_host, request_listing,
                                         sizeof(request_listing)),
             1U);
    CHECK(strstr(request_listing, "WireRequest [127.0.0.1]") != NULL);
    unsigned request_id = 0U;
    CHECK_EQ(sscanf(request_listing, "#%u", &request_id), 1);
    CHECK_EQ(host_ddial_hub_request_deny(g_host, request_id),
             DDIAL_HUB_REQUEST_OK);

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

/* ---- Scrollback blank/noise entry skipping ---- */

TEST(scrollback_entry_visibility_check)
{
    session_ctx_t ctx = {0};
    ctx.owner = g_host;

    chat_history_entry_t empty = {0};
    CHECK(!session_scrollback_entry_is_visible(&ctx, &empty));

    chat_history_entry_t noise = {0};
    snprintf(noise.message, sizeof(noise.message), "%s",
             "[LINK] -->. +^#5[T1:Bob");
    CHECK(!session_scrollback_entry_is_visible(&ctx, &noise));

    chat_history_entry_t user_msg = {0};
    user_msg.is_user_message = true;
    snprintf(user_msg.username, sizeof(user_msg.username), "alice");
    snprintf(user_msg.message, sizeof(user_msg.message), "hello world");
    CHECK(session_scrollback_entry_is_visible(&ctx, &user_msg));

    chat_history_entry_t ddial_chat = {0};
    snprintf(ddial_chat.message, sizeof(ddial_chat.message), "%s",
             "71#4[T1:MaxMouse) hello there");
    CHECK(session_scrollback_entry_is_visible(&ctx, &ddial_chat));
}

TEST(scrollback_skips_consecutive_noise_entries)
{
    host_t *host = new_host();
    CHECK(host != NULL);

    session_ctx_t ctx = {0};
    ctx.owner = host;

    chat_history_entry_t entry1 = {0};
    entry1.is_user_message = true;
    snprintf(entry1.username, sizeof(entry1.username), "alice");
    snprintf(entry1.message, sizeof(entry1.message), "visible first");
    chat_history_entry_t stored = {0};
    CHECK(host_history_commit_entry(host, &entry1, &stored));
    size_t first_idx = host->history_total - 1U;

    /* Add 50 noise lines */
    for (int i = 0; i < 50; ++i) {
        chat_history_entry_t noise = {0};
        snprintf(noise.message, sizeof(noise.message), "[LINK] noise keepalive");
        (void)host_history_commit_entry(host, &noise, &stored);
    }

    chat_history_entry_t entry2 = {0};
    entry2.is_user_message = true;
    snprintf(entry2.username, sizeof(entry2.username), "bob");
    snprintf(entry2.message, sizeof(entry2.message), "visible second");
    CHECK(host_history_commit_entry(host, &entry2, &stored));
    size_t second_idx = host->history_total - 1U;

    CHECK_EQ(second_idx - first_idx, 51U);

    size_t prev_idx = 0U;
    CHECK(session_scrollback_find_prev_visible(&ctx, second_idx, &prev_idx));
    CHECK_EQ(prev_idx, second_idx);

    CHECK(session_scrollback_find_prev_visible(&ctx, second_idx - 1U, &prev_idx));
    CHECK_EQ(prev_idx, first_idx);

    size_t step_idx = 0U;
    bool reached_boundary = false;
    CHECK(session_scrollback_step_visible(&ctx, second_idx, 1, 1, &step_idx,
                                         &reached_boundary));
    CHECK_EQ(step_idx, first_idx);
    CHECK(!reached_boundary);

    /* Stepping backwards from first_idx fails because it is the oldest */
    CHECK(!session_scrollback_step_visible(&ctx, first_idx, 1, 1, &step_idx,
                                          &reached_boundary));
    CHECK(reached_boundary);

    /* Stepping more visible messages than exist reaches boundary */
    CHECK(session_scrollback_step_visible(&ctx, second_idx, 1, 5, &step_idx,
                                         &reached_boundary));
    CHECK_EQ(step_idx, first_idx);
    CHECK(reached_boundary);

    /* Collect visible entries ending at second_idx */
    chat_history_entry_t buf[10];
    size_t indices[10];
    size_t collected = session_scrollback_collect_visible(
        &ctx, second_idx, 10, buf, indices, 10);
    CHECK_EQ(collected, 2U);
    CHECK_EQ(indices[0], first_idx);
    CHECK_EQ(indices[1], second_idx);
    CHECK_STR_EQ(buf[0].message, "visible first");
    CHECK_STR_EQ(buf[1].message, "visible second");

    free(host);
}

TEST(scrollback_navigate_skips_noise_and_never_blanks)
{
    host_t *host = new_host();
    CHECK(host != NULL);

    chat_history_entry_t stored = {0};
    chat_history_entry_t entry1 = {0};
    entry1.is_user_message = true;
    snprintf(entry1.username, sizeof(entry1.username), "alice");
    snprintf(entry1.message, sizeof(entry1.message), "visible first");
    CHECK(host_history_commit_entry(host, &entry1, &stored));

    for (int i = 0; i < 50; ++i) {
        chat_history_entry_t noise = {0};
        snprintf(noise.message, sizeof(noise.message), "[LINK] noise keepalive");
        (void)host_history_commit_entry(host, &noise, &stored);
    }

    chat_history_entry_t entry2 = {0};
    entry2.is_user_message = true;
    snprintf(entry2.username, sizeof(entry2.username), "bob");
    snprintf(entry2.message, sizeof(entry2.message), "visible second");
    CHECK(host_history_commit_entry(host, &entry2, &stored));

    int pipefd[2];
    CHECK_EQ(pipe(pipefd), 0);

    session_ctx_t ctx = {0};
    ctx.transport_kind = SESSION_TRANSPORT_TELNET;
    ctx.telnet_fd = pipefd[1];
    ctx.owner = host;
    ctx.terminal_width = 80;
    ctx.terminal_height = 24;

    size_t total = host_history_total(host);
    size_t latest_vis = 0U;
    CHECK(session_scrollback_find_prev_visible(&ctx, total - 1U, &latest_vis));

    /* Navigate back 1 visible message */
    session_scrollback_navigate_line(&ctx, 1);
    CHECK(ctx.history_scroll_position > 0U);
    size_t expected_anchor = 0U;
    CHECK(session_scrollback_step_visible(&ctx, latest_vis, 1, 1,
                                         &expected_anchor, nullptr));
    CHECK_EQ(ctx.history_scroll_position, total - 1U - expected_anchor);

    /* Navigate forward 1 visible message returns to live tail */
    session_scrollback_navigate_line(&ctx, -1);
    CHECK_EQ(ctx.history_scroll_position, 0U);

    close(pipefd[0]);
    close(pipefd[1]);
    free(host);
}

static void remove_dir_files(const char *dir)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ddial_station_keys.tsv", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_station_keys.tsv.tmp", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_station_requests.dat", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_station_requests.dat.tmp", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_outbound_request.dat", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/ddial_outbound_request.dat.tmp", dir);
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
    RUN_TEST(thread_command_shows_mixed_nested_tree_from_message_or_reply);
    RUN_TEST(thread_command_accepts_ddial_root_id);
    RUN_TEST(thread_command_rejects_bad_targets_without_mutation);
    RUN_TEST(full_reply_table_drops_the_oldest);
    RUN_TEST(station_key_create_match_revoke);
    RUN_TEST(station_request_workflow_persists_and_manages_requests);
    RUN_TEST(failed_logins_block_an_address);
    RUN_TEST(outbound_request_client_tracks_cancels_and_resubmits);
    RUN_TEST(station_links_with_key_and_relays_chat);
    RUN_TEST(scrollback_entry_visibility_check);
    RUN_TEST(scrollback_skips_consecutive_noise_entries);
    RUN_TEST(scrollback_navigate_skips_noise_and_never_blanks);

    remove_dir_files(g_dir);
    return TEST_REPORT();
}
