#include "../../src/host_aggregate.c"

#include <sys/socket.h>
#include <unistd.h>

#include "test_harness.h"

static char g_dir[PATH_MAX];

static host_t *new_host(void)
{
    host_t *host = calloc(1U, sizeof(*host));
    if (host != NULL) {
        ttak_mutex_init(&host->lock);
        ttak_mutex_init(&host->user_data_lock);
        host->user_data_lock_initialized = true;
        chat_room_init(&host->room);
        snprintf(host->user_data_root, sizeof(host->user_data_root), "%s",
                 g_dir);
        snprintf(host->state_file_path, sizeof(host->state_file_path),
                 "%s/multilingual-state.dat", g_dir);
        host->next_message_id = 1U;
        host_preferences_ensure(host);
        host_operator_grants_ensure(host);
    }
    return host;
}

static void free_host(host_t *host)
{
    if (host != NULL) {
        sshc_gc_free(host->history);
        sshc_gc_free(host->preferences);
        sshc_gc_free(host->operator_grants);
        sshc_gc_free(host->replies);
        ttak_mutex_destroy(&host->room.lock);
        ttak_mutex_destroy(&host->user_data_lock);
        ttak_mutex_destroy(&host->lock);
        free(host);
    }
}

static session_ctx_t new_session(host_t *host)
{
    session_ctx_t ctx = {0};
    ctx.owner = host;
    snprintf(ctx.user.name, sizeof(ctx.user.name), "%s", "tester");
    return ctx;
}

typedef struct command_output_reader {
    int fd;
    char *output;
    size_t cap;
    size_t used;
} command_output_reader_t;

static void *command_output_drain(void *argument)
{
    command_output_reader_t *reader = argument;
    char discard[4096];
    for (;;) {
        const bool keep = reader->used + 1U < reader->cap;
        void *destination = keep ? reader->output + reader->used : discard;
        const size_t available = keep ? reader->cap - reader->used - 1U
                                      : sizeof(discard);
        ssize_t n = read(reader->fd, destination, available);
        if (n > 0) {
            if (keep) {
                reader->used += (size_t)n;
            }
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return NULL;
}

static bool command_output(session_ctx_t *ctx, const char *command, char *output,
                           size_t cap)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return false;
    }
    command_output_reader_t reader = {
        .fd = fds[0], .output = output, .cap = cap, .used = 0U};
    pthread_t thread;
    if (pthread_create(&thread, NULL, command_output_drain, &reader) != 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    ctx->transport_kind = SESSION_TRANSPORT_TELNET;
    ctx->telnet_fd = fds[1];
    session_dispatch_command(ctx, command);
    close(fds[1]);
    pthread_join(thread, NULL);
    close(fds[0]);
    output[reader.used] = '\0';
    return true;
}

TEST(routes_utf8_and_legacy_codepages_but_keeps_ascii_and_cp437)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    session_ctx_t ctx = new_session(host);
    ctx.multilingual_route_enabled = true;

    chat_history_entry_t stored = {0};
    CHECK(host_history_record_user(host, &ctx, "hi", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_MAIN);
    CHECK(host_history_record_user(host, &ctx, "안녕하세요", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_UTF8);

    ctx.cp437_input_enabled = true;
    ctx.active_codepage = SESSION_CODEPAGE_CP949;
    CHECK(host_history_record_user(host, &ctx, "안녕하세요", false, &stored));
    CHECK_EQ(stored.room_id, (uint8_t)SESSION_CODEPAGE_CP949 + 1U);

    ctx.active_codepage = SESSION_CODEPAGE_CP437;
    CHECK(host_history_record_user(host, &ctx, "£", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_MAIN);

    ctx.multilingual_route_enabled = false;
    ctx.active_codepage = SESSION_CODEPAGE_CP949;
    CHECK(host_history_record_user(host, &ctx, "안녕하세요", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_MAIN);
    ctx.multilingual_route_override = CHAT_ROOM_UTF8;
    ctx.multilingual_route_override_active = true;
    CHECK(host_history_record_user(host, &ctx, "hi", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_UTF8);
    ctx.multilingual_route_override_active = false;

    CHECK(session_chat_room_exists(host, CHAT_ROOM_UTF8));
    CHECK(session_chat_room_exists(host, (uint8_t)SESSION_CODEPAGE_CP949 + 1U));
    CHECK(!session_chat_room_exists(host, CHAT_ROOM_CP437));
    free_host(host);
}

TEST(room_history_and_route_preference_survive_reload)
{
    host_t *writer = new_host();
    CHECK(writer != NULL);
    unlink(writer->state_file_path);
    session_ctx_t ctx = new_session(writer);
    ctx.multilingual_route_enabled = true;
    host_store_multilingual_route(writer, &ctx);

    chat_history_entry_t stored = {0};
    CHECK(host_history_record_user(writer, &ctx, "안녕하세요", false, &stored));
    CHECK_EQ(stored.room_id, CHAT_ROOM_UTF8);
    CHECK_EQ(writer->history[0].room_id, CHAT_ROOM_UTF8);
    ttak_mutex_lock(&writer->lock);
    host_state_save_force_locked(writer);
    ttak_mutex_unlock(&writer->lock);

    FILE *fp = fopen(writer->state_file_path, "rb");
    CHECK(fp != NULL);
    CHECK_EQ(fseek(fp, (long)sizeof(host_state_header_t), SEEK_SET), 0);
    host_state_history_entry_t serialized = {0};
    CHECK_EQ(fread(&serialized, sizeof(serialized), 1U, fp), 1U);
    fclose(fp);
    CHECK_EQ(serialized.reserved[1], CHAT_ROOM_UTF8);

    host_t *reader = new_host();
    CHECK(reader != NULL);
    host_state_load(reader);
    CHECK_EQ(reader->history_count, 1U);
    CHECK_EQ(reader->history[0].room_id, CHAT_ROOM_UTF8);
    CHECK(session_chat_room_exists(reader, CHAT_ROOM_UTF8));
    ttak_mutex_lock(&reader->lock);
    user_preference_t *pref = host_find_preference_locked(reader, "tester", "");
    CHECK(pref != NULL);
    CHECK(pref->multilingual_route_enabled);
    ttak_mutex_unlock(&reader->lock);
    free_host(writer);
    free_host(reader);
}

TEST(room_visibility_and_navigation_follow_created_rooms)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    session_ctx_t sender = new_session(host);
    snprintf(sender.user.name, sizeof(sender.user.name), "%s", "alice");
    sender.multilingual_route_enabled = true;
    chat_history_entry_t stored = {0};
    CHECK(host_history_record_user(host, &sender, "안녕하세요", false, &stored));

    session_ctx_t ctx = new_session(host);
    CHECK(session_should_hide_entry(&ctx, &stored));
    atomic_store(&ctx.current_room, CHAT_ROOM_UTF8);
    CHECK(!session_should_hide_entry(&ctx, &stored));
    atomic_store(&ctx.current_room, CHAT_ROOM_MAIN);

    char output[16384];
    CHECK(command_output(&ctx, "/room list", output, sizeof(output)));
    CHECK(strstr(output, "Available rooms:") != NULL);
    CHECK(strstr(output, "main") != NULL);
    CHECK(strstr(output, "UTF-8") != NULL);
    CHECK(command_output(&ctx, "/room join CP949", output, sizeof(output)));
    CHECK(strstr(output, "Room 'CP949' was not found.") != NULL);
    CHECK(command_output(&ctx, "/room join UTF-8", output, sizeof(output)));
    CHECK_EQ(atomic_load(&ctx.current_room), CHAT_ROOM_UTF8);
    CHECK(strstr(output, "Joined room UTF-8.") != NULL);
    CHECK(strstr(output, "1 unread messages in UTF-8.") != NULL);
    CHECK(command_output(&ctx, "/room", output, sizeof(output)));
    CHECK(strstr(output, "Current room: UTF-8") != NULL);

    CHECK(command_output(&ctx, "/multilingual-route on", output,
                         sizeof(output)));
    CHECK(ctx.multilingual_route_enabled);
    user_preference_t *pref = host_find_preference_locked(host, "tester", "");
    CHECK(pref != NULL);
    CHECK(pref->multilingual_route_enabled);
    CHECK(command_output(&ctx, "/multilingual-route off", output,
                         sizeof(output)));
    CHECK(!ctx.multilingual_route_enabled);
    CHECK(!pref->multilingual_route_enabled);
    free_host(host);
}

TEST(unread_room_tracks_read_cursor_and_room_activity)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    unlink(host->state_file_path);
    session_ctx_t sender = new_session(host);
    snprintf(sender.user.name, sizeof(sender.user.name), "%s", "alice");
    sender.multilingual_route_enabled = true;
    session_ctx_t ctx = new_session(host);
    snprintf(ctx.user.name, sizeof(ctx.user.name), "%s", "reader");

    chat_history_entry_t stored = {0};
    CHECK(host_history_record_user(host, &sender, "hello", false, &stored));
    CHECK(host_history_record_user(host, &sender, "안녕하세요", false, &stored));
    CHECK(host_history_record_user(host, &sender, "reader ping", false, &stored));
    CHECK(host_history_record_user(host, &ctx, "own", false, &stored));
    CHECK(session_user_data_load(&ctx));
    CHECK_EQ(session_unread_current_count(&ctx), 2U);

    char output[65536];
    CHECK(command_output(&ctx, "/room list", output, sizeof(output)));
    CHECK(strstr(output, "* main") != NULL);
    CHECK(strstr(output, "users:") != NULL);
    CHECK(strstr(output, "unread:") != NULL);
    CHECK(strstr(output, "last:") != NULL);
    CHECK(strstr(output, "UTF-8") != NULL);

    CHECK(command_output(&ctx, "/unread", output, sizeof(output)));
    CHECK(strstr(output, "-- Unread messages in main (2) --") != NULL);
    CHECK(strstr(output, "hello") != NULL);
    CHECK(strstr(output, "reader ping") != NULL);
    CHECK(strstr(output, " own") == NULL);
    CHECK_EQ(ctx.user_data.room_read_message_ids[CHAT_ROOM_MAIN], 3U);

    user_data_record_t saved;
    CHECK(user_data_load(host->user_data_root, "reader", nullptr, &saved));
    CHECK_EQ(saved.room_read_message_ids[CHAT_ROOM_MAIN], 3U);
    CHECK(command_output(&ctx, "/unread", output, sizeof(output)));
    CHECK(strstr(output, "No unread messages in main.") != NULL);
    free_host(host);
}

TEST(unread_paging_only_advances_past_displayed_messages)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    unlink(host->state_file_path);
    session_ctx_t sender = new_session(host);
    snprintf(sender.user.name, sizeof(sender.user.name), "%s", "alice");
    session_ctx_t ctx = new_session(host);
    snprintf(ctx.user.name, sizeof(ctx.user.name), "%s", "pager");
    chat_history_entry_t stored = {0};
    for (size_t idx = 1U; idx <= 105U; ++idx) {
        char text[32];
        snprintf(text, sizeof(text), "msg%zu", idx);
        CHECK(host_history_record_user(host, &sender, text, false, &stored));
    }

    char output[131072];
    CHECK(command_output(&ctx, "/unread", output, sizeof(output)));
    CHECK(strstr(output, "Showing the oldest 100 messages.") != NULL);
    CHECK(strstr(output, "msg1") != NULL);
    CHECK(strstr(output, "msg100") != NULL);
    CHECK(strstr(output, "msg101") == NULL);
    CHECK_EQ(ctx.user_data.room_read_message_ids[CHAT_ROOM_MAIN], 100U);

    CHECK(command_output(&ctx, "/unread", output, sizeof(output)));
    CHECK(strstr(output, "-- Unread messages in main (5) --") != NULL);
    CHECK(strstr(output, "msg101") != NULL);
    CHECK(strstr(output, "msg105") != NULL);
    CHECK_EQ(ctx.user_data.room_read_message_ids[CHAT_ROOM_MAIN], stored.message_id);
    free_host(host);
}

TEST(unread_mentions_include_replies_and_private_messages)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    unlink(host->state_file_path);
    session_ctx_t ctx = new_session(host);
    snprintf(ctx.user.name, sizeof(ctx.user.name), "%s", "mention_reader");
    session_ctx_t sender = new_session(host);
    snprintf(sender.user.name, sizeof(sender.user.name), "%s", "alice");

    chat_history_entry_t parent = {0};
    CHECK(host_history_record_user(host, &ctx, "parent", false, &parent));
    chat_history_entry_t mention = {0};
    CHECK(host_history_record_user(host, &sender, "hello mention_reader", false,
                                   &mention));
    chat_reply_entry_t reply = {0};
    reply.parent_message_id = parent.message_id;
    reply.created_at = time(nullptr);
    snprintf(reply.username, sizeof(reply.username), "%s", "alice");
    snprintf(reply.message, sizeof(reply.message), "%s", "answer");
    chat_reply_entry_t stored_reply = {0};
    CHECK(host_replies_commit_entry(host, &reply, &stored_reply));
    session_unread_record_private(&ctx, "alice", "private hello");
    CHECK_EQ(ctx.user_data.unread_pm_count, 1U);

    char output[65536];
    CHECK(command_output(&ctx, "/unread mentions", output, sizeof(output)));
    CHECK(strstr(output, "Unread mentions:") != NULL);
    CHECK(strstr(output, "hello mention_reader") != NULL);
    CHECK(strstr(output, "Unread replies:") != NULL);
    CHECK(strstr(output, "answer") != NULL);
    CHECK(strstr(output, "Unread private messages:") != NULL);
    CHECK(strstr(output, "private hello") != NULL);
    CHECK_EQ(ctx.user_data.unread_pm_count, 0U);
    CHECK(ctx.user_data.mention_read_message_id >= mention.message_id);
    CHECK(ctx.user_data.reply_read_id >= stored_reply.reply_id);

    CHECK(command_output(&ctx, "/unread mentions", output, sizeof(output)));
    CHECK(strstr(output, "No unread mentions, replies, or private messages.") != NULL);
    free_host(host);
}

TEST(detailed_help_is_localized_and_searchable)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    session_ctx_t ctx = new_session(host);
    char output[32768];
    CHECK(command_output(&ctx, "/help reply", output, sizeof(output)));
    CHECK(strstr(output, "Usage: /reply") != NULL);
    CHECK(strstr(output, "Reply to a message or reply.") != NULL);
    CHECK(strstr(output, "Example: /reply 6428b Thanks!") != NULL);
    CHECK(strstr(output, "Related commands: thread, chat, unread") != NULL);

    ctx.ui_language = SESSION_UI_LANGUAGE_KO;
    CHECK(command_output(&ctx, "/help unread", output, sizeof(output)));
    CHECK(strstr(output, "사용법: /unread") != NULL);
    CHECK(strstr(output, "읽은 위치는 저장됩니다.") != NULL);
    CHECK(command_output(&ctx, "/help 답장", output, sizeof(output)));
    CHECK(strstr(output, "사용법: /답장") != NULL);
    CHECK(strstr(output, "메시지 또는 답글에 답장합니다.") != NULL);
    CHECK(command_output(&ctx, "/help missing", output, sizeof(output)));
    CHECK(strstr(output, "도움말이 없습니다") != NULL);
    CHECK(command_output(&ctx, "/help ban", output, sizeof(output)));
    CHECK(strstr(output, "도움말이 없습니다") != NULL);
    free_host(host);
}

TEST(update_command_migrates_records_and_requests_restart)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    host->user_data_ready = user_data_ensure_root(host->user_data_root);
    CHECK(host->user_data_ready);
    volatile sig_atomic_t shutdown_flag = 0;
    host->shutdown_flag = &shutdown_flag;

    user_data_record_t legacy;
    CHECK(user_data_init(&legacy, "legacy", NULL));
    legacy.version = 7U;
    char path[PATH_MAX];
    CHECK(user_data_path_for(host->user_data_root, "legacy", NULL, true, path,
                             sizeof(path)));
    FILE *fp = fopen(path, "wb");
    CHECK(fp != NULL);
    CHECK_EQ(fwrite(&legacy, offsetof(user_data_record_t, room_read_message_ids),
                    1U, fp),
             1U);
    fclose(fp);

    session_ctx_t ctx = new_session(host);
    char output[32768];
    CHECK(command_output(&ctx, "/update", output, sizeof(output)));
    CHECK(strstr(output, "Only operators may update server records.") != NULL);
    CHECK_EQ(shutdown_flag, 0);

    ctx.user.is_operator = true;
    ctx.ui_language = SESSION_UI_LANGUAGE_KO;
    CHECK(command_output(&ctx, "/help 업데이트", output, sizeof(output)));
    CHECK(strstr(output, "사용법: /업데이트") != NULL);
    CHECK(strstr(output, "모든 구식 사용자 레코드를") != NULL);
    CHECK(command_output(&ctx, "/업데이트", output, sizeof(output)));
    CHECK(strstr(output, "레코드 업데이트 완료: 변환 1개") != NULL);
    CHECK(strstr(output, "지금 서버를 재시작합니다.") != NULL);
    CHECK_EQ(shutdown_flag, 1);
    CHECK(host->force_restart_requested);

    user_data_record_t loaded;
    CHECK(user_data_load(host->user_data_root, "legacy", NULL, &loaded));
    CHECK_EQ(loaded.version, 8U);
    free_host(host);
}

static void remove_tree(const char *directory)
{
    DIR *handle = opendir(directory);
    if (handle == NULL) {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(handle)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            remove_tree(path);
        } else {
            unlink(path);
        }
    }
    closedir(handle);
    rmdir(directory);
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-multilingual-test-%ld",
             (long)getpid());
    remove_tree(g_dir);
    mkdir(g_dir, 0700);
    RUN_TEST(routes_utf8_and_legacy_codepages_but_keeps_ascii_and_cp437);
    RUN_TEST(room_history_and_route_preference_survive_reload);
    RUN_TEST(room_visibility_and_navigation_follow_created_rooms);
    RUN_TEST(unread_room_tracks_read_cursor_and_room_activity);
    RUN_TEST(unread_paging_only_advances_past_displayed_messages);
    RUN_TEST(unread_mentions_include_replies_and_private_messages);
    RUN_TEST(detailed_help_is_localized_and_searchable);
    RUN_TEST(update_command_migrates_records_and_requests_restart);
    remove_tree(g_dir);
    return TEST_REPORT();
}
