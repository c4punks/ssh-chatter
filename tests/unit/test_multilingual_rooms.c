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

static bool command_output(session_ctx_t *ctx, const char *command, char *output,
                           size_t cap)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return false;
    }
    ctx->transport_kind = SESSION_TRANSPORT_TELNET;
    ctx->telnet_fd = fds[1];
    session_dispatch_command(ctx, command);
    close(fds[1]);

    size_t used = 0U;
    while (used + 1U < cap) {
        ssize_t n = read(fds[0], output + used, cap - used - 1U);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    close(fds[0]);
    output[used] = '\0';
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

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-multilingual-test-%ld",
             (long)getpid());
    mkdir(g_dir, 0700);
    RUN_TEST(routes_utf8_and_legacy_codepages_but_keeps_ascii_and_cp437);
    RUN_TEST(room_history_and_route_preference_survive_reload);
    RUN_TEST(room_visibility_and_navigation_follow_created_rooms);
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/multilingual-state.dat", g_dir);
    unlink(path);
    rmdir(g_dir);
    return TEST_REPORT();
}
