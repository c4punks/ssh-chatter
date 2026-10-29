/**
 * @file test_host_persistence.c
 * @desc Regression tests for host state files whose load/save helpers are
 *       static inside the host aggregate. The aggregate is #included so the
 *       tests can call those helpers directly on a zeroed host_t.
 *
 *       Covered:
 *       - /wall canvas survives a save/load cycle (it used to write only
 *         pointer-size bytes of the grid).
 *       - A state file with more preference records than
 *         SSH_CHATTER_MAX_PREFERENCES still loads the grant section that
 *         follows them from the right offset.
 */
#include "../../src/host_aggregate.c"

#include <unistd.h>

#include "test_harness.h"

static char g_dir[PATH_MAX];

static host_t *new_host(void)
{
    host_t *host = calloc(1U, sizeof(*host));
    if (host != NULL) {
        ttak_mutex_init(&host->lock);
    }
    return host;
}

static void free_host(host_t *host)
{
    if (host != NULL) {
        ttak_mutex_destroy(&host->lock);
        free(host);
    }
}

/* ---- wall ---- */

TEST(wall_round_trips_through_disk)
{
    host_t *writer = new_host();
    CHECK(writer != NULL);
    snprintf(writer->wall_state_file_path,
             sizeof(writer->wall_state_file_path), "%s/wall.dat", g_dir);
    host_wall_reset_locked(writer);

    ascii_pixel_t *first = &writer->wall[0];
    first->ch = 'A';
    snprintf(first->color_name, sizeof(first->color_name), "%s", "red");
    first->updated_at_ns = 42;

    size_t last_index = SSH_CHATTER_WALL_HEIGHT * SSH_CHATTER_WALL_WIDTH - 1U;
    ascii_pixel_t *last = &writer->wall[last_index];
    last->ch = 'Z';
    snprintf(last->color_name, sizeof(last->color_name), "%s", "blue");
    host_wall_state_save_locked(writer);

    struct stat st;
    CHECK(stat(writer->wall_state_file_path, &st) == 0);
    CHECK_EQ(st.st_size,
             sizeof(wall_state_header_t) + SSH_CHATTER_WALL_HEIGHT *
                                               SSH_CHATTER_WALL_WIDTH *
                                               sizeof(ascii_pixel_t));

    host_t *reader = new_host();
    CHECK(reader != NULL);
    snprintf(reader->wall_state_file_path,
             sizeof(reader->wall_state_file_path), "%s",
             writer->wall_state_file_path);
    host_wall_state_load(reader);

    CHECK_EQ(reader->wall[0].ch, 'A');
    CHECK_STR_EQ(reader->wall[0].color_name, "red");
    CHECK_EQ(reader->wall[0].updated_at_ns, 42);
    CHECK_EQ(reader->wall[last_index].ch, 'Z');
    CHECK_STR_EQ(reader->wall[last_index].color_name, "blue");
    CHECK_EQ(reader->wall[1].ch, ' ');
    CHECK_STR_EQ(reader->wall[1].color_name, "default");

    unlink(writer->wall_state_file_path);
    free_host(writer);
    free_host(reader);
}

TEST(wall_load_sanitizes_untrusted_cells)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    snprintf(host->wall_state_file_path, sizeof(host->wall_state_file_path),
             "%s/wall-bad.dat", g_dir);
    host_wall_reset_locked(host);
    host->wall[0].ch = '\033';
    memset(host->wall[1].color_name, 'x', sizeof(host->wall[1].color_name));
    host->wall[2].updated_at_ns = -5;
    host_wall_state_save_locked(host);

    host_wall_reset_locked(host);
    host_wall_state_load(host);
    CHECK_EQ(host->wall[0].ch, ' ');
    CHECK_EQ(strlen(host->wall[1].color_name),
             sizeof(host->wall[1].color_name) - 1U);
    CHECK_EQ(host->wall[2].updated_at_ns, 0);

    unlink(host->wall_state_file_path);
    free_host(host);
}

TEST(wall_load_ignores_mismatched_header)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    snprintf(host->wall_state_file_path, sizeof(host->wall_state_file_path),
             "%s/wall-foreign.dat", g_dir);

    FILE *fp = fopen(host->wall_state_file_path, "wb");
    CHECK(fp != NULL);
    wall_state_header_t header = {
        .magic = WALL_STATE_MAGIC,
        .version = WALL_STATE_VERSION,
        .width = SSH_CHATTER_WALL_WIDTH + 1U,
        .height = SSH_CHATTER_WALL_HEIGHT,
    };
    fwrite(&header, sizeof(header), 1U, fp);
    fclose(fp);

    host_wall_state_load(host);
    CHECK(host->wall != NULL);
    CHECK_EQ(host->wall[0].ch, ' ');

    unlink(host->wall_state_file_path);
    free_host(host);
}

/* ---- main state file ---- */

TEST(state_load_reads_grants_after_surplus_preferences)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    host_preferences_ensure(host);
    host_operator_grants_ensure(host);
    snprintf(host->state_file_path, sizeof(host->state_file_path),
             "%s/state.dat", g_dir);

    const uint32_t preference_count = SSH_CHATTER_MAX_PREFERENCES + 3U;
    FILE *fp = fopen(host->state_file_path, "wb");
    CHECK(fp != NULL);

    host_state_header_t header = {0};
    header.base.magic = HOST_STATE_MAGIC;
    header.base.version = HOST_STATE_VERSION;
    header.base.history_count = 0U;
    header.base.preference_count = preference_count;
    header.grant_count = 1U;
    header.next_message_id = 1U;
    CHECK(fwrite(&header, sizeof(header), 1U, fp) == 1U);

    static host_state_preference_entry_t pref;
    for (uint32_t idx = 0U; idx < preference_count; ++idx) {
        memset(&pref, 0, sizeof(pref));
        snprintf(pref.username, sizeof(pref.username), "user%u", idx);
        CHECK(fwrite(&pref, sizeof(pref), 1U, fp) == 1U);
    }

    host_state_grant_entry_t grant = {0};
    snprintf(grant.ip, sizeof(grant.ip), "%s", "203.0.113.7");
    CHECK(fwrite(&grant, sizeof(grant), 1U, fp) == 1U);
    fclose(fp);

    host_state_load(host);

    CHECK_EQ(host->preference_count, SSH_CHATTER_MAX_PREFERENCES);
    CHECK_STR_EQ(host->preferences[0].username, "user0");
    CHECK_EQ(host->operator_grant_count, 1);
    CHECK_STR_EQ(host->operator_grants[0].ip, "203.0.113.7");

    unlink(host->state_file_path);
    free_host(host);
}

/* ---- BBS reply threads sidecar ---- */

static host_t *new_bbs_host(void)
{
    host_t *host = new_host();
    if (host == NULL) {
        return NULL;
    }
    host->bbs_post_capacity = 2U;
    host->bbs_posts = calloc(host->bbs_post_capacity, sizeof(bbs_post_t));
    for (size_t idx = 0U; idx < host->bbs_post_capacity; ++idx) {
        host->bbs_posts[idx].comments =
            calloc(SSH_CHATTER_BBS_MAX_COMMENTS, sizeof(bbs_comment_t));
    }
    snprintf(host->bbs_state_file_path, sizeof(host->bbs_state_file_path),
             "%s/bbs_state.dat", g_dir);
    return host;
}

static void free_bbs_host(host_t *host)
{
    for (size_t idx = 0U; idx < host->bbs_post_capacity; ++idx) {
        free(host->bbs_posts[idx].comments);
    }
    free(host->bbs_posts);
    free_host(host);
}

static void seed_post(host_t *host, size_t count)
{
    bbs_post_t *post = &host->bbs_posts[0];
    post->in_use = true;
    post->id = 7U;
    post->comment_count = count;
    host->bbs_post_count = 1U;
    for (size_t idx = 0U; idx < count; ++idx) {
        post->comments[idx].created_at = (time_t)(1000 + idx);
    }
}

TEST(bbs_threads_round_trip)
{
    host_t *writer = new_bbs_host();
    CHECK(writer != NULL);
    seed_post(writer, 4U);
    writer->bbs_posts[0].comments[1].parent_ref = 1;
    writer->bbs_posts[0].comments[3].parent_ref = 2;
    host_bbs_threads_save_locked(writer);

    host_t *reader = new_bbs_host();
    CHECK(reader != NULL);
    seed_post(reader, 4U);
    reader->bbs_posts[0].comments[2].parent_ref = 9; /* stale, must clear */
    host_bbs_threads_load(reader);
    CHECK_EQ(reader->bbs_posts[0].comments[0].parent_ref, 0);
    CHECK_EQ(reader->bbs_posts[0].comments[1].parent_ref, 1);
    CHECK_EQ(reader->bbs_posts[0].comments[2].parent_ref, 0);
    CHECK_EQ(reader->bbs_posts[0].comments[3].parent_ref, 2);

    char path[PATH_MAX];
    host_bbs_v2_path(writer->bbs_state_file_path, "threads.dat", path,
                     sizeof(path));
    unlink(path);
    free_bbs_host(writer);
    free_bbs_host(reader);
}

TEST(bbs_threads_follow_shifted_comments)
{
    /* Sidecar written with 1 -> 0 and 3 -> 2, then comment 0 vanished from
     * the main state: 3 -> 2 lands on the shifted slots, 1 -> 0 is dropped. */
    host_t *writer = new_bbs_host();
    CHECK(writer != NULL);
    seed_post(writer, 4U);
    writer->bbs_posts[0].comments[1].parent_ref = 1;
    writer->bbs_posts[0].comments[3].parent_ref = 3;
    host_bbs_threads_save_locked(writer);

    host_t *reader = new_bbs_host();
    CHECK(reader != NULL);
    seed_post(reader, 3U);
    for (size_t idx = 0U; idx < 3U; ++idx) {
        reader->bbs_posts[0].comments[idx].created_at = (time_t)(1001 + idx);
    }
    host_bbs_threads_load(reader);
    CHECK_EQ(reader->bbs_posts[0].comments[0].parent_ref, 0);
    CHECK_EQ(reader->bbs_posts[0].comments[1].parent_ref, 0);
    CHECK_EQ(reader->bbs_posts[0].comments[2].parent_ref, 2);

    char path[PATH_MAX];
    host_bbs_v2_path(writer->bbs_state_file_path, "threads.dat", path,
                     sizeof(path));
    unlink(path);
    free_bbs_host(writer);
    free_bbs_host(reader);
}

/* ---- session_is_password_command ---- */

TEST(login_is_password_command_masking)
{
    CHECK(!session_is_password_command(NULL));
    CHECK(!session_is_password_command(""));
    CHECK(!session_is_password_command("/login"));
    CHECK(session_is_password_command("/login "));
    CHECK(session_is_password_command("/login  "));
    CHECK(session_is_password_command("/login secret"));
    CHECK(session_is_password_command("/LOGIN secret"));
    CHECK(session_is_password_command("  /login secret"));
    CHECK(session_is_password_command("\t/login secret"));
    CHECK(session_is_password_command("/login\tsecret"));
    CHECK(session_is_password_command("/signup secret"));
    CHECK(session_is_password_command("/SIGNUP 12345"));

    /* Non-password commands should not mask */
    CHECK(!session_is_password_command("/guest"));
    CHECK(!session_is_password_command("/guest pass"));
    CHECK(!session_is_password_command("/exit"));
    CHECK(!session_is_password_command("/loginsomething"));
    CHECK(!session_is_password_command("/signupp"));
}

TEST(private_data_path_tightens_open_file_and_directory)
{
    host_t *host = new_host();
    CHECK(host != NULL);

    char directory[PATH_MAX];
    snprintf(directory, sizeof(directory), "%s/private", g_dir);
    CHECK(mkdir(directory, 0700) == 0);
    CHECK(chmod(directory, 0777) == 0);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/state.dat", directory);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(chmod(path, 0666) == 0);

    CHECK(host_ensure_private_data_path(host, path, false));

    struct stat st;
    CHECK(stat(directory, &st) == 0);
    CHECK_EQ((int)(st.st_mode & (S_IWGRP | S_IWOTH)), 0);
    CHECK(stat(path, &st) == 0);
    CHECK_EQ((int)(st.st_mode & 0777), 0600);

    unlink(path);
    rmdir(directory);
    free_host(host);
}

TEST(archive_append_creates_then_reopens_same_file)
{
    host_t *host = new_host();
    CHECK(host != NULL);
    snprintf(host->state_file_path, sizeof(host->state_file_path), "%s/state.dat",
             g_dir);
    atomic_store(&host->chat_archive_enabled, true);

    chat_history_entry_t entry = {0};
    entry.created_at = 0;
    entry.is_user_message = true;
    snprintf(entry.username, sizeof(entry.username), "%s", "alice");
    snprintf(entry.message, sizeof(entry.message), "%s", "first");
    CHECK(host_archive_append_entry(host, &entry));
    snprintf(entry.message, sizeof(entry.message), "%s", "second");
    CHECK(host_archive_append_entry(host, &entry));

    char path[PATH_MAX];
    CHECK(host_archive_resolve_path(host, entry.created_at, path, sizeof(path)));
    FILE *fp = fopen(path, "rb");
    CHECK(fp != NULL);
    host_state_header_t header = {0};
    CHECK(fread(&header, sizeof(header), 1U, fp) == 1U);
    CHECK_EQ(header.base.history_count, 2U);
    fclose(fp);

    struct stat st;
    CHECK(stat(path, &st) == 0);
    CHECK_EQ((int)(st.st_mode & 0777), 0600);

    unlink(path);
    free_host(host);
}

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-persistence-test-%ld",
             (long)getpid());
    mkdir(g_dir, 0700);

    RUN_TEST(wall_round_trips_through_disk);
    RUN_TEST(wall_load_sanitizes_untrusted_cells);
    RUN_TEST(wall_load_ignores_mismatched_header);
    RUN_TEST(state_load_reads_grants_after_surplus_preferences);
    RUN_TEST(bbs_threads_round_trip);
    RUN_TEST(bbs_threads_follow_shifted_comments);
    RUN_TEST(login_is_password_command_masking);
    RUN_TEST(private_data_path_tightens_open_file_and_directory);
    RUN_TEST(archive_append_creates_then_reopens_same_file);

    rmdir(g_dir);
    return TEST_REPORT();
}
