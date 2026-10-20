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

int main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/sshc-persistence-test-%ld",
             (long)getpid());
    mkdir(g_dir, 0700);

    RUN_TEST(wall_round_trips_through_disk);
    RUN_TEST(wall_load_sanitizes_untrusted_cells);
    RUN_TEST(wall_load_ignores_mismatched_header);
    RUN_TEST(state_load_reads_grants_after_surplus_preferences);

    rmdir(g_dir);
    return TEST_REPORT();
}
