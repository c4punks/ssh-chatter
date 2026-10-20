/**
 * @file test_user_data.c
 * @desc Unit tests for src/user_data.c: username sanitizing, ANSI
 *       stripping, reserved-flag accessors, password hashing/verification
 *       and the on-disk save/load round trip (in a private temp directory).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ssh_chatter/host.h"
#include "ssh_chatter/user_data.h"
#include "ssh_chatter/security_layer.h"

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_harness.h"

static char g_root[PATH_MAX];

/* Remove every file and subdirectory created under dir (one level deep). */
static void remove_tree(const char *dir)
{
    DIR *handle = opendir(dir);
    if (handle == NULL) {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(handle)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            remove_tree(path);
        } else {
            unlink(path);
        }
    }
    closedir(handle);
    rmdir(dir);
}

/* Give each storage test an empty, freshly created root directory. */
static void fresh_root(void)
{
    remove_tree(g_root);
    mkdir(g_root, 0700);
}

/* ---- user_data_sanitize_username ---- */

TEST(sanitize_lowercases_and_keeps_safe_punctuation)
{
    char out[64];
    CHECK(user_data_sanitize_username("Alice.B-o_b", out, sizeof(out)));
    CHECK_STR_EQ(out, "alice.b-o_b");
}

TEST(sanitize_drops_spaces_and_replaces_unsafe_bytes)
{
    char out[64];
    CHECK(user_data_sanitize_username("a b/../c!", out, sizeof(out)));
    CHECK_STR_EQ(out, "ab_.._c_");
    /* Path separators can never survive. */
    CHECK(strchr(out, '/') == NULL);
}

TEST(sanitize_falls_back_to_user)
{
    char out[64];
    CHECK(user_data_sanitize_username("   ", out, sizeof(out)));
    CHECK_STR_EQ(out, "user");
    CHECK(!user_data_sanitize_username("", out, sizeof(out)));
    CHECK(!user_data_sanitize_username(NULL, out, sizeof(out)));
}

TEST(sanitize_truncates_to_output_size)
{
    char out[4];
    CHECK(user_data_sanitize_username("abcdefgh", out, sizeof(out)));
    CHECK_STR_EQ(out, "abc");
}

/* ---- user_data_strip_ansi_sequences ---- */

TEST(strip_ansi_removes_csi_osc_and_controls)
{
    char out[128];
    CHECK(user_data_strip_ansi_sequences(
        "\033[1;31mred\033[0m \033]0;title\007ok\033]2;t\033\\!\r\n\tx", out,
        sizeof(out)));
    CHECK_STR_EQ(out, "red ok!\tx");
}

TEST(strip_ansi_truncates_safely)
{
    char out[4];
    CHECK(user_data_strip_ansi_sequences("abcdef", out, sizeof(out)));
    CHECK_STR_EQ(out, "abc");
    CHECK(!user_data_strip_ansi_sequences(NULL, out, sizeof(out)));
    CHECK_STR_EQ(out, "");
}

/* ---- reserved flag accessors ---- */

TEST(reserved_flags_round_trip)
{
    user_data_record_t record;
    memset(&record, 0, sizeof(record));

    CHECK(!user_data_reserved_nickname_is_ip_wide(&record));
    CHECK(!user_data_fixnick_enabled(&record));
    CHECK_EQ(user_data_password_hash_algorithm(&record), USER_DATA_HASH_LEGACY);

    user_data_set_reserved_nickname_ip_wide(&record, true);
    user_data_set_fixnick_enabled(&record, true);
    user_data_set_password_hash_algorithm(&record, USER_DATA_HASH_PBKDF2);
    CHECK_EQ(record.reserved[0], 1);
    CHECK_EQ(record.reserved[1], 1);
    CHECK_EQ(record.reserved[2], USER_DATA_HASH_PBKDF2);
    CHECK(user_data_reserved_nickname_is_ip_wide(&record));
    CHECK(user_data_fixnick_enabled(&record));

    user_data_set_fixnick_enabled(&record, false);
    CHECK(!user_data_fixnick_enabled(&record));
    CHECK(user_data_reserved_nickname_is_ip_wide(&record));
}

TEST(unknown_hash_algorithm_reads_as_legacy)
{
    user_data_record_t record;
    memset(&record, 0, sizeof(record));
    record.reserved[2] = 0x7FU;
    CHECK_EQ(user_data_password_hash_algorithm(&record), USER_DATA_HASH_LEGACY);
    user_data_set_password_hash_algorithm(&record, 0x7FU);
    CHECK_EQ(record.reserved[2], USER_DATA_HASH_LEGACY);
}

TEST(null_record_accessors_are_safe)
{
    CHECK(!user_data_has_password(NULL));
    CHECK(!user_data_reserved_nickname_is_ip_wide(NULL));
    CHECK(!user_data_fixnick_enabled(NULL));
    CHECK_EQ(user_data_password_hash_algorithm(NULL), USER_DATA_HASH_LEGACY);
    user_data_set_fixnick_enabled(NULL, true);
    user_data_set_reserved_nickname_ip_wide(NULL, true);
}

/* ---- user_data_init ---- */

TEST(init_sets_defaults)
{
    user_data_record_t record;
    CHECK(user_data_init(&record, "Alice", "10.0.0.1"));
    CHECK_STR_EQ(record.username, "Alice");
    CHECK_STR_EQ(record.last_ip, "10.0.0.1");
    CHECK_EQ(record.mailbox_count, 0);
    CHECK(!user_data_has_password(&record));
    CHECK(user_data_reserved_nickname_is_ip_wide(&record));
    CHECK_EQ(user_data_password_hash_algorithm(&record), USER_DATA_HASH_PBKDF2);
    CHECK(record.alpha.fuel_percent == 100.0);
}

/* ---- passwords ---- */

TEST(upgrade_then_verify_password)
{
    user_data_record_t record;
    CHECK(user_data_init(&record, "bob", NULL));

    user_data_upgrade_password_hash(&record, "hunter2");
    CHECK(user_data_has_password(&record));
    CHECK_EQ(user_data_password_hash_algorithm(&record), USER_DATA_HASH_PBKDF2);

    bool was_legacy = true;
    CHECK(user_data_verify_password(&record, "hunter2", &was_legacy));
    CHECK(!was_legacy);
    CHECK(!user_data_verify_password(&record, "hunter3", NULL));
    CHECK(!user_data_verify_password(&record, "", NULL));
}

TEST(upgrade_with_empty_password_is_noop)
{
    user_data_record_t record;
    CHECK(user_data_init(&record, "bob", NULL));
    user_data_upgrade_password_hash(&record, "");
    CHECK(!user_data_has_password(&record));
}

TEST(legacy_hash_verifies_and_reports_legacy)
{
    user_data_record_t record;
    CHECK(user_data_init(&record, "carol", NULL));
    user_data_set_password_hash_algorithm(&record, USER_DATA_HASH_LEGACY);
    security_layer_hash_password("pw", record.password_salt,
                                 record.password_hash);

    bool was_legacy = false;
    CHECK(user_data_verify_password(&record, "pw", &was_legacy));
    CHECK(was_legacy);
}

/* ---- server config accessors ---- */

TEST(ssh_chat_server_config_round_trip)
{
    user_data_record_t record;
    CHECK(user_data_init(&record, "dave", NULL));
    user_data_set_ssh_chat_server_config(&record, "chat.example.org", 2022U);

    char url[SSH_CHAT_SERVER_URL_LEN];
    uint16_t port = 0U;
    user_data_get_ssh_chat_server_config(&record, url, sizeof(url), &port);
    CHECK_STR_EQ(url, "chat.example.org");
    CHECK_EQ(port, 2022);
}

/* ---- on-disk storage ---- */

TEST(save_then_load_round_trips_fields)
{
    fresh_root();
    CHECK(user_data_ensure_root(g_root));

    user_data_record_t record;
    CHECK(user_data_init(&record, "Eve", "192.0.2.5"));
    snprintf(record.preferred_nickname, sizeof(record.preferred_nickname),
             "%s", "evie");
    record.mailbox_count = 1U;
    record.mailbox[0].timestamp = 1234U;
    snprintf(record.mailbox[0].sender, sizeof(record.mailbox[0].sender), "%s",
             "frank");
    snprintf(record.mailbox[0].message, sizeof(record.mailbox[0].message),
             "%s", "hello there");
    record.flag_count = 3U;
    user_data_set_fixnick_enabled(&record, true);
    user_data_upgrade_password_hash(&record, "secret");
    CHECK(user_data_save(g_root, &record, "192.0.2.5"));

    user_data_record_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    CHECK(user_data_load(g_root, "Eve", "192.0.2.5", &loaded));
    CHECK_STR_EQ(loaded.username, "Eve");
    CHECK_STR_EQ(loaded.preferred_nickname, "evie");
    CHECK_EQ(loaded.mailbox_count, 1);
    CHECK_EQ(loaded.mailbox[0].timestamp, 1234);
    CHECK_STR_EQ(loaded.mailbox[0].sender, "frank");
    CHECK_STR_EQ(loaded.mailbox[0].message, "hello there");
    CHECK_EQ(loaded.flag_count, 3);
    CHECK(user_data_fixnick_enabled(&loaded));
    CHECK(user_data_verify_password(&loaded, "secret", NULL));
}

TEST(load_missing_user_fails)
{
    fresh_root();
    CHECK(user_data_ensure_root(g_root));

    user_data_record_t loaded;
    CHECK(!user_data_load(g_root, "nobody", "192.0.2.9", &loaded));
}

TEST(ensure_exists_creates_then_reuses_record)
{
    fresh_root();

    user_data_record_t first;
    CHECK(user_data_ensure_exists(g_root, "grace", "198.51.100.1", &first));
    CHECK_STR_EQ(first.username, "grace");

    first.flag_count = 9U;
    CHECK(user_data_save(g_root, &first, "198.51.100.1"));

    user_data_record_t second;
    CHECK(user_data_ensure_exists(g_root, "grace", "198.51.100.1", &second));
    CHECK_EQ(second.flag_count, 9);
}

TEST(path_for_stays_inside_root)
{
    fresh_root();
    CHECK(user_data_ensure_root(g_root));

    char path[PATH_MAX];
    CHECK(user_data_path_for(g_root, "../../etc/passwd", "203.0.113.4", true,
                             path, sizeof(path)));
    CHECK(strncmp(path, g_root, strlen(g_root)) == 0);
    /* Everything after "<root>/" must be a single path component. */
    CHECK(strchr(path + strlen(g_root) + 1U, '/') == NULL);
}

TEST(load_rejects_corrupt_file)
{
    fresh_root();
    CHECK(user_data_ensure_root(g_root));

    char path[PATH_MAX];
    CHECK(user_data_path_for(g_root, "mallory", NULL, true, path,
                             sizeof(path)));
    FILE *fp = fopen(path, "wb");
    CHECK(fp != NULL);
    fputs("definitely not a user record", fp);
    fclose(fp);

    user_data_record_t loaded;
    CHECK(!user_data_load(g_root, "mallory", NULL, &loaded));
}

int main(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/sshc-user-data-test-%ld",
             (long)getpid());

    RUN_TEST(sanitize_lowercases_and_keeps_safe_punctuation);
    RUN_TEST(sanitize_drops_spaces_and_replaces_unsafe_bytes);
    RUN_TEST(sanitize_falls_back_to_user);
    RUN_TEST(sanitize_truncates_to_output_size);
    RUN_TEST(strip_ansi_removes_csi_osc_and_controls);
    RUN_TEST(strip_ansi_truncates_safely);
    RUN_TEST(reserved_flags_round_trip);
    RUN_TEST(unknown_hash_algorithm_reads_as_legacy);
    RUN_TEST(null_record_accessors_are_safe);
    RUN_TEST(init_sets_defaults);
    RUN_TEST(upgrade_then_verify_password);
    RUN_TEST(upgrade_with_empty_password_is_noop);
    RUN_TEST(legacy_hash_verifies_and_reports_legacy);
    RUN_TEST(ssh_chat_server_config_round_trip);
    RUN_TEST(save_then_load_round_trips_fields);
    RUN_TEST(load_missing_user_fails);
    RUN_TEST(ensure_exists_creates_then_reuses_record);
    RUN_TEST(path_for_stays_inside_root);
    RUN_TEST(load_rejects_corrupt_file);

    remove_tree(g_root);
    return TEST_REPORT();
}
