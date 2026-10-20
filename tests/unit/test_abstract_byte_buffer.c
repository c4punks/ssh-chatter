/**
 * @file test_abstract_byte_buffer.c
 * @desc Unit tests for the header-only abstract_byte_buffer.h: growth,
 *       NUL termination, mapping and copy-out.
 */
#include "ssh_chatter/abstract_byte_buffer.h"

#include "test_harness.h"

TEST(init_is_empty_and_unallocated)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(buffer.storage == NULL);
    CHECK_EQ(buffer.length, 0);
    CHECK_EQ(buffer.capacity, 0);

    sshc_abstract_byte_buffer_view_t view;
    CHECK(!sshc_abstract_byte_buffer_map_cstr(&buffer, &view));
    CHECK(view.data == NULL);
    sshc_abstract_byte_buffer_free(&buffer);
}

TEST(append_and_map_as_c_string)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(sshc_abstract_byte_buffer_append(&buffer, "hello", 5U));
    CHECK(sshc_abstract_byte_buffer_append(&buffer, ", ", 2U));
    CHECK(sshc_abstract_byte_buffer_append(&buffer, "world", 5U));
    CHECK_EQ(buffer.length, 12);
    CHECK_EQ(buffer.capacity, 256);

    sshc_abstract_byte_buffer_view_t view;
    CHECK(sshc_abstract_byte_buffer_map_cstr(&buffer, &view));
    CHECK_STR_EQ(view.data, "hello, world");
    sshc_abstract_byte_buffer_unmap(&view);
    CHECK(view.data == NULL);
    sshc_abstract_byte_buffer_free(&buffer);
    CHECK(buffer.storage == NULL);
    CHECK_EQ(buffer.length, 0);
}

TEST(empty_append_still_terminates)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(sshc_abstract_byte_buffer_append(&buffer, NULL, 0U));
    CHECK_EQ(buffer.length, 0);

    char out[1] = {'x'};
    CHECK(sshc_abstract_byte_buffer_copy_out(&buffer, out, 1U));
    CHECK_EQ(out[0], '\0');
    sshc_abstract_byte_buffer_free(&buffer);
}

TEST(growth_doubles_and_preserves_contents)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);

    char chunk[100];
    for (size_t i = 0U; i < sizeof(chunk); ++i) {
        chunk[i] = (char)('a' + (char)(i % 26U));
    }
    for (int round = 0; round < 10; ++round) {
        CHECK(sshc_abstract_byte_buffer_append(&buffer, chunk, sizeof(chunk)));
    }
    CHECK_EQ(buffer.length, 1000);
    CHECK_EQ(buffer.capacity, 1024);

    char out[1001];
    CHECK(sshc_abstract_byte_buffer_copy_out(&buffer, out, sizeof(out)));
    CHECK_EQ(out[1000], '\0');
    for (size_t i = 0U; i < 1000U; ++i) {
        CHECK_EQ(out[i], chunk[i % sizeof(chunk)]);
    }
    sshc_abstract_byte_buffer_free(&buffer);
}

TEST(copy_out_rejects_overlong_reads)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(sshc_abstract_byte_buffer_append(&buffer, "abc", 3U));

    char out[16];
    CHECK(sshc_abstract_byte_buffer_copy_out(&buffer, out, 4U));
    CHECK_STR_EQ(out, "abc");
    CHECK(!sshc_abstract_byte_buffer_copy_out(&buffer, out, 5U));
    CHECK(!sshc_abstract_byte_buffer_copy_out(NULL, out, 1U));
    CHECK(!sshc_abstract_byte_buffer_copy_out(&buffer, NULL, 1U));
    sshc_abstract_byte_buffer_free(&buffer);
}

TEST(reserve_total_rounds_up_to_power_of_two)
{
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(sshc_abstract_byte_buffer_reserve_total(&buffer, 10U));
    CHECK_EQ(buffer.capacity, 256);
    CHECK(sshc_abstract_byte_buffer_reserve_total(&buffer, 257U));
    CHECK_EQ(buffer.capacity, 512);
    /* Asking for less never shrinks. */
    CHECK(sshc_abstract_byte_buffer_reserve_total(&buffer, 1U));
    CHECK_EQ(buffer.capacity, 512);
    CHECK(!sshc_abstract_byte_buffer_reserve_total(&buffer, SIZE_MAX));
    sshc_abstract_byte_buffer_free(&buffer);
}

TEST(null_arguments_are_rejected)
{
    CHECK(!sshc_abstract_byte_buffer_append(NULL, "x", 1U));
    sshc_abstract_byte_buffer_t buffer;
    sshc_abstract_byte_buffer_init(&buffer);
    CHECK(!sshc_abstract_byte_buffer_append(&buffer, NULL, 1U));
    CHECK(!sshc_abstract_byte_buffer_map_cstr(&buffer, NULL));
    sshc_abstract_byte_buffer_init(NULL);
    sshc_abstract_byte_buffer_free(NULL);
    sshc_abstract_byte_buffer_unmap(NULL);
}

int main(void)
{
    RUN_TEST(init_is_empty_and_unallocated);
    RUN_TEST(append_and_map_as_c_string);
    RUN_TEST(empty_append_still_terminates);
    RUN_TEST(growth_doubles_and_preserves_contents);
    RUN_TEST(copy_out_rejects_overlong_reads);
    RUN_TEST(reserve_total_rounds_up_to_power_of_two);
    RUN_TEST(null_arguments_are_rejected);
    return TEST_REPORT();
}
