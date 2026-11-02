#include "../internal.h"

#define SESSION_UNREAD_DISPLAY_LIMIT 100U

typedef struct session_room_activity {
    bool exists;
    size_t users;
    size_t unread;
    time_t last_activity;
} session_room_activity_t;

static uint64_t session_unread_room_cursor(const session_ctx_t *ctx,
                                           uint8_t room_id)
{
    if (ctx == nullptr || !ctx->user_data_loaded ||
        room_id > CHAT_ROOM_MAX_ID || room_id >= USER_DATA_ROOM_LIMIT) {
        return 0U;
    }
    return ctx->user_data.room_read_message_ids[room_id];
}

static bool session_unread_entry_is_self(const session_ctx_t *ctx,
                                         const chat_history_entry_t *entry)
{
    if (ctx == nullptr || entry == nullptr) {
        return false;
    }
    return strcasecmp(entry->username, ctx->user.name) == 0 ||
           (entry->raw_username[0] != '\0' &&
            strcasecmp(entry->raw_username, ctx->user.name) == 0);
}

void session_unread_note_entry(session_ctx_t *ctx,
                                      const chat_history_entry_t *entry)
{
    if (ctx == nullptr || entry == nullptr || !ctx->user_data_loaded ||
        !entry->is_user_message || entry->message_id == 0U) {
        return;
    }
    const uint8_t room_id = atomic_load(&ctx->current_room);
    if (entry->room_id != room_id || room_id > CHAT_ROOM_MAX_ID ||
        room_id >= USER_DATA_ROOM_LIMIT) {
        return;
    }
    uint64_t *cursor = &ctx->user_data.room_read_message_ids[room_id];
    if (entry->message_id > *cursor) {
        *cursor = entry->message_id;
    }
}

void session_unread_persist(session_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }
    host_t *host = ctx->owner;
    const bool locked = host->user_data_lock_initialized;
    if (locked) {
        ttak_mutex_lock(&host->user_data_lock);
    }
    if (session_user_data_load(ctx)) {
        (void)user_data_save(host->user_data_root, &ctx->user_data,
                             ctx->client_ip);
    }
    if (locked) {
        ttak_mutex_unlock(&host->user_data_lock);
    }
}

static size_t session_unread_scan_room(session_ctx_t *ctx, uint8_t room_id,
                                       time_t *last_activity,
                                       uint64_t *latest_message_id)
{
    size_t unread = 0U;
    if (last_activity != nullptr) {
        *last_activity = (time_t)0;
    }
    if (latest_message_id != nullptr) {
        *latest_message_id = 0U;
    }
    if (ctx == nullptr || ctx->owner == nullptr ||
        !session_chat_room_is_valid(room_id)) {
        return 0U;
    }

    const uint64_t cursor = session_unread_room_cursor(ctx, room_id);
    const size_t total = host_history_total(ctx->owner);
    size_t index = 0U;
    while (index < total) {
        chat_history_entry_t batch[64];
        size_t count = total - index;
        if (count > sizeof(batch) / sizeof(batch[0])) {
            count = sizeof(batch) / sizeof(batch[0]);
        }
        const size_t copied =
            host_history_copy_range(ctx->owner, index, batch, count);
        if (copied == 0U) {
            break;
        }
        for (size_t idx = 0U; idx < copied; ++idx) {
            const chat_history_entry_t *entry = &batch[idx];
            if (entry->room_id != room_id ||
                chat_history_entry_is_empty(entry)) {
                continue;
            }
            if (last_activity != nullptr && entry->created_at > *last_activity) {
                *last_activity = entry->created_at;
            }
            if (!entry->is_user_message || entry->message_id == 0U) {
                continue;
            }
            if (latest_message_id != nullptr &&
                entry->message_id > *latest_message_id) {
                *latest_message_id = entry->message_id;
            }
            if (entry->message_id > cursor &&
                !session_unread_entry_is_self(ctx, entry)) {
                ++unread;
            }
        }
        index += copied;
    }
    return unread;
}

static size_t session_unread_current_count(session_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return 0U;
    }
    return session_unread_scan_room(ctx, atomic_load(&ctx->current_room),
                                    nullptr, nullptr);
}

void session_unread_announce(session_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->owner == nullptr || !session_user_data_load(ctx)) {
        return;
    }
    const uint8_t room_id = atomic_load(&ctx->current_room);
    const size_t unread = session_unread_current_count(ctx);
    if (unread == 0U) {
        return;
    }
    const char *room_name = session_chat_room_name(room_id);
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    session_command_snprintf(ctx, message, sizeof(message),
                             "%zu unread messages in %s. Use /unread to catch up.",
                             unread, room_name != nullptr ? room_name : "main");
    session_send_system_line(ctx, message);
}

void session_unread_record_private(session_ctx_t *recipient,
                                          const char *sender,
                                          const char *message)
{
    if (recipient == nullptr || recipient->owner == nullptr || sender == nullptr ||
        sender[0] == '\0' || message == nullptr || message[0] == '\0' ||
        strcasecmp(recipient->user.name, sender) == 0) {
        return;
    }

    host_t *host = recipient->owner;
    const bool locked = host->user_data_lock_initialized;
    if (locked) {
        ttak_mutex_lock(&host->user_data_lock);
    }
    if (session_user_data_load(recipient)) {
        user_data_record_t *record = &recipient->user_data;
        if (record->unread_pm_count >= USER_DATA_UNREAD_PM_LIMIT) {
            memmove(&record->unread_pms[0], &record->unread_pms[1],
                    (USER_DATA_UNREAD_PM_LIMIT - 1U) *
                        sizeof(record->unread_pms[0]));
            record->unread_pm_count = USER_DATA_UNREAD_PM_LIMIT - 1U;
        }
        user_data_unread_pm_entry_t *entry =
            &record->unread_pms[record->unread_pm_count++];
        memset(entry, 0, sizeof(*entry));
        entry->timestamp = (uint64_t)time(nullptr);
        snprintf(entry->sender, sizeof(entry->sender), "%s", sender);
        snprintf(entry->message, sizeof(entry->message), "%s", message);
        (void)user_data_save(host->user_data_root, record, recipient->client_ip);
    }
    if (locked) {
        ttak_mutex_unlock(&host->user_data_lock);
    }
}

void session_unread_format_age(session_ctx_t *ctx, time_t timestamp,
                                      char *buffer, size_t length)
{
    if (buffer == nullptr || length == 0U) {
        return;
    }
    if (timestamp <= (time_t)0) {
        snprintf(buffer, length, "%s", session_command_localize(ctx, "never"));
        return;
    }
    time_t now = time(nullptr);
    int64_t seconds = now > timestamp ? (int64_t)(now - timestamp) : 0;
    if (seconds < 60) {
        snprintf(buffer, length, "%s", session_command_localize(ctx, "now"));
        return;
    }
    if (seconds < 3600) {
        session_command_snprintf(ctx, buffer, length, "%lldm",
                                 (long long)(seconds / 60));
        return;
    }
    if (seconds < 86400) {
        session_command_snprintf(ctx, buffer, length, "%lldh",
                                 (long long)(seconds / 3600));
        return;
    }
    session_command_snprintf(ctx, buffer, length, "%lldd",
                             (long long)(seconds / 86400));
}

void session_unread_print_rooms(session_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->owner == nullptr || !session_user_data_load(ctx)) {
        return;
    }

    session_room_activity_t activity[USER_DATA_ROOM_LIMIT] = {0};
    activity[CHAT_ROOM_MAIN].exists = true;
    ttak_mutex_lock(&ctx->owner->room.lock);
    for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
        const session_ctx_t *member = ctx->owner->room.members[idx];
        if (member == nullptr) {
            continue;
        }
        const uint8_t room_id = atomic_load(&member->current_room);
        if (room_id < USER_DATA_ROOM_LIMIT && session_chat_room_is_valid(room_id)) {
            activity[room_id].exists = true;
            ++activity[room_id].users;
        }
    }
    ttak_mutex_unlock(&ctx->owner->room.lock);

    const size_t total = host_history_total(ctx->owner);
    size_t index = 0U;
    while (index < total) {
        chat_history_entry_t batch[64];
        size_t count = total - index;
        if (count > sizeof(batch) / sizeof(batch[0])) {
            count = sizeof(batch) / sizeof(batch[0]);
        }
        const size_t copied =
            host_history_copy_range(ctx->owner, index, batch, count);
        if (copied == 0U) {
            break;
        }
        for (size_t idx = 0U; idx < copied; ++idx) {
            const chat_history_entry_t *entry = &batch[idx];
            const uint8_t room_id = entry->room_id;
            if (room_id >= USER_DATA_ROOM_LIMIT ||
                !session_chat_room_is_valid(room_id) ||
                chat_history_entry_is_empty(entry)) {
                continue;
            }
            session_room_activity_t *room = &activity[room_id];
            room->exists = true;
            if (entry->created_at > room->last_activity) {
                room->last_activity = entry->created_at;
            }
            if (entry->is_user_message && entry->message_id >
                                               session_unread_room_cursor(ctx, room_id) &&
                !session_unread_entry_is_self(ctx, entry)) {
                ++room->unread;
            }
        }
        index += copied;
    }

    session_send_system_line(ctx,
                             session_command_localize(ctx, "Available rooms:"));
    const uint8_t current_room = atomic_load(&ctx->current_room);
    for (uint8_t room_id = CHAT_ROOM_MAIN; room_id <= CHAT_ROOM_MAX_ID; ++room_id) {
        if (!session_chat_room_is_valid(room_id) || !activity[room_id].exists) {
            continue;
        }
        const char *name = session_chat_room_name(room_id);
        char age[64];
        session_unread_format_age(ctx, activity[room_id].last_activity, age,
                                  sizeof(age));
        char line[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, line, sizeof(line),
                                 "%c %s (users: %zu, unread: %zu, last: %s)",
                                 room_id == current_room ? '*' : ' ', name,
                                 activity[room_id].users, activity[room_id].unread,
                                 age);
        session_send_system_line(ctx, line);
    }
}

void session_unread_show_room(session_ctx_t *ctx)
{
    const uint8_t room_id = atomic_load(&ctx->current_room);
    const char *room_name = session_chat_room_name(room_id);
    if (room_name == nullptr) {
        room_name = "main";
    }
    const uint64_t cursor = session_unread_room_cursor(ctx, room_id);
    const size_t total = host_history_total(ctx->owner);
    size_t unread = 0U;

    size_t index = 0U;
    while (index < total) {
        chat_history_entry_t batch[64];
        size_t count = total - index;
        if (count > sizeof(batch) / sizeof(batch[0])) {
            count = sizeof(batch) / sizeof(batch[0]);
        }
        const size_t copied =
            host_history_copy_range(ctx->owner, index, batch, count);
        if (copied == 0U) {
            break;
        }
        for (size_t idx = 0U; idx < copied; ++idx) {
            const chat_history_entry_t *entry = &batch[idx];
            if (entry->room_id == room_id && entry->is_user_message &&
                entry->message_id > cursor &&
                !session_unread_entry_is_self(ctx, entry) &&
                !session_should_hide_entry(ctx, entry)) {
                ++unread;
            }
        }
        index += copied;
    }

    if (unread == 0U) {
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, message, sizeof(message),
                                 "No unread messages in %s.", room_name);
        session_send_system_line(ctx, message);
        return;
    }

    char header[SSH_CHATTER_MESSAGE_LIMIT];
    session_command_snprintf(ctx, header, sizeof(header),
                             "-- Unread messages in %s (%zu) --", room_name,
                             unread);
    session_send_system_line(ctx, header);
    if (unread > SESSION_UNREAD_DISPLAY_LIMIT) {
        char notice[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, notice, sizeof(notice),
                                 "Showing the oldest %u messages.",
                                 (unsigned int)SESSION_UNREAD_DISPLAY_LIMIT);
        session_send_system_line(ctx, notice);
    }

    size_t displayed = 0U;
    uint64_t last_displayed_id = cursor;
    index = 0U;
    while (index < total && displayed < SESSION_UNREAD_DISPLAY_LIMIT) {
        chat_history_entry_t batch[64];
        size_t count = total - index;
        if (count > sizeof(batch) / sizeof(batch[0])) {
            count = sizeof(batch) / sizeof(batch[0]);
        }
        const size_t copied =
            host_history_copy_range(ctx->owner, index, batch, count);
        if (copied == 0U) {
            break;
        }
        for (size_t idx = 0U;
             idx < copied && displayed < SESSION_UNREAD_DISPLAY_LIMIT; ++idx) {
            const chat_history_entry_t *entry = &batch[idx];
            if (entry->room_id != room_id || !entry->is_user_message ||
                entry->message_id <= cursor ||
                session_unread_entry_is_self(ctx, entry) ||
                session_should_hide_entry(ctx, entry)) {
                continue;
            }
            session_send_history_entry(ctx, entry);
            ++displayed;
            last_displayed_id = entry->message_id;
        }
        index += copied;
    }

    if (!ctx->should_exit && last_displayed_id > cursor &&
        room_id < USER_DATA_ROOM_LIMIT) {
        ctx->user_data.room_read_message_ids[room_id] = last_displayed_id;
        session_unread_persist(ctx);
    }
    session_refresh_input_line(ctx);
}

static bool session_unread_name_char(unsigned char ch)
{
    return ch >= 0x80U || isalnum(ch) || ch == '_';
}

static bool session_unread_text_mentions(const char *text, const char *name)
{
    if (text == nullptr || name == nullptr || name[0] == '\0') {
        return false;
    }
    const size_t name_length = strlen(name);
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (strncasecmp(cursor, name, name_length) != 0) {
            continue;
        }
        const unsigned char before =
            cursor == text ? 0U : (unsigned char)cursor[-1];
        const unsigned char after = (unsigned char)cursor[name_length];
        if ((cursor == text || !session_unread_name_char(before)) &&
            (after == 0U || !session_unread_name_char(after))) {
            return true;
        }
    }
    return false;
}

void session_unread_show_mentions(session_ctx_t *ctx)
{
    if (!session_user_data_load(ctx)) {
        return;
    }

    user_data_unread_pm_entry_t pms[USER_DATA_UNREAD_PM_LIMIT];
    size_t pm_count = ctx->user_data.unread_pm_count;
    if (pm_count > USER_DATA_UNREAD_PM_LIMIT) {
        pm_count = USER_DATA_UNREAD_PM_LIMIT;
    }
    memcpy(pms, ctx->user_data.unread_pms, sizeof(pms));

    const size_t total = host_history_total(ctx->owner);
    const uint64_t mention_cursor = ctx->user_data.mention_read_message_id;
    uint64_t latest_message_id = mention_cursor;
    size_t mention_count = 0U;
    size_t index = 0U;
    while (index < total) {
        chat_history_entry_t batch[64];
        size_t count = total - index;
        if (count > sizeof(batch) / sizeof(batch[0])) {
            count = sizeof(batch) / sizeof(batch[0]);
        }
        const size_t copied =
            host_history_copy_range(ctx->owner, index, batch, count);
        if (copied == 0U) {
            break;
        }
        for (size_t idx = 0U; idx < copied; ++idx) {
            const chat_history_entry_t *entry = &batch[idx];
            if (!entry->is_user_message || entry->message_id == 0U) {
                continue;
            }
            if (entry->message_id > latest_message_id) {
                latest_message_id = entry->message_id;
            }
            const uint8_t room_id = entry->room_id;
            uint64_t cursor = mention_cursor;
            if (session_unread_room_cursor(ctx, room_id) > cursor) {
                cursor = session_unread_room_cursor(ctx, room_id);
            }
            if (entry->message_id <= cursor ||
                session_unread_entry_is_self(ctx, entry) ||
                !session_unread_text_mentions(entry->message, ctx->user.name)) {
                continue;
            }
            if (mention_count == 0U) {
                session_send_system_line(
                    ctx, session_command_localize(ctx, "Unread mentions:"));
            }
            ++mention_count;
            session_send_history_entry(ctx, entry);
        }
        index += copied;
    }

    chat_reply_entry_t *replies = nullptr;
    size_t reply_count = 0U;
    uint64_t latest_reply_id = ctx->user_data.reply_read_id;
    ttak_mutex_lock(&ctx->owner->lock);
    if (ctx->owner->reply_count > 0U) {
        replies = sshc_gc_calloc(ctx->owner->reply_count, sizeof(*replies));
        if (replies != nullptr) {
            memcpy(replies, ctx->owner->replies,
                   ctx->owner->reply_count * sizeof(*replies));
            reply_count = ctx->owner->reply_count;
        }
    }
    if (ctx->owner->next_reply_id > 0U) {
        latest_reply_id = ctx->owner->next_reply_id - 1U;
    }
    ttak_mutex_unlock(&ctx->owner->lock);

    size_t unread_replies = 0U;
    for (size_t idx = 0U; idx < reply_count; ++idx) {
        const chat_reply_entry_t *reply = &replies[idx];
        if (!reply->in_use || reply->reply_id <= ctx->user_data.reply_read_id ||
            strcasecmp(reply->username, ctx->user.name) == 0) {
            continue;
        }
        char parent_author[SSH_CHATTER_USERNAME_LEN] = {0};
        if (reply->parent_reply_id != 0U) {
            for (size_t parent_idx = 0U; parent_idx < reply_count; ++parent_idx) {
                if (replies[parent_idx].in_use &&
                    replies[parent_idx].reply_id == reply->parent_reply_id) {
                    snprintf(parent_author, sizeof(parent_author), "%s",
                             replies[parent_idx].username);
                    break;
                }
            }
        } else {
            chat_history_entry_t parent = {0};
            if (host_history_find_entry_by_id(ctx->owner, reply->parent_message_id,
                                              &parent)) {
                snprintf(parent_author, sizeof(parent_author), "%s",
                         parent.username);
            }
        }
        if (strcasecmp(parent_author, ctx->user.name) != 0) {
            continue;
        }
        if (unread_replies == 0U) {
            session_send_system_line(
                ctx, session_command_localize(ctx, "Unread replies:"));
        }
        ++unread_replies;
        char label[32];
        if (!host_compact_id_encode(reply->reply_id, label, sizeof(label))) {
            snprintf(label, sizeof(label), "%" PRIu64, reply->reply_id);
        }
        char line[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, line, sizeof(line), "(r#%s) %s: %s", label,
                                 reply->username, reply->message);
        session_send_plain_line(ctx, line);
    }
    sshc_gc_free(replies);

    for (size_t idx = 0U; idx < pm_count; ++idx) {
        if (idx == 0U) {
            session_send_system_line(
                ctx, session_command_localize(ctx, "Unread private messages:"));
        }
        char line[SSH_CHATTER_MESSAGE_LIMIT + USER_DATA_UNREAD_PM_MESSAGE_LEN];
        session_command_snprintf(ctx, line, sizeof(line), "[PM] %s: %s",
                                 pms[idx].sender, pms[idx].message);
        session_send_plain_line(ctx, line);
    }

    if (mention_count == 0U && unread_replies == 0U && pm_count == 0U) {
        session_send_system_line(
            ctx,
            session_command_localize(
                ctx, "No unread mentions, replies, or private messages."));
        return;
    }

    if (!ctx->should_exit) {
        host_t *host = ctx->owner;
        const bool locked = host->user_data_lock_initialized;
        if (locked) {
            ttak_mutex_lock(&host->user_data_lock);
        }
        ctx->user_data.mention_read_message_id = latest_message_id;
        ctx->user_data.reply_read_id = latest_reply_id;
        if (pm_count > 0U) {
            if (ctx->user_data.unread_pm_count > pm_count) {
                const size_t remaining = ctx->user_data.unread_pm_count - pm_count;
                memmove(&ctx->user_data.unread_pms[0],
                        &ctx->user_data.unread_pms[pm_count],
                        remaining * sizeof(ctx->user_data.unread_pms[0]));
                ctx->user_data.unread_pm_count = (uint32_t)remaining;
            } else {
                ctx->user_data.unread_pm_count = 0U;
            }
            memset(&ctx->user_data.unread_pms[ctx->user_data.unread_pm_count], 0,
                   (USER_DATA_UNREAD_PM_LIMIT - ctx->user_data.unread_pm_count) *
                       sizeof(ctx->user_data.unread_pms[0]));
        }
        (void)user_data_save(host->user_data_root, &ctx->user_data, ctx->client_ip);
        if (locked) {
            ttak_mutex_unlock(&host->user_data_lock);
        }
    }
    session_refresh_input_line(ctx);
}

static void session_handle_unread(session_ctx_t *ctx, const char *arguments)
{
    if (ctx == nullptr || ctx->owner == nullptr || !session_user_data_load(ctx)) {
        return;
    }
    char working[64];
    snprintf(working, sizeof(working), "%s", arguments != nullptr ? arguments : "");
    trim_whitespace_inplace(working);
    if (working[0] == '\0') {
        session_unread_show_room(ctx);
        return;
    }
    if (strcasecmp(working, "mentions") == 0) {
        session_unread_show_mentions(ctx);
        return;
    }
    session_send_system_line(
        ctx, session_command_localize(ctx, "Usage: /unread [mentions]"));
}
