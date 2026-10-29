/**
 * @file rooms.c
 * @desc Encoding-aware chat room routing and room navigation commands.
 */

#include "../internal.h"

static void session_handle_multilingual_route(session_ctx_t *ctx,
                                              const char *arguments)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }

    char working[64];
    snprintf(working, sizeof(working), "%s", arguments != nullptr ? arguments : "");
    trim_whitespace_inplace(working);
    if (working[0] == '\0') {
        session_send_system_line(
            ctx, session_command_localize(
                     ctx, ctx->multilingual_route_enabled
                              ? "Multilingual routing is enabled."
                              : "Multilingual routing is disabled."));
        session_send_system_line(
            ctx, session_command_localize(
                     ctx, "Usage: /multilingual-route on|off"));
        return;
    }

    bool enabled = false;
    if (strcasecmp(working, "on") == 0) {
        enabled = true;
    } else if (strcasecmp(working, "off") != 0) {
        session_send_system_line(
            ctx, session_command_localize(
                     ctx, "Usage: /multilingual-route on|off"));
        return;
    }
    ctx->multilingual_route_enabled = enabled;
    host_store_multilingual_route(ctx->owner, ctx);
    session_send_system_line(
        ctx, session_command_localize(
                 ctx, enabled ? "Multilingual routing enabled."
                              : "Multilingual routing disabled."));
}

static void session_handle_room(session_ctx_t *ctx, const char *arguments)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }

    char working[128];
    snprintf(working, sizeof(working), "%s", arguments != nullptr ? arguments : "");
    trim_whitespace_inplace(working);
    if (working[0] == '\0') {
        uint8_t room_id = atomic_load(&ctx->current_room);
        const char *name = session_chat_room_name(room_id);
        if (name == nullptr) {
            name = "main";
        }
        char line[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, line, sizeof(line), "Current room: %s",
                                 name);
        session_send_system_line(ctx, line);
        return;
    }

    char *saveptr = nullptr;
    char *action = strtok_r(working, " \t", &saveptr);
    if (action != nullptr && strcasecmp(action, "list") == 0) {
        char listing[1024] = "main";
        size_t used = strlen(listing);
        for (uint8_t room_id = CHAT_ROOM_UTF8; room_id <= CHAT_ROOM_MAX_ID;
             ++room_id) {
            const char *name = session_chat_room_name(room_id);
            if (name == nullptr || !session_chat_room_exists(ctx->owner, room_id)) {
                continue;
            }
            int n = snprintf(listing + used, sizeof(listing) - used, "\n%s", name);
            if (n < 0 || (size_t)n >= sizeof(listing) - used) {
                break;
            }
            used += (size_t)n;
        }
        session_send_system_line(
            ctx, session_command_localize(ctx, "Available rooms:"));
        session_send_system_line(ctx, listing);
        return;
    }

    if (action != nullptr && strcasecmp(action, "join") == 0) {
        char *name = saveptr;
        while (name != nullptr && (*name == ' ' || *name == '\t')) {
            ++name;
        }
        if (name == nullptr || name[0] == '\0') {
            session_send_system_line(
                ctx, session_command_localize(
                         ctx, "Usage: /room [list|join <room-name>]"));
            return;
        }
        trim_whitespace_inplace(name);
        uint8_t room_id = session_chat_room_from_name(name);
        if (room_id == UINT8_MAX ||
            !session_chat_room_exists(ctx->owner, room_id)) {
            char line[SSH_CHATTER_MESSAGE_LIMIT];
            session_command_snprintf(ctx, line, sizeof(line),
                                     "Room '%s' was not found.", name);
            session_send_system_line(ctx, line);
            return;
        }

        atomic_store(&ctx->current_room, room_id);
        session_clear_screen(ctx);
        session_scrollback_reset_position(ctx);
        session_apply_background_fill(ctx);
        session_flag_should_sink(ctx);
        session_process_pending_sink(ctx);
        const char *canonical = session_chat_room_name(room_id);
        char line[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(ctx, line, sizeof(line), "Joined room %s.",
                                 canonical);
        session_send_system_line(ctx, line);
        session_refresh_input_line(ctx);
        return;
    }

    session_send_system_line(
        ctx, session_command_localize(ctx, "Usage: /room [list|join <room-name>]"));
}
