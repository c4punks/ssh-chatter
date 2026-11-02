static void session_handle_update(session_ctx_t *ctx, const char *arguments)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }

    if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
        session_send_system_line(
            ctx, session_command_localize(
                     ctx, "Only operators may update server records."));
        return;
    }

    if (arguments != nullptr) {
        char trimmed[32];
        snprintf(trimmed, sizeof(trimmed), "%s", arguments);
        trim_whitespace_inplace(trimmed);
        if (trimmed[0] != '\0') {
            session_send_system_line(ctx, session_command_localize(
                                              ctx, "Usage: /update"));
            return;
        }
    }

    host_t *host = ctx->owner;
    if (!host->user_data_ready || !host->user_data_lock_initialized ||
        host->shutdown_flag == nullptr) {
        session_send_system_line(
            ctx, session_command_localize(
                     ctx, "Record update is unavailable on this server."));
        return;
    }

    ttak_mutex_lock(&host->user_data_lock);
    user_data_upgrade_result_t result = {0};
    const bool success =
        user_data_upgrade_all(host->user_data_root, &result);
    ttak_mutex_unlock(&host->user_data_lock);

    if (!success) {
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        session_command_snprintf(
            ctx, message, sizeof(message),
            "Record update incomplete: %zu upgraded, %zu current, %zu failed. Server restart cancelled.",
            result.upgraded, result.current, result.failed);
        session_send_system_line(ctx, message);
        return;
    }

    char message[SSH_CHATTER_MESSAGE_LIMIT];
    session_command_snprintf(
        ctx, message, sizeof(message),
        "Record update complete: %zu upgraded, %zu already current. Restarting server now.",
        result.upgraded, result.current);
    session_send_system_line(ctx, message);

    host->force_restart_requested = true;
    *host->shutdown_flag = 1;
}
