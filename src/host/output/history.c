static size_t session_visible_history_lines(const session_ctx_t *ctx)
{
    return session_scrollback_line_capacity(ctx);
}

static void session_history_record(session_ctx_t *ctx, const char *line)
{
    if (ctx == nullptr || line == nullptr) {
        return;
    }

    bool has_visible = false;
    for (const char *cursor = line; *cursor != '\0'; ++cursor) {
        if (!isspace((unsigned char)*cursor)) {
            has_visible = true;
            break;
        }
    }

    if (!has_visible) {
        ctx->input_history_position = -1;
        return;
    }

    const char *trimmed = line;
    while (*trimmed == ' ' || *trimmed == '\t') {
        ++trimmed;
    }

    bool is_command = false;
    if (*trimmed != '\0') {
        if (*trimmed == '/') {
            is_command = true;
        } else if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
            is_command = true;
        }
    }

    if (ctx->input_history_count > 0U) {
        const size_t last_index = ctx->input_history_count - 1U;
        if (strncmp(ctx->input_history[last_index], line,
                    sizeof(ctx->input_history[last_index])) == 0) {
            ctx->input_history_position = -1;
            return;
        }
    }

    if (ctx->input_history_count < SSH_CHATTER_INPUT_HISTORY_LIMIT) {
        snprintf(ctx->input_history[ctx->input_history_count],
                 sizeof(ctx->input_history[0]), "%s", line);
        ctx->input_history_is_command[ctx->input_history_count] = is_command;
        ++ctx->input_history_count;
    } else {
        memmove(ctx->input_history, ctx->input_history + 1,
                sizeof(ctx->input_history) - sizeof(ctx->input_history[0]));
        memmove(ctx->input_history_is_command,
                ctx->input_history_is_command + 1,
                (SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U) *
                    sizeof(ctx->input_history_is_command[0]));
        snprintf(ctx->input_history[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U],
                 sizeof(ctx->input_history[0]), "%s", line);
        ctx->input_history_is_command[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U] =
            is_command;
    }

    ctx->input_history_position = -1;
    session_scrollback_reset_position(ctx);
}

static void session_history_navigate(session_ctx_t *ctx, int direction)
{
    if (ctx == nullptr || direction == 0) {
        return;
    }

    // If scrollback is active (scrolled back), clear it before navigating command history
    // This prevents blank lines from appearing when switching from scrollback to command history
    bool was_scrolled_back = (ctx->history_scroll_position > 0U);

    if (was_scrolled_back) {
        /* The screen still holds the scrolled view; make the sink repaint
         * the full tail once instead of appending after stale content. */
        ctx->last_sink_history_total = 0U;
    }
    session_scrollback_reset_position(ctx);

    // Clear the current line to remove any scrollback content
    if (was_scrolled_back) {
        const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
        session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);
    }

    if (ctx->input_history_count == 0U) {
        ctx->input_history_position = (int)ctx->input_history_count;
        session_set_input_text(ctx, "");
        return;
    }

    int position = ctx->input_history_position;
    if (position < 0 || position > (int)ctx->input_history_count) {
        position = (int)ctx->input_history_count;
    }

    position += direction;
    if (position < 0) {
        position = 0;
    }
    if (position > (int)ctx->input_history_count) {
        position = (int)ctx->input_history_count;
    }

    ctx->input_history_position = position;

    if (position == (int)ctx->input_history_count) {
        session_set_input_text(ctx, "");
    } else {
        session_set_input_text(ctx, ctx->input_history[position]);
    }
}

/* Terminal rows the bytes take once printed: follows CR/LF, ESC[nG column
 * moves and wide characters, wrapping at the terminal width the way a
 * terminal does (a full row only wraps on the next printable). */
static size_t session_scrollback_count_rows(const session_ctx_t *ctx,
                                            const char *data, size_t length)
{
    const size_t width =
        (ctx->terminal_width > 0U) ? (size_t)ctx->terminal_width : 80U;
    size_t rows = 0U;
    size_t col = 0U;
    size_t idx = 0U;
    while (idx < length) {
        const unsigned char ch = (unsigned char)data[idx];
        if (ch == 0x1BU) {
            if (idx + 1U < length && data[idx + 1U] == '[') {
                size_t end = idx + 2U;
                size_t param = 0U;
                while (end < length && ((unsigned char)data[end] < 0x40U ||
                                        (unsigned char)data[end] > 0x7EU)) {
                    if (isdigit((unsigned char)data[end])) {
                        param = param * 10U + (size_t)(data[end] - '0');
                    } else {
                        param = 0U;
                    }
                    ++end;
                }
                if (end < length && data[end] == 'G') {
                    col = param > 0U ? param - 1U : 0U;
                    if (col > width) {
                        col = width;
                    }
                }
                idx = end < length ? end + 1U : length;
            } else {
                idx += 2U;
            }
            continue;
        }
        if (ch == '\r') {
            col = 0U;
            ++idx;
            continue;
        }
        if (ch == '\n') {
            ++rows;
            col = 0U;
            ++idx;
            continue;
        }
        if (ch < 0x20U || ch == 0x7FU) {
            ++idx;
            continue;
        }
        size_t seq_len = 1U;
        if (ch >= 0xF0U) {
            seq_len = 4U;
        } else if (ch >= 0xE0U) {
            seq_len = 3U;
        } else if (ch >= 0xC0U) {
            seq_len = 2U;
        }
        if (seq_len > length - idx) {
            seq_len = length - idx;
        }
        const int char_width =
            ch < 0x80U ? 1 : session_utf8_char_width(&data[idx], seq_len);
        if (char_width > 0) {
            if (col + (size_t)char_width > width) {
                ++rows;
                col = 0U;
            }
            col += (size_t)char_width;
        }
        idx += seq_len;
    }
    if (col > 0U) {
        ++rows;
    }
    return rows;
}

static void session_scrollback_send_header(session_ctx_t *ctx, size_t oldest,
                                           size_t newest, size_t total)
{
    char header[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(header, sizeof(header), "Scrollback (%zu-%zu of %zu)",
             oldest + 1U, newest + 1U, total);
    session_send_system_line(ctx, header);
}

static bool session_scrollback_entry_is_visible(session_ctx_t *ctx,
                                                const chat_history_entry_t *entry)
{
    if (entry == nullptr || chat_history_entry_is_empty(entry)) {
        return false;
    }
    return !session_should_hide_entry(ctx, entry);
}

static bool session_scrollback_find_prev_visible(session_ctx_t *ctx,
                                                 size_t from_index,
                                                 size_t *out_index)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return false;
    }
    size_t total = host_history_total(ctx->owner);
    if (total == 0U) {
        return false;
    }
    if (from_index >= total) {
        from_index = total - 1U;
    }

    chat_history_entry_t batch[32];
    size_t cur = from_index;
    while (true) {
        size_t batch_size = sizeof(batch) / sizeof(batch[0]);
        size_t start = (cur + 1U > batch_size) ? (cur + 1U - batch_size) : 0U;
        size_t count = cur + 1U - start;
        size_t copied =
            host_history_copy_range(ctx->owner, start, batch, count);
        if (copied == 0U) {
            return false;
        }
        for (size_t i = copied; i > 0U; --i) {
            if (session_scrollback_entry_is_visible(ctx, &batch[i - 1U])) {
                if (out_index != nullptr) {
                    *out_index = start + i - 1U;
                }
                return true;
            }
        }
        if (start == 0U) {
            break;
        }
        cur = start - 1U;
    }
    return false;
}

static bool session_scrollback_step_visible(session_ctx_t *ctx,
                                            size_t from_index,
                                            int direction,
                                            size_t count,
                                            size_t *out_index,
                                            bool *reached_boundary)
{
    if (ctx == nullptr || ctx->owner == nullptr || count == 0U) {
        return false;
    }
    size_t total = host_history_total(ctx->owner);
    if (total == 0U) {
        return false;
    }

    if (reached_boundary != nullptr) {
        *reached_boundary = false;
    }

    size_t found = 0U;
    size_t last_found = from_index;

    if (direction > 0) {
        if (from_index == 0U) {
            if (reached_boundary != nullptr) {
                *reached_boundary = true;
            }
            return false;
        }

        chat_history_entry_t batch[32];
        size_t cur = from_index - 1U;
        while (found < count) {
            size_t batch_size = sizeof(batch) / sizeof(batch[0]);
            size_t start = (cur + 1U > batch_size) ? (cur + 1U - batch_size) : 0U;
            size_t batch_count = cur + 1U - start;
            size_t copied =
                host_history_copy_range(ctx->owner, start, batch, batch_count);
            if (copied == 0U) {
                break;
            }
            for (size_t i = copied; i > 0U && found < count; --i) {
                if (session_scrollback_entry_is_visible(ctx, &batch[i - 1U])) {
                    last_found = start + i - 1U;
                    ++found;
                }
            }
            if (start == 0U) {
                break;
            }
            cur = start - 1U;
        }

        if (found > 0U) {
            if (out_index != nullptr) {
                *out_index = last_found;
            }
            if (found < count && reached_boundary != nullptr) {
                *reached_boundary = true;
            }
            return true;
        }
        if (reached_boundary != nullptr) {
            *reached_boundary = true;
        }
        return false;
    } else if (direction < 0) {
        if (from_index + 1U >= total) {
            if (reached_boundary != nullptr) {
                *reached_boundary = true;
            }
            return false;
        }

        chat_history_entry_t batch[32];
        size_t cur = from_index + 1U;
        while (cur < total && found < count) {
            size_t batch_size = sizeof(batch) / sizeof(batch[0]);
            if (batch_size > total - cur) {
                batch_size = total - cur;
            }
            size_t copied =
                host_history_copy_range(ctx->owner, cur, batch, batch_size);
            if (copied == 0U) {
                break;
            }
            for (size_t i = 0U; i < copied && found < count; ++i) {
                if (session_scrollback_entry_is_visible(ctx, &batch[i])) {
                    last_found = cur + i;
                    ++found;
                }
            }
            cur += copied;
        }

        if (found > 0U) {
            if (out_index != nullptr) {
                *out_index = last_found;
            }
            if (found < count && reached_boundary != nullptr) {
                *reached_boundary = true;
            }
            return true;
        }
        if (reached_boundary != nullptr) {
            *reached_boundary = true;
        }
        return false;
    }

    return false;
}

static size_t session_scrollback_collect_visible(
    session_ctx_t *ctx, size_t newest_index, size_t target_count,
    chat_history_entry_t *out_buffer, size_t *out_indices, size_t capacity)
{
    if (ctx == nullptr || ctx->owner == nullptr || out_buffer == nullptr ||
        out_indices == nullptr || capacity == 0U || target_count == 0U) {
        return 0U;
    }

    size_t total = host_history_total(ctx->owner);
    if (total == 0U || newest_index >= total) {
        return 0U;
    }

    size_t limit = target_count;
    if (limit > capacity) {
        limit = capacity;
    }
    if (limit > SSH_CHATTER_SCROLLBACK_MAX_CHUNK) {
        limit = SSH_CHATTER_SCROLLBACK_MAX_CHUNK;
    }

    size_t slot = limit;
    chat_history_entry_t batch[32];
    size_t cur = newest_index;

    while (slot > 0U) {
        size_t batch_size = sizeof(batch) / sizeof(batch[0]);
        size_t start = (cur + 1U > batch_size) ? (cur + 1U - batch_size) : 0U;
        size_t batch_count = cur + 1U - start;
        size_t copied =
            host_history_copy_range(ctx->owner, start, batch, batch_count);
        if (copied == 0U) {
            break;
        }
        for (size_t i = copied; i > 0U && slot > 0U; --i) {
            if (session_scrollback_entry_is_visible(ctx, &batch[i - 1U])) {
                --slot;
                out_buffer[slot] = batch[i - 1U];
                out_indices[slot] = start + i - 1U;
            }
        }
        if (start == 0U) {
            break;
        }
        cur = start - 1U;
    }

    size_t collected = limit - slot;
    if (collected > 0U && slot > 0U) {
        memmove(out_buffer, &out_buffer[slot],
                collected * sizeof(chat_history_entry_t));
        memmove(out_indices, &out_indices[slot], collected * sizeof(size_t));
    }

    return collected;
}

/* Render one scrollback frame: a header, then entries[0..count) (history
 * indices history_indices[0..count-1]).  A message can wrap or carry captions over
 * several rows, so a frame of N messages has no fixed height; the frame is
 * captured first, and the oldest messages are dropped until the rest fit in
 * max_rows so every frame is the same height.  Returns the rows written,
 * header included, and the history index of the oldest message shown. */
static size_t session_scrollback_render_window_locked(
    session_ctx_t *ctx, const chat_history_entry_t *entries,
    const size_t *history_indices, size_t count,
    size_t total, size_t max_rows, size_t *first_shown)
{
    if (count == 0U || history_indices == nullptr) {
        session_send_system_line(ctx, "No chat history available yet.");
        *first_shown = 0U;
        ctx->scrollback_rendered_entries = 0U;
        return 1U;
    }

    *first_shown = history_indices[0];
    ctx->scrollback_rendered_entries = count;
    if (ctx->display_model_initialized) {
        ctx->display_model.line_count = 0U;
    }

    size_t offsets[SSH_CHATTER_SCROLLBACK_MAX_CHUNK + 1U];
    bool measurable = count <= SSH_CHATTER_SCROLLBACK_MAX_CHUNK &&
                      ctx->scrollback_capture == nullptr;
    if (measurable) {
        /* Send the clear/cursor moves queued before the frame first. */
        session_output_buffer_flush(ctx);
        ctx->scrollback_capture_capacity = SSH_CHATTER_OUTPUT_BUFFER_SIZE;
        ctx->scrollback_capture =
            (char *)sshc_gc_malloc(ctx->scrollback_capture_capacity);
        ctx->scrollback_capture_length = 0U;
        ctx->scrollback_capture_overflowed = false;
        if (ctx->scrollback_capture == nullptr) {
            ctx->scrollback_capture_capacity = 0U;
            measurable = false;
        }
    }

    if (!measurable) {
        session_scrollback_send_header(ctx, history_indices[0],
                                       history_indices[count - 1U], total);
        for (size_t idx = 0U; idx < count; ++idx) {
            session_send_history_entry(ctx, &entries[idx]);
        }
        if (ctx->display_model_initialized) {
            return ctx->display_model.line_count + 1U;
        }
        return count + 1U;
    }

    for (size_t idx = 0U; idx < count; ++idx) {
        offsets[idx] = ctx->scrollback_capture_length;
        session_send_history_entry(ctx, &entries[idx]);
    }
    offsets[count] = ctx->scrollback_capture_length;

    char *captured = ctx->scrollback_capture;
    ctx->scrollback_capture = nullptr;
    ctx->scrollback_capture_length = 0U;
    ctx->scrollback_capture_capacity = 0U;
    if (captured == nullptr || ctx->scrollback_capture_overflowed) {
        /* The capture outgrew its cap and went out unmeasured (no header). */
        ctx->scrollback_capture_overflowed = false;
        if (ctx->display_model_initialized) {
            return ctx->display_model.line_count;
        }
        return count;
    }

    size_t first = count;
    size_t entry_rows = 0U;
    while (first > 0U) {
        const size_t rows = session_scrollback_count_rows(
            ctx, &captured[offsets[first - 1U]],
            offsets[first] - offsets[first - 1U]);
        /* The newest message always stays, even if it alone is too tall. */
        if (first < count && entry_rows + rows > max_rows) {
            break;
        }
        entry_rows += rows;
        --first;
    }

    /* Refine edge indices if any entry produced zero output */
    while (first < count - 1U && offsets[first + 1U] == offsets[first]) {
        ++first;
    }
    size_t last = count;
    while (last > first + 1U && offsets[last] == offsets[last - 1U]) {
        --last;
    }

    ctx->scrollback_capture_capacity = SSH_CHATTER_MESSAGE_LIMIT;
    ctx->scrollback_capture =
        (char *)sshc_gc_malloc(ctx->scrollback_capture_capacity);
    ctx->scrollback_capture_length = 0U;
    size_t header_rows = 1U;
    if (ctx->scrollback_capture != nullptr) {
        session_scrollback_send_header(ctx, history_indices[first],
                                       history_indices[last - 1U], total);
        char *header = ctx->scrollback_capture;
        const size_t header_length = ctx->scrollback_capture_length;
        ctx->scrollback_capture = nullptr;
        ctx->scrollback_capture_length = 0U;
        ctx->scrollback_capture_capacity = 0U;
        if (header != nullptr && !ctx->scrollback_capture_overflowed) {
            header_rows =
                session_scrollback_count_rows(ctx, header, header_length);
            session_channel_write(ctx, header, header_length);
        }
        ctx->scrollback_capture_overflowed = false;
        sshc_gc_free(header);
    } else {
        ctx->scrollback_capture_capacity = 0U;
        session_scrollback_send_header(ctx, history_indices[first],
                                       history_indices[last - 1U], total);
    }

    session_channel_write(ctx, &captured[offsets[first]],
                          offsets[count] - offsets[first]);
    sshc_gc_free(captured);

    *first_shown = history_indices[first];
    ctx->scrollback_rendered_entries = count - first;
    if (first > 0U && ctx->display_model_initialized &&
        entries[first].message_id > 0U) {
        ctx->display_model.view.mode = VIEW_MANUAL_SCROLL;
        ctx->display_model.view.anchor.message_id = entries[first].message_id;
        ctx->display_model.view.anchor.subline_index = 0U;
    }

    return header_rows + entry_rows;
}

/* Other sessions' threads write to this one; hold its (recursive) output
 * lock so none of their bytes land in, or race with, the capture. */
static size_t session_scrollback_render_window(
    session_ctx_t *ctx, const chat_history_entry_t *entries,
    const size_t *history_indices, size_t count,
    size_t total, size_t max_rows, size_t *first_shown)
{
    const bool locked = session_output_lock(ctx);
    const size_t rows = session_scrollback_render_window_locked(
        ctx, entries, history_indices, count, total, max_rows, first_shown);
    if (locked) {
        session_output_unlock(ctx);
    }
    return rows;
}

static void session_scrollback_navigate_common(session_ctx_t *ctx,
                                               int direction,
                                               size_t step,
                                               bool is_line_step)
{
    if (ctx == nullptr || ctx->owner == nullptr ||
        !session_transport_active(ctx)) {
        return;
    }
    if (direction != 0 &&
        ((direction < 0 && ctx->history_latest_notified) ||
         (direction > 0 && ctx->history_oldest_notified))) {
        return;
    }

    size_t total = host_history_total(ctx->owner);
    if (total == 0U) {
        session_send_system_line(ctx, "No chat history available yet.");
        return;
    }

    bool suppress_translation = translator_should_skip_scrollback_translation();
    bool previous_translation_suppress = ctx->translation_suppress_output;
    if (suppress_translation) {
        ctx->translation_suppress_output = true;
    }

    const bool buffering_started = !ctx->output_buffering_enabled;
    if (buffering_started) {
        session_output_buffer_start(ctx);
    }

    size_t scroll_step = (!is_line_step && step > 0U)
                             ? step
                             : session_visible_history_lines(ctx);
    if (scroll_step == 0U) {
        scroll_step = 1U;
    }

    size_t latest_visible = 0U;
    if (!session_scrollback_find_prev_visible(ctx, total - 1U, &latest_visible)) {
        session_send_system_line(ctx, "No chat history available yet.");
        goto cleanup;
    }

    const size_t position = ctx->history_scroll_position;
    size_t current_anchor = 0U;
    if (position == 0U) {
        current_anchor = latest_visible;
    } else {
        size_t raw_anchor = (position >= total) ? 0U : (total - 1U - position);
        if (!session_scrollback_find_prev_visible(ctx, raw_anchor, &current_anchor)) {
            current_anchor = latest_visible;
        }
    }

    ctx->no_update = true;
    ctx->history_latest_notified = false;
    ctx->history_oldest_notified = false;

    size_t newest_index = current_anchor;

    if (direction > 0) {
        size_t advance = 1U;
        if (!is_line_step) {
            advance = ctx->scrollback_rendered_entries;
            if (position == 0U || advance == 0U || advance > scroll_step) {
                advance = scroll_step;
            }
        }
        size_t target_idx = 0U;
        bool reached_boundary = false;
        bool ok = session_scrollback_step_visible(
            ctx, current_anchor, 1, advance, &target_idx, &reached_boundary);
        if (!ok) {
            ctx->history_oldest_notified = true;
            goto cleanup;
        }
        newest_index = target_idx;
        if (reached_boundary) {
            ctx->history_oldest_notified = true;
        }
    } else if (direction < 0) {
        if (position == 0U) {
            ctx->history_latest_notified = true;
            goto cleanup;
        }
        size_t retreat = 1U;
        if (!is_line_step) {
            retreat = ctx->scrollback_rendered_entries;
            if (retreat == 0U || retreat > scroll_step) {
                retreat = scroll_step;
            }
        }
        if (current_anchor >= latest_visible) {
            ctx->last_sink_history_total = 0U;
            session_scrollback_reset_position(ctx);
            ctx->history_latest_notified = true;
            session_render_prompt(ctx, false);
            goto cleanup;
        }
        size_t target_idx = 0U;
        bool reached_boundary = false;
        bool ok = session_scrollback_step_visible(
            ctx, current_anchor, -1, retreat, &target_idx, &reached_boundary);
        if (!ok || target_idx >= latest_visible) {
            ctx->last_sink_history_total = 0U;
            session_scrollback_reset_position(ctx);
            ctx->history_latest_notified = true;
            session_render_prompt(ctx, false);
            goto cleanup;
        }
        newest_index = target_idx;
    } else {
        /* direction == 0 */
        newest_index = current_anchor;
    }

    const size_t new_position = total - 1U - newest_index;
    ctx->history_scroll_position = new_position;

    if (position == 0U || direction == 0) {
        ctx->scrollback_rendered_lines = 0U;
    }
    session_scrollback_prepare_display(ctx);

    const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
    session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);

    size_t buffer_capacity = 0U;
    chat_history_entry_t *buffer = session_scrollback_reserve_buffer(
        ctx, scroll_step, &buffer_capacity);
    if (buffer == nullptr) {
        goto cleanup;
    }

    size_t history_indices[SSH_CHATTER_SCROLLBACK_MAX_CHUNK];
    size_t count = session_scrollback_collect_visible(
        ctx, newest_index, scroll_step, buffer, history_indices, buffer_capacity);

    if (count == 0U) {
        session_send_system_line(ctx, "No chat history available yet.");
        session_render_prompt(ctx, false);
        goto cleanup;
    }

    size_t first_shown = 0U;
    ctx->scrollback_rendered_lines = session_scrollback_render_window(
        ctx, buffer, history_indices, count, total, scroll_step, &first_shown);

    if (first_shown == 0U) {
        ctx->history_oldest_notified = true;
    } else {
        size_t older_test = 0U;
        bool reached_top = false;
        if (!session_scrollback_step_visible(ctx, first_shown, 1, 1,
                                            &older_test, &reached_top)) {
            ctx->history_oldest_notified = true;
        }
    }

    session_render_prompt(ctx, false);
    session_process_pending_sink(ctx);

cleanup:
    if (buffering_started) {
        session_output_buffer_stop(ctx);
    }
    if (suppress_translation) {
        ctx->translation_suppress_output = previous_translation_suppress;
    }
}

void session_scrollback_navigate(session_ctx_t *ctx, int direction,
                                 size_t step)
{
    session_scrollback_navigate_common(ctx, direction, step, false);
}

static void session_scrollback_navigate_line(session_ctx_t *ctx, int direction)
{
    if (direction == 0) {
        return;
    }
    session_scrollback_navigate_common(ctx, direction, 0U, true);
}

/* ANSI art editors keep pasted SGR color sequences in the input line. */
static bool session_editor_accepts_ansi(const session_ctx_t *ctx)
{
    return ctx != nullptr && ctx->bbs_post_pending && ctx->bbs_editor_ansi &&
           !ctx->bbs_search_active;
}

/* Append an SGR sequence to the input line without echoing it. A sequence
 * that does not fit is dropped rather than splitting the line. */
static void session_input_append_sgr(session_ctx_t *ctx, const char *sequence,
                                     size_t length)
{
    if (ctx == nullptr || sequence == nullptr ||
        !host_ansi_is_sgr(sequence, length) ||
        ctx->input_length + length >= sizeof(ctx->input_buffer)) {
        return;
    }

    memcpy(&ctx->input_buffer[ctx->input_length], sequence, length);
    ctx->input_length += length;
    ctx->input_buffer[ctx->input_length] = '\0';
}

static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch)
{
    if (ctx == nullptr) {
        return false;
    }

    if (!ctx->input_escape_active) {
        if (ch == 0x1b) {
            ctx->input_escape_active = true;
            ctx->input_escape_length = 0U;
            if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
                ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
            }
            return true;
        }
        return false;
    }

    if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
        ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
    }

    const char *sequence = ctx->input_escape_buffer;
    const size_t length = ctx->input_escape_length;

    if (length == 1U) {
        return true;
    }

    if (length == 2U) {
        if (sequence[1] == '[') {
            return true;
        }
        if (sequence[1] == 'k') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, -1);
            } else {
                if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
                    ctx->input_escape_active = false;
                    ctx->input_escape_length = 0U;
                    return true;
                }
                session_history_navigate(ctx, -1);
            }
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[1] == 'j') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, 1);
            } else {
                if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
                    ctx->input_escape_active = false;
                    ctx->input_escape_length = 0U;
                    return true;
                }
                session_history_navigate(ctx, 1);
            }
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if ((sequence[1] == 'l' || sequence[1] == 'L') && ctx->game.active &&
            ctx->game.type == SESSION_GAME_ALPHA) {
            session_game_alpha_manual_lock(ctx);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
    }

    if (length == 3U && sequence[1] == '[') {
        if (session_wall_process_escape(ctx, sequence, length)) {
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        int dx = 0;
        int dy = 0;
        switch (sequence[2]) {
        case 'A':
            dy = -1;
            break;
        case 'B':
            dy = 1;
            break;
        case 'C':
            dx = 1;
            break;
        case 'D':
            dx = -1;
            break;
        default:
            break;
        }
        if ((dx != 0 || dy != 0) &&
            session_game_alpha_handle_arrow(ctx, dx, dy)) {
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[2] == 'A') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, -1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
                session_history_navigate(ctx, -1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            session_scrollback_navigate_line(ctx, 1);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[2] == 'B') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, 1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
                session_history_navigate(ctx, 1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            session_scrollback_navigate_line(ctx, -1);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
    }

    if (length == 3U && sequence[1] == 'O') {
        if (session_wall_process_escape(ctx, sequence, length)) {
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        int dx = 0;
        int dy = 0;
        switch (sequence[2]) {
        case 'A':
            dy = -1;
            break;
        case 'B':
            dy = 1;
            break;
        case 'C':
            dx = 1;
            break;
        case 'D':
            dx = -1;
            break;
        default:
            break;
        }
        if ((dx != 0 || dy != 0) &&
            session_game_alpha_handle_arrow(ctx, dx, dy)) {
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[2] == 'A') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, -1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
                session_history_navigate(ctx, -1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            session_scrollback_navigate_line(ctx, 1);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[2] == 'B') {
            if (ctx->bbs_post_pending) {
                session_bbs_move_cursor(ctx, 1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
                session_history_navigate(ctx, 1);
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            session_scrollback_navigate_line(ctx, -1);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
    }

    if (length == 4U && sequence[1] == '[' && sequence[3] == '~') {
        if (sequence[2] == '5') {
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 0U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            // Treat PageUp/PageDown as single-page navigation based on the
            // current viewport height instead of a fixed minimum history size.
            session_scrollback_navigate(ctx, 1, 0U);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
        if (sequence[2] == '6') {
            if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 0U)) {
                ctx->input_escape_active = false;
                ctx->input_escape_length = 0U;
                return true;
            }
            // Treat PageUp/PageDown as single-page navigation based on the
            // current viewport height instead of a fixed minimum history size.
            session_scrollback_navigate(ctx, -1, 0U);
            ctx->input_escape_active = false;
            ctx->input_escape_length = 0U;
            return true;
        }
    }

    const bool bracket_sequence = (length >= 2U && sequence[1] == '[');
    if (bracket_sequence) {
        const unsigned char final = (unsigned char)sequence[length - 1U];
        const bool overflow = length >= sizeof(ctx->input_escape_buffer);
        /* Keep collecting until the CSI final byte (0x40-0x7e) arrives. */
        if (!overflow && (length < 3U || final < 0x40U || final > 0x7eU)) {
            return true;
        }
        if (!overflow && final == 'm' && session_editor_accepts_ansi(ctx)) {
            session_input_append_sgr(ctx, sequence, length);
        }
        if (final == '~') {
            if (length >= 5U && strncmp(&sequence[2], "200", 3) == 0) {
                ctx->bracket_paste_active = true;
            } else if (length >= 5U && strncmp(&sequence[2], "201", 3) == 0) {
                ctx->bracket_paste_active = false;
                session_refresh_input_line(ctx);
            }
        }
    }

    ctx->input_escape_active = false;
    ctx->input_escape_length = 0U;
    if (bracket_sequence) {
        return true;
    }
    return ch == 0x1b;
}

static void session_send_private_message_line(session_ctx_t *ctx,
                                              const session_ctx_t *color_source,
                                              const char *label,
                                              const char *message)
{
    if (ctx == nullptr || !session_transport_active(ctx) ||
        color_source == nullptr || label == nullptr || message == nullptr) {
        return;
    }

    if (ctx->editor_mode != SESSION_EDITOR_MODE_NONE || ctx->bbs_rendering_editor) {
        if (color_source != ctx && session_transport_active((session_ctx_t *)color_source)) {
            char busy_msg[SSH_CHATTER_MESSAGE_LIMIT];
            snprintf(busy_msg, sizeof(busy_msg), "User '%s' is currently editing and cannot receive private messages.", ctx->user.name);
            session_send_system_line((session_ctx_t *)color_source, busy_msg);
        }
        return;
    }

    const char *highlight = color_source->user_highlight_code[0] != '\0'
                                ? color_source->user_highlight_code
                                : "";
    const char *color = color_source->user_color_code[0] != '\0'
                            ? color_source->user_color_code
                            : "";
    const char *bold = color_source->user_is_bold ? ANSI_BOLD : "";

    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color,
             label, ANSI_RESET, message);
    session_send_line(ctx, line);

    if (ctx != color_source && ctx->history_scroll_position == 0U) {
        session_refresh_input_line(ctx);
    }
}

// Helper function to send a message line-by-line with cursor reset for each line
static void session_send_multiline_message(session_ctx_t *ctx,
                                           const char *message)
{
    if (ctx == nullptr || message == nullptr ||
        !session_transport_active(ctx)) {
        return;
    }

    // Make a copy of the message since we'll be modifying it
    size_t message_len = strlen(message);
    if (message_len == 0U) {
        return;
    }

    char *message_copy = sshc_gc_calloc(1U, message_len + 1U);
    if (message_copy == nullptr) {
        // If allocation fails, split inline without copying
        // This is a fallback path that still preserves the line-by-line behavior
        const char *line_start = message;
        const char *newline_pos = nullptr;

        while ((newline_pos = strchr(line_start, '\n')) != nullptr) {
            // Calculate line length
            size_t line_len = (size_t)(newline_pos - line_start);

            // Create a temporary buffer for this line (reserve 1 byte for null terminator)
            char line_buffer[SSH_CHATTER_MESSAGE_LIMIT];
            const size_t max_line_len = sizeof(line_buffer) - 1U;
            if (line_len > max_line_len) {
                line_len = max_line_len;
            }

            memcpy(line_buffer, line_start, line_len);
            line_buffer[line_len] = '\0';

            session_send_plain_line(ctx, line_buffer);

            // Move to the next line
            line_start = newline_pos + 1;
        }

        // Send any remaining text after the last newline
        if (line_start[0] != '\0') {
            session_send_plain_line(ctx, line_start);
        }
        return;
    }

    memcpy(message_copy, message, message_len);

    // Split by newlines and send each line individually
    char *line_start = message_copy;
    char *newline_pos = nullptr;

    while ((newline_pos = strchr(line_start, '\n')) != nullptr) {
        // Temporarily null-terminate at the newline
        *newline_pos = '\0';

        // Send this line with cursor reset
        session_send_plain_line(ctx, line_start);

        // Move to the next line
        line_start = newline_pos + 1;
    }

    // Send any remaining text after the last newline
    if (line_start[0] != '\0') {
        session_send_plain_line(ctx, line_start);
    }

    sshc_gc_free(message_copy);
}

static void session_render_history_entry(session_ctx_t *ctx,
                                         const chat_history_entry_t *entry,
                                         bool emit_output)
{
    if (ctx == nullptr || !session_transport_active(ctx) || entry == nullptr) {
        return;
    }

    if (chat_history_entry_is_empty(entry)) {
        return;
    }

    // Show what the display filter says, not the stored text.  The id
    // label comes from the stored entry: relayed DDial lines read "d<id>".
    char id_label[32];
    const bool has_id_label =
        host_history_id_label(entry, id_label, sizeof(id_label));
    chat_history_entry_t ddial_view;
    if (!host_ddial_display_view(entry, &ddial_view, &entry)) {
        return;
    }

    session_output_kind_t previous_kind =
        session_output_set_kind(ctx, SESSION_OUTPUT_KIND_CHAT);

    if (session_should_hide_entry(ctx, entry)) {
        session_output_restore_kind(ctx, previous_kind);
        return;
    }

    if (entry->is_user_message) {
        char formatted[SSH_CHATTER_MESSAGE_LIMIT * 2U];
        formatted[0] = '\0';

        const char *highlight = (entry->user_highlight_code[0] != '\0')
                                    ? entry->user_highlight_code
                                    : "";
        const char *color =
            (entry->user_color_code[0] != '\0') ? entry->user_color_code : "";
        const char *bold = entry->user_is_bold ? ANSI_BOLD : "";

        const bool has_custom_codes =
            (color[0] != '\0') || (highlight[0] != '\0');

        char name_block[SSH_CHATTER_MESSAGE_LIMIT];
        const char *id_display = has_id_label ? id_label : "-";
        const char *display_name = chat_history_entry_display_name(entry);
        if (has_custom_codes) {
            snprintf(name_block, sizeof(name_block), ANSI_CYAN "[%s]" ANSI_RESET " <%s%s%s%s%s>",
                     id_display, highlight, color, bold, display_name,
                     ANSI_RESET);
        } else {
            snprintf(name_block, sizeof(name_block), "%s%s%s " ANSI_CYAN "[%s]" ANSI_RESET " <%s>%s",
                     highlight, bold, color, id_display, display_name,
                     ANSI_RESET);
        }
        size_t fmt_len = strlen(name_block);
        memcpy(formatted, name_block, fmt_len);
        formatted[fmt_len] = '\0';

        if (entry->message[0] != '\0') {
            const bool multiline = strchr(entry->message, '\n') != nullptr;
            if (multiline) {
                // For multiline messages, send the username first, then each line separately
                if (fmt_len + 1 < sizeof(formatted)) {
                    formatted[fmt_len++] = ' ';
                    formatted[fmt_len] = '\0';
                }
                if (ctx->display_model_initialized) {
                    unsigned int width = (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
                    display_model_append_message(&ctx->display_model, entry->message_id, formatted, width);
                    display_model_append_message(&ctx->display_model, entry->message_id, entry->message, width);
                }
                if (emit_output) {
                    session_send_plain_line(ctx, formatted);
                    session_send_multiline_message(ctx, entry->message);
                }
            } else {
                // For single-line messages, send as before
                if (fmt_len + 1 < sizeof(formatted)) {
                    formatted[fmt_len++] = ' ';
                    formatted[fmt_len] = '\0';
                }
                size_t msg_len = strlen(entry->message);
                if (fmt_len + msg_len < sizeof(formatted)) {
                    memcpy(formatted + fmt_len, entry->message, msg_len);
                    fmt_len += msg_len;
                    formatted[fmt_len] = '\0';
                }
                if (ctx->display_model_initialized) {
                    unsigned int width = (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
                    display_model_append_message(&ctx->display_model, entry->message_id, formatted, width);
                }
                if (emit_output) {
                    session_send_plain_line(ctx, formatted);
                }
            }
        } else {
            if (ctx->display_model_initialized) {
                unsigned int width = (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
                display_model_append_message(&ctx->display_model, entry->message_id, formatted, width);
            }
            if (emit_output) {
                session_send_plain_line(ctx, formatted);
            }
        }

        // Translation mode: show the cached translation under the line.
        if (entry->message_id > 0U) {
            char translated[SSH_CHATTER_TRANSLATION_WORKING_LEN];
            if (session_translation_chat_caption(ctx, entry->message_id,
                                                 translated,
                                                 sizeof(translated))) {
                session_translation_emit_caption(ctx, nullptr, translated,
                                                 true, entry->message_id,
                                                 emit_output);
            }
        }

        // Display attachment URL if present, similar to reply format
        if (emit_output && entry->attachment_type != CHAT_ATTACHMENT_NONE &&
            entry->attachment_target[0] != '\0') {
            const char *label =
                chat_attachment_type_label(entry->attachment_type);
            char attachment_line[SSH_CHATTER_MESSAGE_LIMIT];
            snprintf(attachment_line, sizeof(attachment_line),
                     "    (%s)" ANSI_RESET " %s", label,
                     entry->attachment_target);
            session_send_plain_line(ctx, attachment_line);

            if (entry->attachment_caption[0] != '\0') {
                char caption_line[SSH_CHATTER_MESSAGE_LIMIT];
                snprintf(caption_line, sizeof(caption_line),
                         "    -> %s", entry->attachment_caption);
                session_send_plain_line(ctx, caption_line);
            }
        }

        char reaction_summary[SSH_CHATTER_MESSAGE_LIMIT];
        if (chat_history_entry_build_reaction_summary(
                entry, reaction_summary, sizeof(reaction_summary),
                ctx->ui_language)) {
            char reaction_line[SSH_CHATTER_MESSAGE_LIMIT];
            snprintf(reaction_line, sizeof(reaction_line), "    - %s",
                     reaction_summary);
            if (ctx->display_model_initialized) {
                unsigned int width =
                    (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
                display_model_append_message(&ctx->display_model,
                                             entry->message_id, reaction_line,
                                             width);
            }
            if (emit_output) {
                session_send_plain_line(ctx, reaction_line);
            }
        }

        // Incoming lines join the batched translator; the translation shows
        // up once the batch returns.
        if (emit_output) {
            session_translation_note_chat_line(ctx, entry);
        }

        session_output_restore_kind(ctx, previous_kind);
        return;
    }

    // For non-user messages, check if multiline and send accordingly
    const bool multiline = strchr(entry->message, '\n') != nullptr;
    if (multiline) {
        if (ctx->display_model_initialized) {
            unsigned int width = (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
            display_model_append_message(&ctx->display_model, entry->message_id,
                                         entry->message, width);
        }
        if (emit_output) {
            session_send_multiline_message(ctx, entry->message);
        }
    } else {
        if (ctx->display_model_initialized) {
            unsigned int width = (ctx->terminal_width > 0U) ? ctx->terminal_width : 80U;
            display_model_append_message(&ctx->display_model, entry->message_id,
                                         entry->message, width);
        }
        if (emit_output) {
            session_send_plain_line(ctx, entry->message);
        }
    }

    session_output_restore_kind(ctx, previous_kind);
}

void session_send_history_entry(session_ctx_t *ctx,
                                const chat_history_entry_t *entry)
{
    session_render_history_entry(ctx, entry, true);
}

// Present a summary of a poll, optionally showing the label used for named polls.
static void session_send_poll_summary_generic(session_ctx_t *ctx,
                                              const poll_state_t *poll,
                                              const char *label)
{
    if (ctx == nullptr || poll == nullptr) {
        return;
    }

    if (!poll->active || poll->option_count == 0U) {
        if (label == nullptr) {
            session_send_system_line(ctx, "No active poll right now.");
        } else {
            char message[128];
            snprintf(message, sizeof(message), "Poll '%s' is not active.",
                     label);
            session_send_system_line(ctx, message);
        }
        return;
    }

    char header[SSH_CHATTER_MESSAGE_LIMIT];
    enum {
        SESSION_POLL_HEADER_QUESTION_PREC = SSH_CHATTER_MESSAGE_LIMIT / 2,
        SESSION_POLL_HEADER_LABEL_PREC = SSH_CHATTER_POLL_LABEL_LEN - 1,
        SESSION_POLL_OPTION_TEXT_PREC = SSH_CHATTER_MESSAGE_LIMIT / 2
    };
    const char *mode_suffix = poll->allow_multiple ? " (multiple choice)" : "";
    if (label == nullptr) {
        snprintf(header, sizeof(header), "Poll #%" PRIu64 ": %.*s%s", poll->id,
                 SESSION_POLL_HEADER_QUESTION_PREC, poll->question,
                 mode_suffix);
    } else {
        snprintf(header, sizeof(header), "Poll [%.*s] #%" PRIu64 ": %.*s%s",
                 SESSION_POLL_HEADER_LABEL_PREC, label, poll->id,
                 SESSION_POLL_HEADER_QUESTION_PREC, poll->question,
                 mode_suffix);
    }
    session_send_system_line(ctx, header);

    for (size_t idx = 0U; idx < poll->option_count; ++idx) {
        char option_line[SSH_CHATTER_MESSAGE_LIMIT];
        uint32_t votes = poll->options[idx].votes;
        if (label == nullptr) {
            snprintf(option_line, sizeof(option_line),
                     "  /%zu - %.*s (%u vote%s)", idx + 1U,
                     SESSION_POLL_OPTION_TEXT_PREC, poll->options[idx].text,
                     votes, votes == 1U ? "" : "s");
        } else {
            snprintf(option_line, sizeof(option_line),
                     "  /%zu %.*s - %.*s (%u vote%s)", idx + 1U,
                     SESSION_POLL_HEADER_LABEL_PREC, label,
                     SESSION_POLL_OPTION_TEXT_PREC, poll->options[idx].text,
                     votes, votes == 1U ? "" : "s");
        }
        session_send_system_line(ctx, option_line);
    }

    if (label == nullptr) {
        if (poll->allow_multiple) {
            session_send_system_line(
                ctx, "Vote with /1 through /5 (multiple selections allowed).");
        } else {
            session_send_system_line(ctx, "Vote with /1 through /5.");
        }
    } else {
        char footer[192];
        if (poll->allow_multiple) {
            snprintf(footer, sizeof(footer),
                     "Vote with /1 %s through /%zu %s (multiple selections "
                     "allowed).",
                     label, poll->option_count, label);
        } else {
            snprintf(footer, sizeof(footer), "Vote with /1 %s through /%zu %s.",
                     label, poll->option_count, label);
        }
        session_send_system_line(ctx, footer);
    }
}

// Gather the main poll and any named polls and present summaries to the caller.
static __attribute__((unused)) void
session_send_poll_summary(session_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }

    host_t *host = ctx->owner;
    poll_state_t main_snapshot = {0};
    named_poll_state_t named_snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
    size_t named_count = 0U;

    ttak_mutex_lock(&host->lock);
    main_snapshot = host->poll;
    for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
        if (host->named_polls[idx].label[0] == '\0') {
            continue;
        }
        named_snapshot[named_count++] = host->named_polls[idx];
        if (named_count >= SSH_CHATTER_MAX_NAMED_POLLS) {
            break;
        }
    }
    ttak_mutex_unlock(&host->lock);

    session_send_poll_summary_generic(ctx, &main_snapshot, nullptr);

    size_t active_named = 0U;
    for (size_t idx = 0U; idx < named_count; ++idx) {
        if (named_snapshot[idx].poll.active &&
            named_snapshot[idx].poll.option_count > 0U) {
            if (active_named == 0U) {
                session_send_system_line(ctx, "Active named polls:");
            }
            session_send_poll_summary_generic(ctx, &named_snapshot[idx].poll,
                                              named_snapshot[idx].label);
            ++active_named;
        }
    }

    if (active_named == 0U) {
        session_send_system_line(
            ctx, "No active named polls. Use /vote <label> "
                 "<question>|<option1>|<option2> or /vote-single for a "
                 "single-choice poll.");
    }
}

// Provide a lightweight overview of every named poll regardless of status.
static __attribute__((unused)) void session_list_named_polls(session_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }

    host_t *host = ctx->owner;
    named_poll_state_t snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
    size_t count = 0U;

    ttak_mutex_lock(&host->lock);
    for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
        if (host->named_polls[idx].label[0] == '\0') {
            continue;
        }
        snapshot[count++] = host->named_polls[idx];
        if (count >= SSH_CHATTER_MAX_NAMED_POLLS) {
            break;
        }
    }
    ttak_mutex_unlock(&host->lock);

    if (count == 0U) {
        session_send_system_line(
            ctx, "No named polls exist. Start one with /vote <label> "
                 "<question>|<option1>|<option2> or /vote-single "
                 "for single-choice voting.");
        return;
    }

    session_send_system_line(ctx, "Named polls overview:");
    for (size_t idx = 0U; idx < count; ++idx) {
        const named_poll_state_t *entry = &snapshot[idx];
        char line[SSH_CHATTER_MESSAGE_LIMIT];
        const char *status = entry->poll.active ? "active" : "inactive";
        const char *mode =
            entry->poll.allow_multiple ? "multiple choice" : "single choice";
        snprintf(line, sizeof(line), "- [%s] %s (options: %zu, %s, %s)",
                 entry->label, entry->poll.question, entry->poll.option_count,
                 status, mode);
        session_send_system_line(ctx, line);
    }
}

static bool
chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry,
                                          char *buffer, size_t length,
                                          session_ui_language_t lang)
{
    if (entry == nullptr || buffer == nullptr || length == 0U) {
        return false;
    }

    buffer[0] = '\0';
    bool any = false;
    size_t offset = 0U;

    if (lang >= SESSION_UI_LANGUAGE_COUNT) {
        lang = SESSION_UI_LANGUAGE_EN;
    }

    for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
        uint32_t count = entry->reaction_counts[idx];
        if (count == 0U) {
            continue;
        }

        const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
        const char *label = descriptor->localized_label[lang];
        if (label == nullptr || label[0] == '\0') {
            label = descriptor->label;
        }
        char chunk[64];
        snprintf(chunk, sizeof(chunk), "[%s: %u]", label, count);

        size_t chunk_len = strlen(chunk);
        if (chunk_len + 1U >= length - offset) {
            break;
        }

        if (any) {
            buffer[offset++] = ' ';
            buffer[offset++] = '|';
            buffer[offset++] = ' ';
        }
        memcpy(buffer + offset, chunk, chunk_len);
        offset += chunk_len;
        buffer[offset] = '\0';
        any = true;
    }

    return any;
}

static const char *chat_attachment_type_label(chat_attachment_type_t type)
{
    switch (type) {
    case CHAT_ATTACHMENT_IMAGE:
        return "image";
    case CHAT_ATTACHMENT_VIDEO:
        return "video";
    case CHAT_ATTACHMENT_AUDIO:
        return "audio";
    case CHAT_ATTACHMENT_FILE:
        return "file";
    case CHAT_ATTACHMENT_NONE:
    default:
        return "attachment";
    }
}
