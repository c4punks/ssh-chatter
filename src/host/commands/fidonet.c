/**
 * @file fidonet.c
 * @desc The /fido command: read and write FidoNet echomail carried by the
 *       node in src/host/fidonet/node.c.
 *
 *         /fido                         node status and carried areas
 *         /fido list <area> [page]      threads, newest page first
 *         /fido read <area> <n>         one message
 *         /fido post <area> <subject>|<text>
 *         /fido reply <area> <n> <text>
 *         /fido poll                    poll the uplink now (operator)
 *         /fido hide|unhide <area> <n>  hide a message here (operator)
 *
 *       Text typed on one line may use "\n" for line breaks.  Posting obeys
 *       the BBS mute list and post throttle; NETMAIL is operator-only.
 */

#define FIDO_LIST_PAGE 20U
#define FIDO_LIST_MAX 20000U
#define FIDO_THREAD_MAX_DEPTH 4U
#define FIDO_POST_INTERVAL_SECONDS 30

typedef struct fido_summary {
    size_t number;
    char from[64];
    char subject[96];
    char msgid[FTN_MSGID_LEN];
    char reply[FTN_MSGID_LEN];
    time_t written;
    uint32_t flags;
} fido_summary_t;

typedef struct fido_summary_list {
    fido_summary_t *items;
    size_t count;
    size_t cap;
} fido_summary_list_t;

static bool fido_collect_visit(size_t number, const ftn_message_t *msg,
                               void *user)
{
    fido_summary_list_t *list = user;
    if (list->count >= FIDO_LIST_MAX) {
        return false;
    }
    if (list->count == list->cap) {
        size_t next = list->cap == 0U ? 64U : list->cap * 2U;
        fido_summary_t *grown = realloc(list->items, next * sizeof(*grown));
        if (grown == nullptr) {
            return false;
        }
        list->items = grown;
        list->cap = next;
    }
    fido_summary_t *item = &list->items[list->count++];
    item->number = number;
    snprintf(item->from, sizeof(item->from), "%s", msg->from);
    snprintf(item->subject, sizeof(item->subject), "%s", msg->subject);
    snprintf(item->msgid, sizeof(item->msgid), "%s", msg->msgid);
    snprintf(item->reply, sizeof(item->reply), "%s", msg->reply);
    item->written = msg->written != 0 ? msg->written : msg->imported;
    item->flags = msg->flags;
    return true;
}

static bool session_fido_is_operator(const session_ctx_t *ctx)
{
    return ctx->user.is_operator || ctx->user.is_lan_operator;
}

/* The canonical area tag for a user argument, enforcing NETMAIL access. */
static const char *session_fido_area(session_ctx_t *ctx, const char *arg)
{
    host_fidonet_t *fido = ctx->owner->fidonet;
    const char *tag = fido_area_lookup(fido, arg);
    if (tag == nullptr) {
        session_send_system_line(ctx, "This node does not carry that area. "
                                      "Type /fido to see the list.");
        return nullptr;
    }
    if (strcmp(tag, FTN_NETMAIL_AREA) == 0 && !session_fido_is_operator(ctx)) {
        session_send_system_line(ctx, "NETMAIL is for operators only.");
        return nullptr;
    }
    return tag;
}

static void session_fido_status(session_ctx_t *ctx)
{
    host_fidonet_t *fido = ctx->owner->fidonet;
    char self_text[FTN_ADDR_TEXT_LEN], uplink_text[FTN_ADDR_TEXT_LEN];
    char zmh_text[32], line[SSH_CHATTER_MESSAGE_LIMIT];
    ftn_addr_format(&fido->self, self_text, sizeof(self_text));
    ftn_addr_format(&fido->uplink, uplink_text, sizeof(uplink_text));
    ftn_zmh_format(&fido->zmh, zmh_text, sizeof(zmh_text));

    pthread_mutex_lock(&fido->lock);
    const time_t last_success = fido->last_success;
    const size_t pending = fido->exported_pending;
    char result[sizeof(fido->last_result)];
    snprintf(result, sizeof(result), "%s", fido->last_result);
    pthread_mutex_unlock(&fido->lock);

    session_render_separator(ctx, "FidoNet");
    snprintf(line, sizeof(line), "Node %s, uplink %s", self_text,
             uplink_text);
    session_send_system_line(ctx, line);
    const time_t now = time(nullptr);
    const time_t next = ftn_zmh_window_start(&fido->zmh, now);
    char next_text[32] = "now";
    if (!ftn_zmh_contains(&fido->zmh, now)) {
        struct tm tm_utc;
        gmtime_r(&next, &tm_utc);
        strftime(next_text, sizeof(next_text), "%Y-%m-%d %H:%M UTC",
                 &tm_utc);
    }
    snprintf(line, sizeof(line), "Mail hour %s%s, next window: %s", zmh_text,
             fido->zmh_custom ? " (custom)" : " (zone standard)", next_text);
    session_send_system_line(ctx, line);
    if (fido->poll_minutes > 0U) {
        snprintf(line, sizeof(line), "Also polling every %u minute(s).",
                 fido->poll_minutes);
        session_send_system_line(ctx, line);
    }
    char success_text[32] = "never";
    if (last_success != 0) {
        struct tm tm_utc;
        gmtime_r(&last_success, &tm_utc);
        strftime(success_text, sizeof(success_text), "%Y-%m-%d %H:%M UTC",
                 &tm_utc);
    }
    snprintf(line, sizeof(line),
             "Last good session: %s. Last result: %s. Waiting to send: %zu.",
             success_text, result, pending);
    session_send_system_line(ctx, line);

    session_render_separator(ctx, "Areas");
    bool operator_view = session_fido_is_operator(ctx);
    for (size_t idx = 0U; idx <= fido->area_count; ++idx) {
        const char *tag =
            idx < fido->area_count ? fido->areas[idx] : FTN_NETMAIL_AREA;
        if (idx == fido->area_count && !operator_view) {
            break;
        }
        snprintf(line, sizeof(line), "  %-30s %zu message(s)", tag,
                 ftn_msgbase_count(fido->dir, tag));
        session_send_plain_line(ctx, line);
    }
    if (fido->area_count == 0U) {
        session_send_system_line(ctx, "No echo areas configured "
                                      "(CHATTER_FIDO_AREAS).");
    }
    session_send_system_line(
        ctx, "Commands: /fido list <area> [page], /fido read <area> <n>, "
             "/fido post <area> <subject>|<text>, /fido reply <area> <n> "
             "<text>");
}

/* Thread order over list->items: replies (REPLY matching an earlier
 * MSGID) follow their parent.  Fills order[] and depth[] (count entries). */
static void session_fido_thread_order(const fido_summary_list_t *list,
                                      size_t *order, size_t *depth)
{
    const size_t n = list->count;
    long *parent = malloc(n * sizeof(*parent));
    long *first_child = malloc(n * sizeof(*first_child));
    long *last_child = malloc(n * sizeof(*last_child));
    long *next_sibling = malloc(n * sizeof(*next_sibling));
    size_t *stack = malloc(n * sizeof(*stack));
    size_t *stack_depth = malloc(n * sizeof(*stack_depth));
    if (parent == nullptr || first_child == nullptr || last_child == nullptr ||
        next_sibling == nullptr || stack == nullptr ||
        stack_depth == nullptr) {
        for (size_t idx = 0U; idx < n; ++idx) {
            order[idx] = idx;
            depth[idx] = 0U;
        }
        goto done;
    }
    for (size_t idx = 0U; idx < n; ++idx) {
        parent[idx] = -1;
        first_child[idx] = -1;
        last_child[idx] = -1;
        next_sibling[idx] = -1;
        if (list->items[idx].reply[0] == '\0') {
            continue;
        }
        for (size_t back = idx; back > 0U; --back) {
            if (strcmp(list->items[back - 1U].msgid,
                       list->items[idx].reply) == 0) {
                parent[idx] = (long)(back - 1U);
                break;
            }
        }
        if (parent[idx] >= 0) {
            const long p = parent[idx];
            if (last_child[p] < 0) {
                first_child[p] = (long)idx;
            } else {
                next_sibling[last_child[p]] = (long)idx;
            }
            last_child[p] = (long)idx;
        }
    }
    size_t written = 0U;
    for (size_t root = 0U; root < n; ++root) {
        if (parent[root] >= 0) {
            continue;
        }
        size_t top = 0U;
        stack[top] = root;
        stack_depth[top] = 0U;
        ++top;
        while (top > 0U) {
            --top;
            const size_t node = stack[top];
            const size_t level = stack_depth[top];
            order[written] = node;
            depth[written] = level < FIDO_THREAD_MAX_DEPTH
                                 ? level
                                 : FIDO_THREAD_MAX_DEPTH;
            ++written;
            /* Push children in reverse so the oldest comes out first. */
            size_t child_count = 0U;
            for (long c = first_child[node]; c >= 0; c = next_sibling[c]) {
                ++child_count;
            }
            size_t slot = top + child_count;
            for (long c = first_child[node]; c >= 0; c = next_sibling[c]) {
                --slot;
                stack[slot] = (size_t)c;
                stack_depth[slot] = level + 1U;
            }
            top += child_count;
        }
    }
done:
    free(parent);
    free(first_child);
    free(last_child);
    free(next_sibling);
    free(stack);
    free(stack_depth);
}

static void session_fido_list(session_ctx_t *ctx, const char *area_arg,
                              const char *page_arg)
{
    host_fidonet_t *fido = ctx->owner->fidonet;
    const char *tag = session_fido_area(ctx, area_arg);
    if (tag == nullptr) {
        return;
    }
    unsigned long page = page_arg != nullptr ? strtoul(page_arg, nullptr, 10)
                                             : 1UL;
    if (page == 0UL) {
        page = 1UL;
    }

    fido_summary_list_t list = {0};
    ftn_msgbase_each(fido->dir, tag, false, fido_collect_visit, &list);
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "%s (%zu)", tag, list.count);
    session_render_separator(ctx, line);
    if (list.count == 0U) {
        session_send_system_line(ctx, "No messages yet. They arrive at the "
                                      "next mail hour.");
        free(list.items);
        return;
    }

    size_t *order = malloc(list.count * sizeof(*order));
    size_t *depth = malloc(list.count * sizeof(*depth));
    if (order == nullptr || depth == nullptr) {
        free(order);
        free(depth);
        free(list.items);
        return;
    }
    session_fido_thread_order(&list, order, depth);

    const size_t pages = (list.count + FIDO_LIST_PAGE - 1U) / FIDO_LIST_PAGE;
    if (page > pages) {
        page = pages;
    }
    const size_t end = list.count - (size_t)(page - 1UL) * FIDO_LIST_PAGE;
    const size_t begin = end > FIDO_LIST_PAGE ? end - FIDO_LIST_PAGE : 0U;
    const bool operator_view = session_fido_is_operator(ctx);
    for (size_t slot = begin; slot < end; ++slot) {
        const fido_summary_t *item = &list.items[order[slot]];
        const bool hidden =
            ftn_hidden_contains(fido->dir, tag, item->number);
        char when[16] = "";
        if (item->written != 0) {
            struct tm tm_utc;
            gmtime_r(&item->written, &tm_utc);
            strftime(when, sizeof(when), "%m-%d %H:%M", &tm_utc);
        }
        char indent[2U * FIDO_THREAD_MAX_DEPTH + 8U] = "";
        if (depth[slot] > 0U) {
            size_t pad = 2U * (depth[slot] - 1U);
            memset(indent, ' ', pad);
            snprintf(indent + pad, sizeof(indent) - pad, "↳ ");
        }
        if (hidden && !operator_view) {
            snprintf(line, sizeof(line), "%5zu %s(hidden)", item->number,
                     indent);
        } else {
            snprintf(line, sizeof(line), "%5zu %s%s%s  %s  [%s]%s",
                     item->number, indent,
                     (item->flags & FTN_MSG_FLAG_LOCAL) != 0U ? "*" : "",
                     item->subject[0] != '\0' ? item->subject : "(no subject)",
                     item->from, when, hidden ? " [hidden]" : "");
        }
        session_send_plain_line(ctx, line);
    }
    snprintf(line, sizeof(line),
             "Page %lu/%zu. '/fido list %s %lu' for older. * = written here.",
             page, pages, tag, page < pages ? page + 1UL : pages);
    session_send_system_line(ctx, line);
    free(order);
    free(depth);
    free(list.items);
}

static bool session_fido_parse_number(session_ctx_t *ctx, const char *text,
                                      size_t *out)
{
    char *end = nullptr;
    errno = 0;
    unsigned long value = text != nullptr ? strtoul(text, &end, 10) : 0UL;
    if (text == nullptr || errno != 0 || end == text || *end != '\0' ||
        value == 0UL) {
        session_send_system_line(ctx, "Give a message number from "
                                      "'/fido list'.");
        return false;
    }
    *out = (size_t)value;
    return true;
}

static void session_fido_read(session_ctx_t *ctx, const char *area_arg,
                              const char *number_arg)
{
    host_fidonet_t *fido = ctx->owner->fidonet;
    const char *tag = session_fido_area(ctx, area_arg);
    size_t number = 0U;
    if (tag == nullptr || !session_fido_parse_number(ctx, number_arg, &number)) {
        return;
    }
    if (ftn_hidden_contains(fido->dir, tag, number) &&
        !session_fido_is_operator(ctx)) {
        session_send_system_line(ctx, "That message has been hidden.");
        return;
    }
    ftn_message_t msg;
    if (!ftn_msgbase_read(fido->dir, tag, number, &msg)) {
        session_send_system_line(ctx, "No message with that number.");
        return;
    }
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "%s #%zu", tag, number);
    session_render_separator(ctx, line);
    snprintf(line, sizeof(line), "From: %s%s%s%s", msg.from,
             msg.origin_addr[0] != '\0' ? " (" : "", msg.origin_addr,
             msg.origin_addr[0] != '\0' ? ")" : "");
    session_send_plain_line(ctx, line);
    snprintf(line, sizeof(line), "To:   %s", msg.to);
    session_send_plain_line(ctx, line);
    snprintf(line, sizeof(line), "Subj: %s", msg.subject);
    session_send_plain_line(ctx, line);
    if (msg.written != 0) {
        struct tm tm_utc;
        gmtime_r(&msg.written, &tm_utc);
        strftime(line, sizeof(line), "Date: %Y-%m-%d %H:%M:%S UTC", &tm_utc);
        session_send_plain_line(ctx, line);
    }
    session_render_separator(ctx, "{Body}");
    char *cursor = msg.body != nullptr ? msg.body : (char *)"";
    for (;;) {
        char *newline = strchr(cursor, '\n');
        if (newline != nullptr) {
            *newline = '\0';
        }
        session_send_plain_line(ctx, cursor);
        if (newline == nullptr) {
            break;
        }
        cursor = newline + 1;
    }
    snprintf(line, sizeof(line), "Reply with '/fido reply %s %zu <text>'.",
             tag, number);
    session_send_system_line(ctx, line);
    ftn_message_free(&msg);
}

/* Mute list and post throttle shared with the BBS. */
static bool session_fido_may_post(session_ctx_t *ctx)
{
    host_t *host = ctx->owner;
    if (!session_bbs_ensure_live_storage(host)) {
        return true; /* no BBS state: nothing to enforce */
    }
    bool allowed = true;
    ttak_mutex_lock(&host->lock);
    if (session_bbs_mute_blocks_locked(ctx, host)) {
        session_send_system_line(ctx, "You are muted and cannot post right "
                                      "now.");
        allowed = false;
    } else if (!session_fido_is_operator(ctx)) {
        const time_t now = time(nullptr);
        bbs_rate_limit_entry_t *limit =
            host_bbs_rate_limit_ensure_locked(host, ctx->user.name);
        if (limit != nullptr && limit->last_post_at != 0 &&
            now - limit->last_post_at < FIDO_POST_INTERVAL_SECONDS) {
            session_send_system_line(ctx, "You are posting too quickly. Try "
                                          "again in a moment.");
            allowed = false;
        } else if (limit != nullptr) {
            limit->last_post_at = now;
        }
    }
    ttak_mutex_unlock(&host->lock);
    return allowed;
}

/* Turn typed "\n" sequences into line breaks, in place. */
static void session_fido_unescape(char *text)
{
    size_t out = 0U;
    for (size_t idx = 0U; text[idx] != '\0'; ++idx) {
        if (text[idx] == '\\' && text[idx + 1U] == 'n') {
            text[out++] = '\n';
            ++idx;
        } else {
            text[out++] = text[idx];
        }
    }
    text[out] = '\0';
}

static void session_fido_submit(session_ctx_t *ctx, const char *tag,
                                const char *to, const char *subject,
                                char *text, const char *reply_msgid)
{
    session_fido_unescape(text);
    if (session_security_check_text(ctx, "FidoNet message", text,
                                    strlen(text), false) !=
            HOST_SECURITY_SCAN_CLEAN ||
        !session_fido_may_post(ctx)) {
        return;
    }
    size_t number = host_fidonet_post(ctx->owner, tag, ctx->user.name, to,
                                      subject, text, reply_msgid);
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (number == 0U) {
        session_send_system_line(ctx, "Could not queue the message.");
        return;
    }
    snprintf(line, sizeof(line),
             "Queued as %s #%zu; it goes out at the next mail hour.", tag,
             number);
    session_send_system_line(ctx, line);
}

static void session_fido_post(session_ctx_t *ctx, const char *area_arg,
                              char *rest)
{
    const char *tag = session_fido_area(ctx, area_arg);
    if (tag == nullptr) {
        return;
    }
    if (strcmp(tag, FTN_NETMAIL_AREA) == 0) {
        session_send_system_line(ctx, "Writing netmail is not supported "
                                      "yet.");
        return;
    }
    char *bar = rest != nullptr ? strchr(rest, '|') : nullptr;
    if (bar == nullptr) {
        session_send_system_line(ctx,
                                 "Usage: /fido post <area> <subject>|<text>");
        return;
    }
    *bar = '\0';
    char *subject = rest;
    char *text = bar + 1;
    trim_whitespace_inplace(subject);
    trim_whitespace_inplace(text);
    if (subject[0] == '\0' || text[0] == '\0') {
        session_send_system_line(ctx,
                                 "Usage: /fido post <area> <subject>|<text>");
        return;
    }
    session_fido_submit(ctx, tag, "All", subject, text, nullptr);
}

static void session_fido_reply(session_ctx_t *ctx, const char *area_arg,
                               const char *number_arg, char *text)
{
    host_fidonet_t *fido = ctx->owner->fidonet;
    const char *tag = session_fido_area(ctx, area_arg);
    size_t number = 0U;
    if (tag == nullptr || !session_fido_parse_number(ctx, number_arg, &number)) {
        return;
    }
    if (strcmp(tag, FTN_NETMAIL_AREA) == 0) {
        session_send_system_line(ctx, "Writing netmail is not supported "
                                      "yet.");
        return;
    }
    if (text == nullptr || text[0] == '\0') {
        session_send_system_line(ctx,
                                 "Usage: /fido reply <area> <n> <text>");
        return;
    }
    ftn_message_t original;
    if (!ftn_msgbase_read(fido->dir, tag, number, &original)) {
        session_send_system_line(ctx, "No message with that number.");
        return;
    }
    char subject[FTN_SUBJ_LEN * 4U];
    if (strncasecmp(original.subject, "Re:", 3) == 0) {
        snprintf(subject, sizeof(subject), "%s", original.subject);
    } else {
        snprintf(subject, sizeof(subject), "Re: %s", original.subject);
    }
    char to[FTN_NAME_LEN * 4U];
    snprintf(to, sizeof(to), "%s", original.from);
    char reply_msgid[FTN_MSGID_LEN];
    snprintf(reply_msgid, sizeof(reply_msgid), "%s", original.msgid);
    ftn_message_free(&original);
    session_fido_submit(ctx, tag, to, subject, text,
                        reply_msgid[0] != '\0' ? reply_msgid : nullptr);
}

static void session_handle_fido(session_ctx_t *ctx, const char *arguments)
{
    if (ctx == nullptr || ctx->owner == nullptr) {
        return;
    }
    if (ctx->owner->fidonet == nullptr) {
        session_send_system_line(ctx, "FidoNet is not set up on this server "
                                      "(CHATTER_FIDO_ADDRESS).");
        return;
    }
    char working[SSH_CHATTER_MAX_INPUT_LEN];
    snprintf(working, sizeof(working), "%s",
             arguments != nullptr ? arguments : "");
    trim_whitespace_inplace(working);

    char *save = nullptr;
    char *command = strtok_r(working, " \t", &save);
    if (command == nullptr || strcasecmp(command, "areas") == 0 ||
        strcasecmp(command, "status") == 0) {
        session_fido_status(ctx);
        return;
    }
    if (strcasecmp(command, "poll") == 0) {
        if (!session_fido_is_operator(ctx)) {
            session_send_system_line(ctx, "Only operators can poll the "
                                          "uplink.");
            return;
        }
        host_fidonet_request_poll(ctx->owner);
        session_send_system_line(ctx, "Polling the uplink now; '/fido' shows "
                                      "the result.");
        return;
    }

    char *area = strtok_r(nullptr, " \t", &save);
    if (area == nullptr) {
        session_send_system_line(
            ctx, "Usage: /fido [list|read|post|reply|poll|hide|unhide] ...");
        return;
    }
    if (strcasecmp(command, "list") == 0) {
        session_fido_list(ctx, area, strtok_r(nullptr, " \t", &save));
    } else if (strcasecmp(command, "read") == 0) {
        session_fido_read(ctx, area, strtok_r(nullptr, " \t", &save));
    } else if (strcasecmp(command, "post") == 0) {
        session_fido_post(ctx, area, save);
    } else if (strcasecmp(command, "reply") == 0) {
        char *number = strtok_r(nullptr, " \t", &save);
        if (save != nullptr) {
            trim_whitespace_inplace(save);
        }
        session_fido_reply(ctx, area, number, save);
    } else if (strcasecmp(command, "hide") == 0 ||
               strcasecmp(command, "unhide") == 0) {
        const bool hide = strcasecmp(command, "hide") == 0;
        size_t number = 0U;
        const char *tag = nullptr;
        if (!session_fido_is_operator(ctx)) {
            session_send_system_line(ctx, "Only operators can hide "
                                          "messages.");
        } else if ((tag = session_fido_area(ctx, area)) != nullptr &&
                   session_fido_parse_number(
                       ctx, strtok_r(nullptr, " \t", &save), &number)) {
            host_fidonet_t *fido = ctx->owner->fidonet;
            bool ok = ftn_hidden_set(fido->dir, tag, number, hide);
            char line[SSH_CHATTER_MESSAGE_LIMIT];
            snprintf(line, sizeof(line), "%s #%zu %s.", tag, number,
                     !ok    ? "could not be updated"
                     : hide ? "is now hidden"
                            : "is visible again");
            session_send_system_line(ctx, line);
            if (ok) {
                ttak_mutex_lock(&ctx->owner->lock);
                host_bbs_modlog_append_locked(ctx->owner, ctx->user.name,
                                              hide ? "fido-hide"
                                                   : "fido-unhide",
                                              tag);
                ttak_mutex_unlock(&ctx->owner->lock);
            }
        }
    } else {
        session_send_system_line(
            ctx, "Usage: /fido [list|read|post|reply|poll|hide|unhide] ...");
    }
}
