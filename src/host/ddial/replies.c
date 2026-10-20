/**
 * @file replies.c
 * @desc DDial replies taken into Chatter's reply threads.
 *
 * A DDial client replies with chat whose body ends in a quote of the line
 * it answers ("text^ >>RE:[N] author: quote", see protocol.c).  When such
 * a line lands in history, host_ddial_link_reply() looks back through
 * recent history for the quoted line -- a Chatter message, a DDial line or
 * a Chatter reply -- and records the DDial line as a Chatter reply to it,
 * so it shows in reply trees and can itself be replied to as r#<id>.
 *
 * Which DDial history line became which reply is kept in a small table
 * keyed by the line's message id; the display filter reads it to show the
 * line in Chatter's reply form ("->[r#5 #d12] oxy: text").  The table is
 * not saved: host_ddial_replies_rebuild() fills it again at startup by
 * running the same linking over the loaded history.  Linking is
 * idempotent -- a line that already has its reply entry is only mapped --
 * so that pass is also how old history is brought in.
 */

#include "ssh_chatter/ddial_protocol.h"
#include "ssh_chatter/host.h"

#include <pthread.h>
#include <string.h>
#include <strings.h>

/* How far back to look for the quoted line. */
#define DDIAL_REPLY_PARENT_SCAN 600U
#define DDIAL_REPLY_LINK_CAPACITY 4096U

typedef struct ddial_reply_link {
    uint64_t message_id; /* the DDial history line */
    uint64_t reply_id;   /* its Chatter reply entry */
    char parent_label[40]; /* "#12", "#d12" or "r#5" */
} ddial_reply_link_t;

static pthread_mutex_t g_ddial_reply_link_lock = PTHREAD_MUTEX_INITIALIZER;
static ddial_reply_link_t g_ddial_reply_links[DDIAL_REPLY_LINK_CAPACITY];
static size_t g_ddial_reply_link_next = 0U;

static void ddial_reply_link_put(uint64_t message_id, uint64_t reply_id,
                                 const char *parent_label)
{
    pthread_mutex_lock(&g_ddial_reply_link_lock);
    ddial_reply_link_t *slot = nullptr;
    for (size_t i = 0U; i < DDIAL_REPLY_LINK_CAPACITY; ++i) {
        if (g_ddial_reply_links[i].message_id == message_id) {
            slot = &g_ddial_reply_links[i];
            break;
        }
    }
    if (slot == nullptr) {
        slot = &g_ddial_reply_links[g_ddial_reply_link_next];
        g_ddial_reply_link_next =
            (g_ddial_reply_link_next + 1U) % DDIAL_REPLY_LINK_CAPACITY;
    }
    slot->message_id = message_id;
    slot->reply_id = reply_id;
    snprintf(slot->parent_label, sizeof(slot->parent_label), "%s",
             parent_label);
    pthread_mutex_unlock(&g_ddial_reply_link_lock);
}

bool host_ddial_reply_link_get(uint64_t message_id, uint64_t *reply_id,
                               char *parent_label, size_t label_cap)
{
    if (message_id == 0U) {
        return false;
    }
    bool found = false;
    pthread_mutex_lock(&g_ddial_reply_link_lock);
    for (size_t i = 0U; i < DDIAL_REPLY_LINK_CAPACITY; ++i) {
        const ddial_reply_link_t *link = &g_ddial_reply_links[i];
        if (link->message_id == message_id) {
            if (reply_id != nullptr) {
                *reply_id = link->reply_id;
            }
            if (parent_label != nullptr && label_cap > 0U) {
                snprintf(parent_label, label_cap, "%s", link->parent_label);
            }
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ddial_reply_link_lock);
    return found;
}

/* Chatter's own reply lines: "->[r#<reply> <target>] <user>: <text>". */
static bool ddial_reply_parse_chatter_reply_line(const char *line,
                                                 uint64_t *reply_id,
                                                 char *user, size_t user_cap,
                                                 const char **text)
{
    if (line == nullptr || strncmp(line, "->[r#", 5U) != 0) {
        return false;
    }
    const char *label = line + 5;
    const char *space = strchr(label, ' ');
    const char *close = strchr(label, ']');
    if (space == nullptr || close == nullptr || space > close ||
        close[1] != ' ') {
        return false;
    }
    char label_buf[32];
    size_t label_len = (size_t)(space - label);
    if (label_len == 0U || label_len >= sizeof(label_buf)) {
        return false;
    }
    memcpy(label_buf, label, label_len);
    label_buf[label_len] = '\0';
    if (!host_compact_id_decode(label_buf, reply_id) || *reply_id == 0U) {
        return false;
    }
    const char *name = close + 2;
    const char *sep = strstr(name, ": ");
    if (sep == nullptr || sep == name) {
        return false;
    }
    size_t name_len = (size_t)(sep - name);
    if (name_len >= user_cap) {
        name_len = user_cap - 1U;
    }
    memcpy(user, name, name_len);
    user[name_len] = '\0';
    *text = sep + 2;
    return true;
}

typedef struct ddial_reply_parent {
    uint64_t message_id;      /* parent line's id (0 for a Chatter reply line) */
    uint64_t chatter_reply_id; /* set when the parent is a Chatter reply line */
    bool relayed;             /* parent is a DDial line ("#d<id>") */
} ddial_reply_parent_t;

/* Look back from the reply line (message_id) for the line it quotes.
 * A match whose line number agrees with [N] wins over one that does not. */
static bool ddial_reply_find_parent(host_t *host, uint64_t message_id,
                                    const char *author, uint16_t quoted_slot,
                                    const char *quote,
                                    ddial_reply_parent_t *out)
{
    bool found = false;
    bool found_exact = false;
    ttak_mutex_lock(&host->lock);
    host_history_restore_cache_locked(host);
    size_t idx = host->history_count;
    while (idx > 0U && host->history[idx - 1U].message_id != message_id) {
        --idx;
    }
    size_t scanned = 0U;
    for (size_t i = idx > 0U ? idx - 1U : 0U;
         idx > 0U && i > 0U && scanned < DDIAL_REPLY_PARENT_SCAN && !found_exact;
         --i, ++scanned) {
        const chat_history_entry_t *cand = &host->history[i - 1U];
        char cand_author[SSH_CHATTER_USERNAME_LEN];
        const char *cand_text = nullptr;
        uint16_t cand_slot = 0U;
        uint64_t cand_reply = 0U;
        bool relayed = false;
        if (cand->is_user_message) {
            snprintf(cand_author, sizeof(cand_author), "%s", cand->username);
            cand_text = cand->message;
        } else if (ddial_reply_parse_chatter_reply_line(
                       cand->message, &cand_reply, cand_author,
                       sizeof(cand_author), &cand_text)) {
            /* a Chatter reply line */
        } else if (host_ddial_entry_is_relayed_chat(cand)) {
            bool is_link = false;
            if (!ddial_parse_incoming_chat(cand->message, nullptr, &cand_slot,
                                           nullptr, &is_link, nullptr,
                                           cand_author, sizeof(cand_author),
                                           &cand_text)) {
                continue;
            }
            relayed = true;
        } else {
            continue;
        }
        if (cand_text == nullptr || !ddial_handles_equal(cand_author, author) ||
            !ddial_reply_quote_matches(cand_text, quote)) {
            continue;
        }
        const bool slot_agrees =
            quoted_slot == 0U || !relayed || cand_slot == quoted_slot;
        if (!found || slot_agrees) {
            out->message_id = cand_reply != 0U ? 0U : cand->message_id;
            out->chatter_reply_id = cand_reply;
            out->relayed = relayed;
            found = true;
            found_exact = slot_agrees;
        }
    }
    ttak_mutex_unlock(&host->lock);
    return found && (out->message_id != 0U || out->chatter_reply_id != 0U);
}

/* The reply entry already recorded for this DDial line, if any. */
static uint64_t ddial_reply_find_existing(host_t *host, const char *author,
                                          const char *text, time_t created_at)
{
    uint64_t reply_id = 0U;
    ttak_mutex_lock(&host->lock);
    for (size_t i = 0U; i < host->reply_count; ++i) {
        const chat_reply_entry_t *r = &host->replies[i];
        if (r->in_use && r->created_at == created_at &&
            strcmp(r->username, author) == 0 && strcmp(r->message, text) == 0) {
            reply_id = r->reply_id;
            break;
        }
    }
    ttak_mutex_unlock(&host->lock);
    return reply_id;
}

void host_ddial_link_reply(host_t *host, const chat_history_entry_t *stored)
{
    if (host == nullptr || stored == nullptr || stored->message_id == 0U ||
        !host_ddial_entry_is_relayed_chat(stored)) {
        return;
    }
    char handle[DDIAL_MAX_HANDLE_LEN];
    const char *body = nullptr;
    if (!ddial_parse_incoming_chat(stored->message, nullptr, nullptr, nullptr,
                                   nullptr, nullptr, handle, sizeof(handle),
                                   &body) ||
        body == nullptr) {
        return;
    }
    size_t text_len = 0U;
    uint16_t quoted_slot = 0U;
    char quoted_author[DDIAL_MAX_HANDLE_LEN];
    const char *quote = nullptr;
    if (!ddial_split_reply(body, &text_len, &quoted_slot, quoted_author,
                           sizeof(quoted_author), &quote)) {
        return;
    }
    char text[SSH_CHATTER_MESSAGE_LIMIT];
    if (text_len >= sizeof(text)) {
        text_len = sizeof(text) - 1U;
    }
    memcpy(text, body, text_len);
    text[text_len] = '\0';
    trim_whitespace_inplace(text);
    if (text[0] == '\0') {
        return;
    }

    ddial_reply_parent_t parent = {0};
    if (!ddial_reply_find_parent(host, stored->message_id, quoted_author,
                                 quoted_slot, quote, &parent)) {
        return;
    }

    /* Thread under the parent the way /reply does: a reply to a reply keeps
     * the root message and names the reply it answers. */
    uint64_t parent_message_id = parent.message_id;
    uint64_t parent_reply_id = parent.chatter_reply_id;
    if (parent_reply_id == 0U) {
        uint64_t linked_reply = 0U;
        if (host_ddial_reply_link_get(parent.message_id, &linked_reply,
                                      nullptr, 0U)) {
            parent_reply_id = linked_reply;
        }
    }
    if (parent_reply_id != 0U) {
        chat_reply_entry_t parent_reply = {0};
        if (!host_replies_find_entry_by_id(host, parent_reply_id,
                                           &parent_reply)) {
            if (parent.message_id == 0U) {
                return; /* a Chatter reply that is gone */
            }
            parent_reply_id = 0U;
        } else {
            parent_message_id = parent_reply.parent_message_id;
        }
    }
    if (parent_message_id == 0U) {
        return;
    }

    char parent_label[40];
    char id_label[32];
    if (parent_reply_id != 0U) {
        if (!host_compact_id_encode(parent_reply_id, id_label,
                                    sizeof(id_label))) {
            return;
        }
        snprintf(parent_label, sizeof(parent_label), "r#%s", id_label);
    } else {
        if (!host_compact_id_encode(parent_message_id, id_label,
                                    sizeof(id_label))) {
            return;
        }
        snprintf(parent_label, sizeof(parent_label), "#%s%s",
                 parent.relayed ? "d" : "", id_label);
    }

    uint64_t reply_id =
        ddial_reply_find_existing(host, handle, text, stored->created_at);
    if (reply_id == 0U) {
        chat_reply_entry_t entry = {0};
        entry.parent_message_id = parent_message_id;
        entry.parent_reply_id = parent_reply_id;
        entry.created_at = stored->created_at;
        snprintf(entry.username, sizeof(entry.username), "%s", handle);
        snprintf(entry.message, sizeof(entry.message), "%s", text);
        chat_reply_entry_t committed = {0};
        if (!host_replies_commit_entry(host, &entry, &committed)) {
            return;
        }
        reply_id = committed.reply_id;
    }
    ddial_reply_link_put(stored->message_id, reply_id, parent_label);
}

/* Link every DDial reply in loaded history, oldest first so a reply to a
 * reply finds its parent's link.  Run once both history and reply state
 * are loaded. */
void host_ddial_replies_rebuild(host_t *host)
{
    if (host == nullptr) {
        return;
    }
    ttak_mutex_lock(&host->lock);
    host_history_restore_cache_locked(host);
    size_t count = host->history_count;
    uint64_t *ids = count > 0U ? sshc_gc_calloc(count, sizeof(*ids)) : nullptr;
    size_t found = 0U;
    for (size_t i = 0U; ids != nullptr && i < count; ++i) {
        const chat_history_entry_t *entry = &host->history[i];
        if (entry->message_id != 0U && !entry->is_user_message &&
            strstr(entry->message, "^ >>RE:") != nullptr) {
            ids[found++] = entry->message_id;
        }
    }
    ttak_mutex_unlock(&host->lock);

    size_t linked = 0U;
    for (size_t i = 0U; i < found; ++i) {
        chat_history_entry_t entry = {0};
        if (host_history_find_entry_by_id(host, ids[i], &entry)) {
            host_ddial_link_reply(host, &entry);
            if (host_ddial_reply_link_get(ids[i], nullptr, nullptr, 0U)) {
                ++linked;
            }
        }
    }
    sshc_gc_free(ids);
    if (found > 0U) {
        printf("[ddial] %zu of %zu DDial replies in history linked as replies\n",
               linked, found);
    }
}
