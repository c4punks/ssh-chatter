/**
 * @file display.c
 * @desc The one display-time filter for DDial relay lines in history.
 *
 * History stores what the link sent (the normalized wire text), untouched,
 * so the link roster can be replayed from it.  Whatever shows history to a
 * person -- SSH rendering and scrollback, the live broadcast, the JSON/web
 * event feed -- asks host_ddial_display_view() what to show instead of
 * reading entry->message directly, so old and new entries look the same:
 *
 *   "[SYSOP] 73-.SynerChat #0[T1:..." / "[LINK] -->. + #5[T1:..."
 *       link housekeeping: hidden.
 *   "76}}}3-.DigitalDial-Sta#1^#7[T1=COTOSNET-NYC!"
 *       network map redraws (the NETS screen): hidden, people should not
 *       see cursor-addressed hub lists as scrolling garbage.
 *   "[E-MAIL #012@070 Bob] text"
 *       link e-mail older builds wrote to the room: hidden (it is private).
 *   "71#4[T1:MaxMouse) text"
 *       shown as a Chatter chat message from MaxMouse.
 *   anything else
 *       shown as stored.
 */

#include "ssh_chatter/ddial_protocol.h"
#include "ssh_chatter/host.h"

#include <string.h>

bool host_ddial_display_view(const chat_history_entry_t *entry,
                             chat_history_entry_t *scratch,
                             const chat_history_entry_t **view)
{
    if (view != nullptr) {
        *view = entry;
    }
    if (entry == nullptr || entry->is_user_message) {
        return true;
    }
    /* Link e-mail used to be written to the room; it is private. */
    if (strncmp(entry->message, "[E-MAIL ", 8U) == 0) {
        return false;
    }

    char handle[DDIAL_MAX_HANDLE_LEN];
    const char *body = nullptr;
    bool is_link = false;
    if (scratch != nullptr &&
        ddial_parse_incoming_chat(entry->message, nullptr, nullptr, nullptr,
                                  &is_link, nullptr, handle, sizeof(handle),
                                  &body) &&
        !is_link && handle[0] != '\0' && body != nullptr) {
        /* A DDial reply that joined a Chatter thread reads like a Chatter
         * reply line: "->[r#5 #d12] oxy: text". */
        uint64_t reply_id = 0U;
        char parent_label[40];
        size_t text_len = 0U;
        char reply_label[32];
        if (ddial_split_reply(body, &text_len, nullptr, nullptr, 0U,
                              nullptr) &&
            host_ddial_reply_link_get(entry->message_id, &reply_id,
                                      parent_label, sizeof(parent_label)) &&
            host_compact_id_encode(reply_id, reply_label,
                                   sizeof(reply_label))) {
            *scratch = *entry;
            scratch->is_user_message = false;
            snprintf(scratch->message, sizeof(scratch->message),
                     "->[r#%s %s] %s: %.*s", reply_label, parent_label, handle,
                     (int)text_len, body);
            if (view != nullptr) {
                *view = scratch;
            }
            return true;
        }
        /* Same id, time and reactions; speaker and text taken from the line. */
        *scratch = *entry;
        scratch->is_user_message = true;
        snprintf(scratch->username, sizeof(scratch->username), "%s", handle);
        snprintf(scratch->raw_username, sizeof(scratch->raw_username), "%s",
                 handle);
        snprintf(scratch->message, sizeof(scratch->message), "%s", body);
        if (view != nullptr) {
            *view = scratch;
        }
        return true;
    }

    /* Not a chat line: link housekeeping and the network map redraws stay
     * hidden; everything else displays as stored. */
    if (ddial_roster_line_is_operational(entry->message) ||
        ddial_line_is_network_map_noise(entry->message)) {
        return false;
    }
    return true;
}

/* True for a stored relay line that the display filter presents as chat
 * from a DDial user ("71#4[T1:MaxMouse) text").  These get a message id
 * like Chatter messages so they can be replied to and reacted on. */
bool host_ddial_entry_is_relayed_chat(const chat_history_entry_t *entry)
{
    if (entry == nullptr || entry->is_user_message) {
        return false;
    }
    char handle[DDIAL_MAX_HANDLE_LEN];
    const char *body = nullptr;
    bool is_link = false;
    return ddial_parse_incoming_chat(entry->message, nullptr, nullptr, nullptr,
                                     &is_link, nullptr, handle, sizeof(handle),
                                     &body) &&
           !is_link && handle[0] != '\0' && body != nullptr;
}

/* Label for a stored entry's message id: the compact id, prefixed with 'd'
 * for lines relayed from DDial ("d42" vs "42").  Compact ids always start
 * with a digit, so the prefix never collides with an id; the decoder
 * accepts both spellings.  Returns false when the entry has no id. */
bool host_history_id_label(const chat_history_entry_t *stored, char *buffer,
                           size_t length)
{
    if (buffer == nullptr || length == 0U) {
        return false;
    }
    buffer[0] = '\0';
    if (stored == nullptr || stored->message_id == 0U) {
        return false;
    }
    const bool relayed = host_ddial_entry_is_relayed_chat(stored);
    if (relayed) {
        if (length < 2U) {
            return false;
        }
        buffer[0] = 'd';
    }
    size_t offset = relayed ? 1U : 0U;
    if (!host_compact_id_encode(stored->message_id, buffer + offset,
                                length - offset)) {
        buffer[0] = '\0';
        return false;
    }
    return true;
}
