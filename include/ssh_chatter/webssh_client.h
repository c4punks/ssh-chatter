/**
 * @file webssh_client.h
 * @desc In-process client used by the web front end. It registers with the
 *       client manager, keeps a ring buffer of recent chat history for the
 *       web view, and posts messages on behalf of web users.
 */
#ifndef SSH_CHATTER_WEBSSH_CLIENT_H
#define SSH_CHATTER_WEBSSH_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

struct host;
struct client_manager;
struct chat_history_entry;

/* Opaque handle; the definition lives in webssh_client.c. */
typedef struct webssh_client webssh_client_t;

/**
 * @desc Create a web client and register it with the client manager.
 * @param host    Host that receives posted messages.
 * @param manager Manager that will feed history entries to this client.
 * @return New client, or nullptr on failure (including a full manager).
 */
webssh_client_t *webssh_client_create(struct host *host,
                                      struct client_manager *manager);

/**
 * @desc Unregister from the manager and free the client.
 * @param client Client to destroy (nullptr is ignored).
 */
void webssh_client_destroy(webssh_client_t *client);

/**
 * @desc Copy buffered history, oldest first, into the caller's array.
 * @param client   Client to read from.
 * @param buffer   Destination array.
 * @param capacity Number of entries buffer can hold.
 * @return Number of entries copied.
 */
size_t webssh_client_snapshot(webssh_client_t *client,
                              struct chat_history_entry *buffer,
                              size_t capacity);

/**
 * @desc Post a chat message to the room as the given web user.
 * @param client   Web client.
 * @param username Display name to post as.
 * @param message  Message body.
 * @return true when the host accepted the message.
 */
bool webssh_client_send_message(webssh_client_t *client, const char *username,
                                const char *message);

#endif
