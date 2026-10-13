/**
 * @file morse_client.h
 * @desc Client for the Reverse Beacon Network telnet feed. A background
 *       thread keeps a connection open, decodes incoming CW spots and relays
 *       them to chat sessions that opted in to the morse feed.
 */
#ifndef SSH_CHATTER_MORSE_CLIENT_H
#define SSH_CHATTER_MORSE_CLIENT_H

#include <stdbool.h>

#include "ssh_chatter/host.h"

/* Opaque handle; the definition lives in morse_client.c. */
typedef struct morse_client morse_client_t;

/**
 * @desc Allocate a client and start its background connect/read thread.
 * @param host Host whose room members receive relayed spots.
 * @return New client, or nullptr on allocation/thread failure.
 */
morse_client_t *morse_client_create(host_t *host);

/**
 * @desc Stop the background thread, close the socket and free the client.
 * @param client Client to destroy (nullptr is ignored).
 */
void morse_client_destroy(morse_client_t *client);

/**
 * @desc Send one line (CRLF is appended) to the remote feed.
 * @param client Connected client.
 * @param line   Non-empty line to send.
 * @return true when the whole line was written, false if disconnected or the
 *         send failed.
 */
bool morse_client_send(morse_client_t *client, const char *line);

/**
 * @desc Report whether the client currently holds a live connection.
 * @param client Client to query.
 * @return true when connected.
 */
bool morse_client_connected(const morse_client_t *client);

#endif // SSH_CHATTER_MORSE_CLIENT_H
