/**
 * @file client.h
 * @desc Registry of in-process (non-terminal) chat clients such as the web
 *       front end and bots. Registered connections are called back for every
 *       new history entry. The registry is lock-free: slots are claimed and
 *       released with atomic compare-and-swap.
 */
#ifndef SSH_CHATTER_CLIENT_H
#define SSH_CHATTER_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

struct host;
struct chat_history_entry;

/* What kind of component sits behind a connection. */
typedef enum client_kind {
    CLIENT_KIND_UNKNOWN = 0,
    CLIENT_KIND_WEBSSH,
    CLIENT_KIND_BOT,
    CLIENT_KIND_AI,
} client_kind_t;

#define CLIENT_IDENTIFIER_LEN 64

/* Opaque registry; holds a fixed number of connection slots. */
typedef struct client_manager client_manager_t;

/*
 * One registered client. The caller owns the storage and fills in kind,
 * identifier, the callbacks and user_data; active and owner are managed by
 * the client manager.
 */
typedef struct client_connection {
    client_kind_t kind;
    char identifier[CLIENT_IDENTIFIER_LEN]; /* Name used in logs */
    bool receive_system_messages; /* Also deliver non-user (system) entries */
    _Atomic bool active;          /* True while registered */
    /* Required. Called for each new history entry, on the posting thread. */
    void (*on_message)(struct client_connection *connection,
                       const struct chat_history_entry *entry);
    /* Optional. Called once when the connection is removed. */
    void (*on_detach)(struct client_connection *connection);
    void *user_data;                  /* Opaque pointer for the callbacks */
    _Atomic(client_manager_t *) owner; /* Manager holding this connection */
} client_connection_t;

/**
 * @desc Create an empty registry bound to host.
 * @return New manager, or nullptr on allocation failure.
 */
client_manager_t *client_manager_create(struct host *host);

/**
 * @desc Detach every connection (firing on_detach) and free the manager.
 */
void client_manager_destroy(client_manager_t *manager);

/**
 * @desc Add a connection to the first free slot.
 * @return true when registered (or already registered with this manager);
 *         false when on_message is missing, the manager is shutting down,
 *         the connection belongs to another manager, or no slot is free.
 */
bool client_manager_register(client_manager_t *manager,
                             client_connection_t *connection);
/**
 * @desc Remove a connection and fire its on_detach callback.
 */
void client_manager_unregister(client_manager_t *manager,
                               client_connection_t *connection);

/**
 * @desc Deliver a new history entry to every active connection, skipping
 *       system entries for connections that did not ask for them.
 */
void client_manager_notify_history(client_manager_t *manager,
                                   const struct chat_history_entry *entry);

/* Host the manager was created for. */
struct host *client_manager_host(client_manager_t *manager);

#endif
