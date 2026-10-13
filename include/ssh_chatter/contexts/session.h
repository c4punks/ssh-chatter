/**
 * @file session.h
 * @desc Pulls in everything a session context depends on: the libssh core
 *       API, the server-side libssh shim, and the host definitions that
 *       declare session_ctx_t itself.
 */
#ifndef CONTEXT_SESSION_H
#define CONTEXT_SESSION_H

#include <libssh/libssh.h>
#include "ssh_chatter/shim_libssh/server.h"

#include "ssh_chatter/host.h"

#endif
