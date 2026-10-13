/**
 * @file file_transfer.h
 * @desc Shared file store ("/filestore") and the transfer protocols that
 *       reach it: SCP and SFTP over SSH, and ZMODEM over TELNET. All paths
 *       given by users are virtual and are resolved inside the storage root.
 */
#ifndef SSH_CHATTER_FILE_TRANSFER_H
#define SSH_CHATTER_FILE_TRANSFER_H

#include "ssh_chatter/host.h"

/**
 * @desc Prepare the storage root. The path comes from CHATTER_FILESTORE_PATH,
 *       then the legacy CHATTER_FILE_STORAGE_ROOT, then the compiled default,
 *       and must be absolute.
 * @param host Host whose file_storage_root/file_storage_ready are set.
 * @return true when storage is usable.
 */
bool host_file_storage_init(host_t *host);

/**
 * @desc Render a recursive listing of the storage root for display.
 * @param host   Host owning the storage.
 * @param buffer Output buffer for the listing (or an explanatory message).
 * @param length Size of buffer.
 * @return false when storage is unavailable, true otherwise.
 */
bool host_file_storage_list(host_t *host, char *buffer, size_t length);

/**
 * @desc Map a user-supplied virtual path onto a real path inside the
 *       storage root, rejecting traversal outside it.
 * @param host         Host owning the storage.
 * @param virtual_path Path as typed by the user.
 * @param resolved     Receives the absolute on-disk path.
 * @param resolved_len Size of resolved.
 * @param display      Optional buffer for a user-friendly path.
 * @param display_len  Size of display.
 * @return true when the path is valid and inside the store.
 */
bool file_transfer_resolve_path(host_t *host, const char *virtual_path,
                                char *resolved, size_t resolved_len,
                                char *display, size_t display_len);

/**
 * @desc Receive a ZMODEM upload from a TELNET session into the store.
 * @param ctx             TELNET session performing the upload.
 * @param resolved_target Optional already-resolved destination path.
 * @return true on a successful transfer.
 */
bool file_transfer_telnet_receive(session_ctx_t *ctx,
                                  const char *resolved_target);

/**
 * @desc Send a stored file to a TELNET session via ZMODEM.
 * @param ctx          TELNET session receiving the file.
 * @param virtual_path File to send, relative to the store.
 * @return true on a successful transfer.
 */
bool file_transfer_telnet_send(session_ctx_t *ctx, const char *virtual_path);

/**
 * @desc Serve an `scp -t` (upload) or `scp -f` (download) exec request.
 * @param ctx     SSH session whose channel carries the SCP protocol.
 * @param command The exec command line sent by the client.
 * @return 0 on success, -1 on failure.
 */
int file_transfer_handle_scp_exec(session_ctx_t *ctx, const char *command);

/**
 * @desc Run an SFTP subsystem server on the session's channel until the
 *       client disconnects.
 * @param ctx SSH session that requested the sftp subsystem.
 * @return 0 on success, -1 on failure.
 */
int file_transfer_handle_sftp(session_ctx_t *ctx);

#endif /* SSH_CHATTER_FILE_TRANSFER_H */
