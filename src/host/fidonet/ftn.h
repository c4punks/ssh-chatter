/**
 * @file ftn.h
 * @desc FidoNet Technology Network (FTN) types shared by the FidoNet node:
 *       addresses (FTS-5001), Type 2+ packets (FTS-0001, FSC-0039/0048),
 *       packed messages and their kludge lines (FTS-0009 MSGID/REPLY,
 *       FTS-4000 control lines, FTS-5003 CHRS), the per-area message base
 *       and the BinkP session (FTS-1026).
 *
 *       Private to the host aggregate; the pure parts (ftn.c, zmh.c,
 *       msgbase.c, binkp.c) only use libc and libcrypto so unit tests can
 *       include them directly.
 */

#ifndef SSH_CHATTER_FIDONET_FTN_H
#define SSH_CHATTER_FIDONET_FTN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Field limits from FTS-0001 (including the terminating NUL). */
#define FTN_NAME_LEN 36U
#define FTN_SUBJ_LEN 72U
#define FTN_DATETIME_LEN 20U
#define FTN_PKT_PASSWORD_LEN 8U
#define FTN_AREATAG_LEN 61U /* FSC-0074: 60 characters plus NUL */
#define FTN_ADDR_TEXT_LEN 48U
#define FTN_MSGID_LEN 128U
#define FTN_PKT_HEADER_LEN 58U
#define FTN_MSG_HEADER_LEN 14U

/* Packed message attribute bits (FTS-0001). */
#define FTN_ATTR_PRIVATE 0x0001U
#define FTN_ATTR_LOCAL 0x0100U

/* Our product code: 0xFE is the FTSC value for products without an
 * assigned code. */
#define FTN_PRODUCT_CODE 0xFEU
#define FTN_PRODUCT_NAME "ssh-chatter"
#define FTN_PRODUCT_VERSION "1.4"

typedef struct ftn_addr {
    uint16_t zone;
    uint16_t net;
    uint16_t node;
    uint16_t point;
} ftn_addr_t;

/* Packet header fields we care about (Type 2+ with Type 2 fallback). */
typedef struct ftn_pkt_header {
    ftn_addr_t orig;
    ftn_addr_t dest;
    struct tm created; /* UTC */
    char password[FTN_PKT_PASSWORD_LEN + 1U];
    uint16_t product;
} ftn_pkt_header_t;

/* One message as carried in a packet; body is the raw text with CR line
 * ends and kludges still in place. */
typedef struct ftn_packed_msg {
    uint16_t orig_node;
    uint16_t dest_node;
    uint16_t orig_net;
    uint16_t dest_net;
    uint16_t attr;
    char datetime[FTN_DATETIME_LEN];
    char to[FTN_NAME_LEN];
    char from[FTN_NAME_LEN];
    char subject[FTN_SUBJ_LEN];
    char *body; /* malloc'd, NUL-terminated */
    size_t body_len;
} ftn_packed_msg_t;

/* A message after its body has been parsed: kludges pulled out, text
 * converted to UTF-8 with '\n' line ends. */
typedef struct ftn_message {
    char area[FTN_AREATAG_LEN];    /* empty for netmail */
    char from[FTN_NAME_LEN * 4U];  /* UTF-8 can be longer than CP437 */
    char to[FTN_NAME_LEN * 4U];
    char subject[FTN_SUBJ_LEN * 4U];
    char msgid[FTN_MSGID_LEN];
    char reply[FTN_MSGID_LEN];
    char origin_addr[FTN_ADDR_TEXT_LEN];
    char charset[24];
    time_t written;  /* from the packed message date, UTC */
    time_t imported; /* when we stored it */
    uint32_t flags;
    char *body; /* malloc'd UTF-8 text, '\n' line ends, kludges removed */
} ftn_message_t;

/* ftn_message_t.flags */
#define FTN_MSG_FLAG_LOCAL 0x0001U  /* written on this system */
#define FTN_MSG_FLAG_NETMAIL 0x0002U

#endif /* SSH_CHATTER_FIDONET_FTN_H */
