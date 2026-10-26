# FidoNet in SSH-Chatter

SSH-Chatter can run as a FidoNet node (or point) behind one uplink. Echomail
for the areas you choose is stored on this server and read and written with
`/fido`. Mail is exchanged with the uplink over BinkP during the Zone Mail
Hour.

FidoNet data stays in its own directory. It never goes into
`bbs_state.dat`, so a bad import can never damage the BBS.

## Setup

Get an address and a session password from your uplink, then set:

| Variable | Meaning |
| --- | --- |
| `CHATTER_FIDO_ADDRESS` | Our address, `zone:net/node[.point]`. Required; the node is off without it. |
| `CHATTER_FIDO_UPLINK` | The uplink's address. Required. |
| `CHATTER_FIDO_UPLINK_HOST` | `host[:port]` of the uplink's BinkP server (default port 24554). Without it we only take calls from the uplink. |
| `CHATTER_FIDO_PASSWORD` | Session password. The first 8 characters are also the packet password. Keep it in a root-only `EnvironmentFile`. |
| `CHATTER_FIDO_AREAS` | Comma-separated echo tags to carry, e.g. `FIDOTEST,KOREAN`. Mail for other areas is dropped. |
| `CHATTER_FIDO_ZMH` | Override the poll window, `HH:MM-HH:MM` in UTC. |
| `CHATTER_FIDO_POLL_MINUTES` | Also poll every N minutes outside the window (default 0: mail hour only). |
| `CHATTER_FIDO_BINKP_PORT` | Accept calls from the uplink on this port (default off). |
| `CHATTER_FIDO_DIR` | Node directory (default: `fidonet/` next to `bbs_state.dat`). |
| `CHATTER_FIDO_SYSTEM`, `CHATTER_FIDO_SYSOP`, `CHATTER_FIDO_LOCATION` | BinkP banner (`SYS`/`ZYZ`/`LOC`). |
| `CHATTER_FIDO_ORIGIN` | Text of the ` * Origin:` line on our messages. |

Install `unzip` if your uplink sends ArcMail bundles (`*.su0`, `*.mo1`, ...).
Plain `.pkt` files need nothing extra.

## When mail moves

By default the node polls once inside its zone's **Zone Mail Hour**, the
hour every FidoNet node must accept mail (UTC):

| Zone | Region | Mail hour |
| --- | --- | --- |
| 1 | North America | 09:00-10:00 |
| 2 | Europe | 02:30-03:30 |
| 3 | Australasia | 18:00-19:00 |
| 4 | Latin America | 08:00-09:00 |
| 5 | Africa | 01:00-02:00 |
| 6 | Asia | 20:00-21:00 |

Other zones use 09:00-10:00. The zone comes from `CHATTER_FIDO_ADDRESS`.
After a failed session the node retries every 10 minutes until the window
closes. Messages written here are queued in `outbound/` and go out with
the next session. Operators can poll now with `/fido poll`. If
`CHATTER_FIDO_BINKP_PORT` is set, the uplink can also call in at any time.

## Commands

| Command | |
| --- | --- |
| `/fido` | Node status, next mail hour, carried areas and message counts. |
| `/fido list <area> [page]` | Messages in thread order (replies under the message they answer). Page 1 is the newest. `*` marks messages written here. |
| `/fido read <area> <n>` | One message. |
| `/fido post <area> <subject>\|<text>` | New message to All. Type `\n` for a line break. |
| `/fido reply <area> <n> <text>` | Reply: `Re:` subject, addressed to the author, linked with `REPLY`. |
| `/fido poll` | Operators: poll the uplink now. |
| `/fido hide\|unhide <area> <n>` | Operators: hide a message on this system (logged in `modlog`). |

Posting follows the BBS mute list and the 30-second post throttle, and goes
through the same content filter as BBS posts. `NETMAIL` (netmail addressed
to us) is readable by operators only. Writing netmail is not supported yet.

## Files

```
fidonet/
  inbound/      received over BinkP; tossed after every session
  outbound/     our packets, one per message, deleted once the uplink has them
  bad/          packets that failed (wrong destination or password, bad bundle)
  areas/<tag>.msgs  append-only message base per area
  dupes.dat     recent "AREA msgid" keys; the newest 10000 are kept
  hidden.dat    operator-hidden messages
  serial.dat    last MSGID serial
```

A message's number is its position in the area file, so numbers never
change. A record torn by a crash is skipped when the file is read.

## Protocol notes

- BinkP (FTS-1026) with binkp/1.0 batch rules, in both roles. The answerer
  offers CRAM-MD5 (FTS-1027) whenever a password is set. Only the
  configured uplink is accepted. Our files go out only on a
  password-protected session.
- Type 2+ packets (FSC-0039/0048). Type 2 headers are also read.
- Outgoing echomail carries `MSGID`, `REPLY`, `PID`, `CHRS: UTF-8 4` and
  `TZUTC`, a tear line and an Origin line. A node adds `SEEN-BY` and `PATH`;
  a point leaves them to its boss.
- Incoming text is converted to UTF-8 from its `CHRS`/`CODEPAGE` kludge
  (CP437 when there is none). Terminal escape sequences and control bytes
  are removed before anything is stored.
- Dupes are found by `MSGID`, or by a hash of the header and body when
  there is no MSGID. Our own messages are recorded when written, so the copy
  the uplink echoes back is dropped.

This was tested against binkd 1.1a in both directions (we call the hub, and
the hub calls us), with CRAM-MD5, plain packets and ZIP bundles.
Synchronet's sbbsecho and binkit were used as behavioural references. The
BinkP framing started from the FidoNet client removed in commit `f25bfcd`.
