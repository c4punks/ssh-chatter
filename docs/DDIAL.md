# DDial in SSH-Chatter

SSH-Chatter speaks the Diversi Dial (DDial) line protocol in three ways:

- **Listener** (`-D bind:port`): retro terminals dial in over raw TCP/telnet
  and get a DDial-style chat with the MagViz command set.
- **Upstream client** (`CHATTER_DDIAL_HOST`/`PORT`): Chatter connects out to
  another DDial station and bridges it with the Chatter room.
- **Station hub** (`CHATTER_DDIAL_HUB_LISTEN`): other stations link to this
  one with a station key generated here. See [Station hub](#station-hub).

Channel 1 is one conversation across all three: the Chatter room (SSH and
telnet users), local dial-ins tuned to T1, and the upstream station.

## Upstream client modes

| Variable | Meaning |
| --- | --- |
| `CHATTER_DDIAL_HOST`, `CHATTER_DDIAL_PORT` | Remote station. |
| `CHATTER_DDIAL_KEY` | Password sent at the `Enter Password` prompt (`###password` for member accounts). Empty = guest. Keep it in a root-only `EnvironmentFile`. |
| `CHATTER_DDIAL_HANDLE` | Handle set with `/H` after login. |
| `CHATTER_DDIAL_MODE` | `station` (default) or `user` (alias `hijack`). |
| `CHATTER_DDIAL_RELOGIN_COOLDOWN` | User mode: seconds to wait between hanging up and dialing again (default 120). |
| `CHATTER_DDIAL_LOCK_DIR` | User mode: directory for the account lock file (default: the user data root). |
| `CHATTER_DDIAL_STATION` | Station name used in `}}}` broadcasts (station mode). |

### Station mode

For a real Station Link account. Outbound chat uses the full wire form
`#slot[T1:handle) message`, and Chatter sends `}` / `}}` login and logout
events and a `}}}` user list every 15 minutes, so the remote sees each
Chatter user as their own line.

### User ("hijack") mode

For an ordinary member or guest account on a DDial that won't issue a link
account. Chatter logs in as one user and relays traffic through that user.
Two problems with this approach are handled explicitly:

1. **Echo loops.** The remote repeats everything we type as
   `#N[T1:ourhandle) ...`. If those lines came back into Chatter, every
   message would show up again as the relay user. In user mode:
   - Outbound chat goes out as `speaker: message`. The remote adds our own
     prefix itself.
   - The last eight outbound lines are remembered for 90 s. An incoming line
     that matches one of them, or any line under our own handle, is dropped
     before it reaches the room or the dial-ins.
   - Link-only traffic (login/logout events, `}}}` lists, link-form private
     messages) is never sent.
2. **Double logins disable the account.** Classic ddials disable an account
   that is logged in twice. Over telnet that happens easily after a quick
   reconnect or a service restart. User mode therefore:
   - Holds an exclusive `flock` on `ddial-account-<host>-<port>.lock`, so a
     second ssh-chatter process (a restart overlap or a test run) cannot
     dial the same account. It waits instead.
   - Writes `active <epoch>` / `closed <epoch>` to that file and, across
     restarts, waits `CHATTER_DDIAL_RELOGIN_COOLDOWN` seconds after the
     last hang-up before dialing again. If the previous process died while
     connected, the full cooldown starts from the moment the new process
     notices.
   - Sends `/Q` before hanging up (including on `systemctl stop`), so the
     remote logs the account out instead of waiting for a carrier timeout.
   - Stops reconnecting when the remote reports a duplicate or locked login
     ("already logged in", "account disabled", ...). An operator clears this
     with `/ddial reconnect`.
   - Only treats a line as a kick or hang-up if it is not user-authored chat
     (someone typing "bye" no longer drops the link). A `-->` prompt glued to
     the front of a chat line is stripped first.

Only operators can run `/ddial connect|disconnect|reconnect`.
`/ddial status` shows the mode and any lockout.

## Listener: MagViz command set

Dial-ins log in with a guest handle, or as members with `###password` /
`###:password[:command]`. `/signup <password>` registers the current handle.
Members, mail and offline messages are stored in `ddial_members.tsv` and
`ddial_mail.tsv` under the user data root (`CHATTER_DDIAL_MEMBERS_DIR`
overrides it), with PBKDF2-SHA256 password hashes.

Type `/i`, `/?m` and `/t?` on a dial-in for the full lists. Summary:

- **Everyone:** `/i /h /s[#] /sm /p# @# /m /r# /ls /b /b? /bv# /font /baud /sc /re
  /ai /q /q+ /jk[#] /giphy /forgot /signup /ps`
- **Members:** `/t# (1-999) /t+# /t-# /ts# ;msg /tb# /p#,# /p=#,# /pv /h#RRGGBBName
  /h#= /h? /a /a# /us /c /pre /post /r= /t? /ig# /ig+# /ig-# /x# /xx# /cls /m= /n
  /null# /topic /ask /answer /8ball /anim# /taco /buzz /image /pw= /remember //+
  /@? /bday /bday+ /bday- /bdayRemove /bg /o# /e? /e /e=# /e-# /e-all /d /u /300
  /1200 /2400 /reverse /scramble /lorem /code /define /whois# /stats /bior /voice
  /spaces /sentry`
- **Extras:** `` ` `` alternating case, `~` rainbow, `,` vanishes after 30 s,
  `\i \b \u` italic/bold/underline, `#RRGGBB` inline colour.

Notes:

- Channels 1-4 map to the linked station's channels. 5-999 stay on this
  station. Guests are limited to 1-4.
- Colours are mapped onto the xterm-256 palette so retro terminals render
  them.
- `/baud` and `/300`-style messages are paced on the server side.
- Commands that only make sense in a web client (`/font`, `/n`, `/voice`,
  `/remember`) are stored as preferences for GUI front ends, and the terminal
  says so.
- `/giphy` needs `CHATTER_GIPHY_API_KEY`. `/define` uses dictionaryapi.dev.
  `/image` (AI image generation) is not available.
- CoSysops are set with `CHATTER_DDIAL_COSYSOPS=1,7,...` (member numbers) or
  by another CoSysop with `/sc+#`.

## Message ids and replies

Chat that arrives from DDial (the upstream station, linked stations and
local dial-ins) gets a message id like any Chatter message, shown with a `d`
in front: `[d42] <MaxMouse> hello`. The number shares Chatter's id sequence,
so `d42` and `42` can never both exist; commands accept either spelling
(`/reply d42 hi`, reactions, and so on).

A `/reply` is relayed to DDial in the reply form DDial clients understand:

    text^ >>RE:[N] author: quoted text

`^` is the DDial line break, `N` is the quoted author's line number (left
out when they have none), and the quote is the parent's own text without
any `>>RE:` tail of its own. The body is capped at 255 characters: the
reply text is kept and the quote is clipped. DDial is ASCII-only, so a reply
to a message with non-ASCII text falls back to the older `@author text`
form (and, like any chat, a reply that is itself non-ASCII is not relayed).

### Replies arriving from DDial

A DDial line in that reply form joins Chatter's reply threads. The quoted
line is looked up among the last 600 history entries by author and quote
(the quote may be clipped, with or without a trailing `...`; `[N]` picks
between candidates). It can be a Chatter message, a DDial line or a
Chatter reply. The DDial line then:

- is recorded as a Chatter reply (threaded under a reply when it answers
  one) and shows up in that message's reply tree;
- is shown like Chatter's own replies: `->[r#5 #d12] oxyosbourne: text`;
- can be answered with `/reply r5 ...` (or still `/reply d<id> ...`).

The quote forms `[N] author: quote`, `author: quote`, `[] author: quote`
and `#N[T1:author) quote` are understood. Quotes of lines that are not
messages (DJ announcements, `/a` actions) stay plain lines.

The link between a DDial line and its reply is rebuilt at every start by
running the same matching over loaded history; it is idempotent, which is
also how history from before this feature was brought in. When the reply
table is full (1024), the oldest reply is dropped to make room.

## Station hub

Other stations can link to this one, the same way this station links to
its own upstream hub:

| Variable | Meaning |
| --- | --- |
| `CHATTER_DDIAL_HUB_LISTEN` | `port` or `addr:port` (`[v6addr]:port`) to accept station links on. Unset = off. |
| `CHATTER_DDIAL_STATION` | Name shown in the welcome line and the `}}}` user list. |

Operators manage requests and keys from the Chatter room:

- `/ddial requests` lists pending inbound station requests with their ids,
  names and source addresses.
- `/ddial approve <request-id>` prints a new nine-digit station key and
  removes the request. **The key is shown once.** Give it to that station's
  operator; it is their link password (`CHATTER_DDIAL_KEY` on another
  ssh-chatter).
- `/ddial deny <request-id>` removes a request without issuing a key.
- `/ddial key new <station-name>` still creates a key directly when no
  inbound request is needed.
- `/ddial key list` shows each key's id, name, creation date and last use.
- `/ddial key revoke <id>` deletes a key and drops a station linked with it.
  Ids are never reused.
- `/ddial hub` lists the linked stations.

A station without a key sends `@request:<station-name>` at the password
prompt (for example, `CHATTER_DDIAL_KEY='@request:RemoteOne'`). The hub
records the request and closes that login attempt; the station can use the
key after an operator approves it. Repeating a request from the same address
and name keeps its original id. Pending requests are stored in
`ddial_station_requests.dat` next to the member files and rewritten
atomically whenever they change.

Keys are stored as PBKDF2-SHA256 hashes in `ddial_station_keys.tsv` next to
the member files (mode 0600).

The join sequence is the upstream login run in reverse:

1. The station connects and gets `Enter Password or [RETURN]: `.
2. It sends its key. A wrong key gets `Invalid password` after a short delay
   and the connection is closed; five bad keys from one address within ten
   minutes block that address for the rest of the window. One key holds one
   link at a time.
3. A good key gets `Welcome to <station> station link`, the status line
   ` #<line>(T1:?)` that names the station's link line (60 and up), the
   `-->` prompt, and our `}}}` user list (repeated every 15 minutes).
4. The station sets its name with `/H<name>` and speaks the link wire forms.

What flows where:

- Chat from a station's users is shown and stored with the station's link
  line in front (`60#4[T1:Bob) hi`), the same way chat relayed by our own
  upstream hub is. It reaches the room, local dial-ins and the other linked
  stations, and AI members answer it.
- `/P<line>` private messages and `/E~` link e-mail from a station are
  delivered to this station's users.
- Linked stations get everything this station sends its own upstream:
  public chat from Chatter members, dial-ins and AI members, login and
  logout events, the `}}}` list, and chat relayed down from our upstream.
- Traffic from linked stations is **not** passed up to our own upstream hub.
- Login/logout events and user lists sent by a linked station number lines
  on that station, so they are not replayed here.
