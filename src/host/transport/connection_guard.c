
/*
 * Connection flood guard, MOTD hot-reload and captcha prompt generation.
 *
 * The guard keeps one entry per client IP. Each IP may make up to
 * SSH_CHATTER_CONNECTION_GUARD_THRESHOLD connection attempts per
 * SSH_CHATTER_CONNECTION_GUARD_WINDOW_NS; crossing it blocks the IP for a
 * penalty that grows by BLOCK_STEP with each repeated block (capped at
 * BLOCK_MAX). After BAN_THRESHOLD blocks the caller is told to escalate to
 * a real ban. Entries idle longer than the retention period are pruned.
 * All guard state lives on host_t and is protected by host->lock.
 */

/* Verdict for one connection attempt. */
typedef struct connection_guard_result {
    bool blocked;                  /* Reject this connection */
    bool escalate_ban;             /* Repeat offender; caller should ban */
    struct timespec blocked_until; /* CLOCK_MONOTONIC end of the block */
    size_t attempt_count;          /* Attempts counted in the current window */
    unsigned int block_count;      /* Blocks issued to this IP so far */
} connection_guard_result_t;

/*
 * Drop entries not seen within the retention period and compact the array
 * in place, zeroing the freed tail. Caller holds host->lock.
 */
static void host_connection_guard_prune_locked(host_t *host,
                                               const struct timespec *now)
{
    if (host == nullptr || now == nullptr ||
        host->connection_guard_count == 0U) {
        return;
    }

    size_t write_idx = 0U;
    const size_t original_count = host->connection_guard_count;
    for (size_t idx = 0U; idx < original_count; ++idx) {
        connection_guard_entry_t *entry = &host->connection_guard[idx];
        if (entry->ip[0] == '\0') {
            continue;
        }

        if (entry->last_seen.tv_sec != 0 || entry->last_seen.tv_nsec != 0) {
            struct timespec age = timespec_diff(now, &entry->last_seen);
            long long age_ns = timespec_to_ns(&age);
            if (age_ns > SSH_CHATTER_CONNECTION_GUARD_RETENTION_NS) {
                continue;
            }
        }

        if (write_idx != idx) {
            host->connection_guard[write_idx] = *entry;
        }
        ++write_idx;
    }

    if (write_idx < original_count) {
        size_t cleared = original_count - write_idx;
        memset(&host->connection_guard[write_idx], 0,
               cleared * sizeof(host->connection_guard[write_idx]));
    }
    host->connection_guard_count = write_idx;
}

/* Linear lookup of an IP's entry. Caller holds host->lock. */
static connection_guard_entry_t *
host_find_connection_guard_locked(host_t *host, const char *ip)
{
    if (host == nullptr || ip == nullptr) {
        return nullptr;
    }

    for (size_t idx = 0U; idx < host->connection_guard_count; ++idx) {
        connection_guard_entry_t *entry = &host->connection_guard[idx];
        if (strncmp(entry->ip, ip, SSH_CHATTER_IP_LEN) == 0) {
            return entry;
        }
    }

    return nullptr;
}

/*
 * Find or append the entry for ip, doubling the array (starting at 16)
 * when full. Allocations are charged to the host's memory scope.
 * Caller holds host->lock.
 */
static connection_guard_entry_t *
host_ensure_connection_guard_locked(host_t *host, const char *ip)
{
    if (host == nullptr || ip == nullptr || ip[0] == '\0') {
        return nullptr;
    }

    sshc_memory_context_t *memory_scope = host_memory_scope_push(host);

    connection_guard_entry_t *entry =
        host_find_connection_guard_locked(host, ip);
    if (entry != nullptr) {
        host_memory_scope_pop(memory_scope);
        return entry;
    }

    if (host->connection_guard_count >= host->connection_guard_capacity) {
        size_t new_capacity = host->connection_guard_capacity > 0U
                                  ? host->connection_guard_capacity * 2U
                                  : 16U;
        connection_guard_entry_t *resized =
            sshc_gc_realloc(host->connection_guard,
                       new_capacity * sizeof(connection_guard_entry_t));
        if (resized == nullptr) {
            host_memory_scope_pop(memory_scope);
            return nullptr;
        }
        host->connection_guard = resized;
        memset(&host->connection_guard[host->connection_guard_capacity], 0,
               (new_capacity - host->connection_guard_capacity) *
                   sizeof(connection_guard_entry_t));
        host->connection_guard_capacity = new_capacity;
    }

    entry = &host->connection_guard[host->connection_guard_count++];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->ip, sizeof(entry->ip), "%.*s", SSH_CHATTER_IP_LEN - 1, ip);
    host_memory_scope_pop(memory_scope);
    return entry;
}

/*
 * Record a connection attempt from ip and decide whether to allow it.
 * Uses CLOCK_MONOTONIC so wall-clock changes cannot lift a block early.
 */
static connection_guard_result_t host_connection_guard_register(host_t *host,
                                                                const char *ip)
{
    connection_guard_result_t result = {0};
    if (host == nullptr || ip == nullptr || ip[0] == '\0') {
        return result;
    }

    struct timespec now = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &now);

    ttak_mutex_lock(&host->lock);
    host_connection_guard_prune_locked(host, &now);
    connection_guard_entry_t *entry =
        host_ensure_connection_guard_locked(host, ip);
    if (entry == nullptr) {
        ttak_mutex_unlock(&host->lock);
        return result;
    }

    entry->last_seen = now;

    /* Still serving a block: refuse without counting the attempt. */
    if (entry->blocked_until.tv_sec != 0 || entry->blocked_until.tv_nsec != 0) {
        if (timespec_compare(&entry->blocked_until, &now) > 0) {
            result.blocked = true;
            result.blocked_until = entry->blocked_until;
            result.block_count = entry->block_count;
            result.attempt_count = entry->attempts;
            ttak_mutex_unlock(&host->lock);
            return result;
        }
        entry->blocked_until.tv_sec = 0;
        entry->blocked_until.tv_nsec = 0L;
    }

    /*
     * Start a new counting window when none is open or the old one expired.
     * A long quiet period also forgives earlier blocks.
     */
    if (entry->window_start.tv_sec == 0 && entry->window_start.tv_nsec == 0) {
        entry->window_start = now;
        entry->attempts = 0U;
    } else {
        struct timespec diff = timespec_diff(&now, &entry->window_start);
        long long window_ns = timespec_to_ns(&diff);
        if (window_ns > SSH_CHATTER_CONNECTION_GUARD_WINDOW_NS) {
            entry->window_start = now;
            entry->attempts = 0U;
            if (window_ns > SSH_CHATTER_CONNECTION_GUARD_RETENTION_NS) {
                entry->block_count = 0U;
            }
        }
    }

    if (entry->attempts < SIZE_MAX) {
        entry->attempts += 1U;
    }
    result.attempt_count = entry->attempts;
    result.block_count = entry->block_count;

    /* Threshold hit: block with a penalty that grows per repeat offense. */
    if (entry->attempts >= SSH_CHATTER_CONNECTION_GUARD_THRESHOLD) {
        size_t attempt_snapshot = entry->attempts;
        if (entry->block_count < UINT_MAX) {
            entry->block_count += 1U;
        }
        long long penalty_ns =
            SSH_CHATTER_CONNECTION_GUARD_BLOCK_BASE_NS +
            (long long)(entry->block_count > 0U ? entry->block_count - 1U
                                                : 0U) *
                SSH_CHATTER_CONNECTION_GUARD_BLOCK_STEP_NS;
        if (penalty_ns > SSH_CHATTER_CONNECTION_GUARD_BLOCK_MAX_NS) {
            penalty_ns = SSH_CHATTER_CONNECTION_GUARD_BLOCK_MAX_NS;
        }
        entry->blocked_until = timespec_add_ns(&now, penalty_ns);
        entry->window_start = now;
        entry->attempts = 0U;

        result.blocked = true;
        result.blocked_until = entry->blocked_until;
        result.block_count = entry->block_count;
        result.attempt_count = attempt_snapshot;
        if (entry->block_count >= SSH_CHATTER_CONNECTION_GUARD_BAN_THRESHOLD) {
            result.escalate_ban = true;
        }
    }

    ttak_mutex_unlock(&host->lock);
    return result;
}

/* Reset the host health guard's error streak after a successful operation. */
static void host_error_guard_register_success(host_t *host)
{
    if (host == nullptr) {
        return;
    }

    host->health_guard.consecutive_errors = 0U;
    host->health_guard.last_error_time.tv_sec = 0;
    host->health_guard.last_error_time.tv_nsec = 0L;
}

static bool host_try_load_motd_from_path(host_t *host, const char *path);

/* Portable nanosecond-precision mtime from a struct stat. */
static struct timespec host_stat_mtime(const struct stat *info)
{
    struct timespec result = {0, 0};
    if (info == nullptr) {
        return result;
    }

#if defined(__APPLE__)
    result.tv_sec = info->st_mtimespec.tv_sec;
    result.tv_nsec = info->st_mtimespec.tv_nsec;
#elif defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || defined(__USE_XOPEN2K8)
    result.tv_sec = info->st_mtim.tv_sec;
    result.tv_nsec = info->st_mtim.tv_nsec;
#else
    result.tv_sec = info->st_mtime;
    result.tv_nsec = 0;
#endif

    if (result.tv_sec < 0) {
        result.tv_sec = 0;
    }
    if (result.tv_nsec < 0) {
        result.tv_nsec = 0;
    }
    return result;
}

/*
 * Reload the MOTD when its file changed on disk (mtime differs from the
 * last load). A leading "~" is expanded with $HOME. If the file vanished
 * the host stops treating the MOTD as file-backed; if it never existed,
 * loading is retried.
 */
static void host_maybe_reload_motd_from_file(host_t *host)
{
    if (host == nullptr) {
        return;
    }

    /* Snapshot the path under the lock; do file I/O without holding it. */
    char stored_path[PATH_MAX];
    stored_path[0] = '\0';
    struct timespec last_loaded = {0, 0};
    bool had_file = false;

    ttak_mutex_lock(&host->lock);
    if (host->motd_path[0] != '\0') {
        snprintf(stored_path, sizeof(stored_path), "%s", host->motd_path);
        last_loaded = host->motd_last_modified;
        had_file = host->motd_has_file;
    }
    ttak_mutex_unlock(&host->lock);

    if (stored_path[0] == '\0') {
        return;
    }

    char resolved_path[PATH_MAX];
    resolved_path[0] = '\0';

    if (stored_path[0] == '~' &&
        (stored_path[1] == '\0' || stored_path[1] == '/')) {
        const char *home = getenv("HOME");
        if (home != nullptr && home[0] != '\0') {
            int expanded = snprintf(resolved_path, sizeof(resolved_path),
                                    "%s%s", home, stored_path + 1);
            if (expanded <= 0 || (size_t)expanded >= sizeof(resolved_path)) {
                resolved_path[0] = '\0';
            }
        }
    }

    const char *path_to_try =
        resolved_path[0] != '\0' ? resolved_path : stored_path;

    struct stat file_info;
    if (stat(path_to_try, &file_info) != 0 || !S_ISREG(file_info.st_mode)) {
        if (!had_file) {
            (void)host_try_load_motd_from_path(host, path_to_try);
        }
        if (had_file) {
            ttak_mutex_lock(&host->lock);
            if (host->motd_has_file && strncmp(host->motd_path, stored_path,
                                               sizeof(host->motd_path)) == 0) {
                host->motd_has_file = false;
                host->motd_last_modified.tv_sec = 0;
                host->motd_last_modified.tv_nsec = 0L;
            }
            ttak_mutex_unlock(&host->lock);
        }
        return;
    }

    struct timespec modified = host_stat_mtime(&file_info);

    if (had_file && modified.tv_sec == last_loaded.tv_sec &&
        modified.tv_nsec == last_loaded.tv_nsec) {
        return;
    }

    (void)host_try_load_motd_from_path(host, path_to_try);
}

/* djb2-style (xor variant) string hash; not cryptographic. */
static unsigned session_simple_hash(const char *text)
{
    unsigned hash = 5381U;
    if (text == nullptr) {
        return hash;
    }

    for (const unsigned char *cursor = (const unsigned char *)text;
         *cursor != '\0'; ++cursor) {
        hash = (hash * 33U) ^ *cursor;
    }
    return hash;
}

/*
 * Build a digit-sum captcha for a connecting session. The PRNG seed mixes
 * the user name, client IP, current time and a per-host nonce so that two
 * clients connecting at the same instant still get different puzzles. This
 * only needs to deter scripts, not resist a determined attacker.
 */
static void session_build_captcha_prompt(session_ctx_t *ctx,
                                         captcha_prompt_t *prompt)
{
    if (prompt == nullptr) {
        return;
    }

    memset(prompt, 0, sizeof(*prompt));

    unsigned basis =
        session_simple_hash(ctx != nullptr ? ctx->user.name : "user");
    basis ^= session_simple_hash(ctx != nullptr ? ctx->client_ip : "ip");

    unsigned entropy = 0U;
    struct timespec now = {0, 0};
    if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
        uint64_t now_sec = (uint64_t)now.tv_sec;
        entropy ^= (unsigned)now_sec;
        entropy ^= (unsigned)(now_sec >> 32);
        entropy ^= (unsigned)now.tv_nsec;
    } else {
        uint64_t fallback = (uint64_t)time(nullptr);
        entropy ^= (unsigned)fallback;
        entropy ^= (unsigned)(fallback >> 32);
    }

    host_t *host = (ctx != nullptr) ? ctx->owner : nullptr;
    if (host != nullptr) {
        ttak_mutex_lock(&host->lock);
        uint64_t nonce = ++host->captcha_nonce;
        ttak_mutex_unlock(&host->lock);
        entropy ^= (unsigned)nonce;
        entropy ^= (unsigned)(nonce >> 32);
    }

    basis ^= entropy;

    const unsigned variant_seed = basis ^ (basis >> 16U) ^ (entropy << 1U);
    unsigned prng_state = variant_seed | 1U; /* Keep the PRNG state non-zero */

    session_fill_digit_sum_prompt(prompt, &prng_state);
}
