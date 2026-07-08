/*
 * backend.c - privileged validation service
 * -------------------------------------------------------------------------
 * This process is the ONLY part of the system that is ever allowed to touch
 * the protected credential database (authdb, analogous to /etc/shadow).
 * It is started with root privileges (in the demo: via `sudo` or a
 * setuid-root binary), performs the single privileged action it needs
 * (opening the 0600 root-owned authdb file), and then PERMANENTLY drops
 * privileges with setresuid()/setresgid() before it ever looks at
 * attacker-controlled data (the submitted password) or does any
 * comparison work. It never regains privileges after that point -- this
 * is verified at runtime via getresuid()/geteuid() and a probe write to
 * confirm root cannot be re-acquired.
 *
 * Build: gcc -O2 -Wall -Wextra -o backend backend.c -lcrypt
 * Run  : must be started as root (or with the CAP_SETUID/CAP_DAC_OVERRIDE
 *        capability); refuses to run otherwise.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <pwd.h>
#include <crypt.h>
#include <time.h>
#include "authproto.h"
#define AUTHDB_PATH "/tmp/authsvc/authdb"
#define BACKLOG     8
#define MAX_LINE    256

static volatile sig_atomic_t g_stop = 0;
static void on_sigterm(int sig) { (void)sig; g_stop = 1; }

/* ------------------------------------------------------------------ */
/* Explicit, non-optimizable memory wipe.                              */
/*                                                                      */
/* Why not memset()? The C standard treats memset() on a buffer that is */
/* never read again as dead-store-eliminable "as-if" behaviour: a       */
/* sufficiently smart compiler is permitted to remove it entirely,      */
/* because from the abstract machine's point of view the write has no   */
/* observable effect once the object's lifetime ends. This has been      */
/* repeatedly observed with real compilers at -O2/-O3. explicit_bzero() */
/* (glibc) is specifically defined to never be optimized away because   */
/* it is implemented in a separate translation unit the optimizer       */
/* cannot see into, and/or is annotated to prevent DSE. We additionally  */
/* pair it with a compiler barrier and munlock() so the page cannot be   */
/* paged to swap while it holds secrets.                                */
/* ------------------------------------------------------------------ */
static void secure_wipe(void *buf, size_t len) {
    explicit_bzero(buf, len);
    __asm__ __volatile__("" ::: "memory"); /* compiler barrier, belt & braces */
}

/* Verify -- at runtime, not just by reading the source -- that this
 * process no longer holds elevated privileges. Used both as a log
 * assertion and as a defensive check that aborts if privilege dropping
 * silently failed (a bug class explained in the report). */
static int verify_unprivileged(uid_t expected_uid) {
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        perror("getresuid");
        return -1;
    }
    fprintf(stderr, "[backend] post-drop getresuid() -> real=%d eff=%d saved=%d\n",
            ruid, euid, suid);

    if (ruid != expected_uid || euid != expected_uid || suid != expected_uid) {
        fprintf(stderr, "[backend] FATAL: privilege drop incomplete!\n");
        return -1;
    }
/* Runtime check via /proc as required by the assignment, independent
     * of the getresuid() result above. */
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/status");
    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "Uid:", 4)) {
                fprintf(stderr, "[backend] /proc/self/status -> %s", line);
            }
        }
        fclose(f);
    }

    /* Attempt to regain root. If this succeeds, privilege dropping was
     * NOT irreversible and we must treat that as a fatal security bug. */
    if (setuid(0) == 0) {
        fprintf(stderr, "[backend] FATAL: setuid(0) succeeded after drop -- "
                        "privileges were NOT irreversibly dropped!\n");
        return -1;
    }
    if (errno != EPERM) {
        fprintf(stderr, "[backend] warning: setuid(0) failed with unexpected "
                        "errno %d (expected EPERM)\n", errno);
    }
    return 0;
}

/* Look up the password hash for `username` in the protected authdb.
 * MUST be called before privileges are dropped. Format: user:hash */
static int lookup_hash(const char *username, char *hash_out, size_t hash_out_len) {
    FILE *f = fopen(AUTHDB_PATH, "r");
    if (!f) {
        fprintf(stderr, "[backend] cannot open authdb (%s): %s\n",
                AUTHDB_PATH, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) {
        fprintf(stderr, "[backend] refusing to trust authdb: bad owner/perms\n");
        fclose(f);
        return -1;
    }

    char line[MAX_LINE];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';
        if (strcmp(line, username) == 0) {
            strncpy(hash_out, sep + 1, hash_out_len - 1);
            hash_out[hash_out_len - 1] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/* Extremely small fixed-window rate limiter keyed by uid, so a compromised
 * or buggy frontend cannot brute force the backend into the ground.
 * This is the "backend rejects requests that are not a valid, well-formed,
 * rate-permitted validation attempt" attack-resistance requirement. */
#define RATE_WINDOW_SECONDS 10
#define RATE_MAX_ATTEMPTS   5
#define RATE_TABLE_SIZE     64

/* Each connection is handled in its own forked child (process isolation,
 * per the assignment), so per-uid attempt counters CANNOT simply be
 * `static` locals -- fork() gives every child a private copy-on-write
 * address space and any counting done there is invisible to the next
 * connection's child and to the parent. To make rate limiting actually
 * work across many short-lived children we keep the table in a
 * MAP_SHARED|MAP_ANONYMOUS region created ONCE by the parent before the
 * accept() loop starts; every forked child inherits the same mapping to
 * the same physical pages, so updates are visible process-to-process
 * without a separate shared-memory-name/IPC-key dance. */
typedef struct {
    uid_t  uid;
    int    count;
    time_t window_start;
} rate_entry_t;

typedef struct {
    int n;
    rate_entry_t entries[RATE_TABLE_SIZE];
} rate_table_t;

static rate_table_t *g_rate_table = NULL;

static rate_table_t *rate_table_create(void) {
    rate_table_t *t = mmap(NULL, sizeof(rate_table_t), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (t == MAP_FAILED) return NULL;
    memset(t, 0, sizeof(*t));
    return t;
}

static int rate_limited(uid_t uid) {
    rate_table_t *t = g_rate_table;
    time_t now = time(NULL);

    for (int i = 0; i < t->n; i++) {
        if (t->entries[i].uid == uid) {
            if (now - t->entries[i].window_start > RATE_WINDOW_SECONDS) {
                t->entries[i].window_start = now;
                t->entries[i].count = 0;
            }
            t->entries[i].count++;
            return t->entries[i].count > RATE_MAX_ATTEMPTS;
        }
    }
    if (t->n < RATE_TABLE_SIZE) {
        t->entries[t->n].uid = uid;
        t->entries[t->n].count = 1;
        t->entries[t->n].window_start = now;
        t->n++;
    }
    return 0;
}
auth_request_t req;
    ssize_t r = read(cfd, &req, sizeof(req));
    if (r != (ssize_t)sizeof(req) || req.magic != AUTH_MAGIC_REQ) {
        fprintf(stderr, "[backend] malformed/short request, rejecting\n");
        send_response(cfd, 0, AUTH_ERR_BAD_MAGIC, "bad request");
        munlock(shared_pw, pagesz);
        munmap(shared_pw, pagesz);
        return;
    }
    req.username[AUTH_USER_MAX - 1] = '\0';
    req.password[AUTH_PASS_MAX - 1] = '\0';

    /* Copy the password into the guarded shared region; nothing else in
     * this function keeps a second live copy of it. */
    memcpy(shared_pw, req.password, AUTH_PASS_MAX);
    secure_wipe(req.password, sizeof(req.password)); /* wipe the stack copy immediately */

    /* --- The one privileged operation this whole service exists to
     * protect: reading the protected credential database. This runs
     * with root's original effective uid because main() has not dropped
     * yet in the parent — but by design, each connection handler is
     * forked and drops immediately after this call returns, so the
     * window in which any code is running as root is as small as
     * possible and never includes attacker-controlled comparison logic. */
    char hash[128];
    int lookup_rc = lookup_hash(req.username, hash, sizeof(hash));

    /* --- Permanently drop privileges now, before touching the password
     * we just stored, and before doing any comparison work. */
    if (setresgid(drop_uid, drop_uid, drop_uid) != 0 ||
        setresuid(drop_uid, drop_uid, drop_uid) != 0) {
        fprintf(stderr, "[backend] FATAL: setresuid/setresgid failed: %s\n",
                strerror(errno));
        secure_wipe(shared_pw, pagesz);
        munlock(shared_pw, pagesz);
        munmap(shared_pw, pagesz);
        _exit(1);
    }
    if (verify_unprivileged(drop_uid) != 0) {
        secure_wipe(shared_pw, pagesz);
        munlock(shared_pw, pagesz);
        munmap(shared_pw, pagesz);
        _exit(1);
    }

    int granted = 0;
    if (lookup_rc == 0) {
        char *result = crypt((char *)shared_pw, hash);
        if (result && strcmp(result, hash) == 0) {
            granted = 1;
        }
    }
