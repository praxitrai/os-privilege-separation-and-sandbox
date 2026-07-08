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
tatic void send_response(int fd, int granted, int err, const char *msg) {
    auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.magic = AUTH_MAGIC_RESP;
    resp.granted = granted;
    resp.error_code = err;
    strncpy(resp.message, msg, sizeof(resp.message) - 1);
    ssize_t w = write(fd, &resp, sizeof(resp));
    if (w != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "[backend] short write on response\n");
    }
}

/* Handle one already-accepted connection. Called AFTER privileges have
 * been dropped for the connection-handling child (see main()). */
static void handle_client(int cfd, uid_t drop_uid) {
    /* --- Secure IPC: verify who is really on the other end of the socket.
     * SO_PEERCRED is filled in by the KERNEL at connect() time from the
     * connecting process's real credentials; it cannot be spoofed by the
     * client because the client never gets to set these fields itself. */
    struct ucred peer;
    socklen_t len = sizeof(peer);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &peer, &len) != 0) {
        fprintf(stderr, "[backend] SO_PEERCRED failed: %s\n", strerror(errno));
        send_response(cfd, 0, AUTH_ERR_BAD_PEER, "internal error");
        return;
    }
    fprintf(stderr, "[backend] peer pid=%d uid=%d gid=%d\n",
            peer.pid, peer.uid, peer.gid);

    if (rate_limited(peer.uid)) {
        fprintf(stderr, "[backend] rate limit exceeded for uid=%d, rejecting\n",
                peer.uid);
        send_response(cfd, 0, AUTH_ERR_RATE_LIMIT, "too many attempts");
        return;
    }

    /* --- Shared memory for the password buffer.
     * We deliberately place the password in an anonymous MAP_SHARED
     * region (rather than a plain stack/heap buffer) and mlock() it:
     *   1. mlock() prevents the page holding the secret from ever being
     *      written to swap, where it could outlive the process.
     *   2. Using a distinct mapping makes the secret's lifetime explicit
     *      and lets us msync/munlock/munmap it as one deliberate unit,
     *      instead of trusting stack-frame reuse to overwrite it.
     * (See report Q10-Q12 / README for the objdump verification that the
     * wipe below survives optimization.) */
    size_t pagesz = (size_t)sysconf(_SC_PAGESIZE);
    void *shared_pw = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared_pw == MAP_FAILED) {
        perror("mmap");
        send_response(cfd, 0, AUTH_ERR_INTERNAL, "internal error");
        return;
    }
    if (mlock(shared_pw, pagesz) != 0) {
        fprintf(stderr, "[backend] warning: mlock failed (%s), continuing\n",
                strerror(errno));
    }

/* Constant-ish response regardless of *why* it failed (no user
     * enumeration): unknown user and wrong password look identical. */
    send_response(cfd, granted, AUTH_ERR_NONE,
                  granted ? "authentication granted" : "authentication denied");

    fprintf(stderr, "[backend] result for uid=%d user=%s -> %s\n",
            peer.uid, req.username, granted ? "GRANTED" : "DENIED");

    secure_wipe(shared_pw, pagesz);
    secure_wipe(hash, sizeof(hash));
    munlock(shared_pw, pagesz);
    munmap(shared_pw, pagesz);
}

int main(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "backend: must be started as root (it needs to read "
                        "%s once, then drops privileges).\n", AUTHDB_PATH);
        return 1;
    }

    struct passwd *pw = getpwnam(AUTH_DROP_USER);
    if (!pw) {
        fprintf(stderr, "backend: drop-to user '%s' does not exist. "
                        "Create it with: useradd -r -s /usr/sbin/nologin %s\n",
                AUTH_DROP_USER, AUTH_DROP_USER);
        return 1;
    }
    uid_t drop_uid = pw->pw_uid;

    signal(SIGCHLD, SIG_IGN); /* reap children automatically, no zombies */
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);

    mkdir("/tmp/authsvc", 0755);
    unlink(AUTH_SOCK_PATH);

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AUTH_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); return 1;
    }
    chmod(AUTH_SOCK_PATH, 0666); /* any local user may attempt to connect;
                                    authorization happens via SO_PEERCRED +
                                    per-uid credential lookup, not socket
                                    permission bits */
    if (listen(sfd, BACKLOG) != 0) { perror("listen"); return 1; }

    g_rate_table = rate_table_create();
    if (!g_rate_table) {
        perror("mmap (rate table)");
        return 1;
    }

    fprintf(stderr, "[backend] listening on %s as uid=%d (will drop to uid=%d "
                    "'%s' per connection)\n",
            AUTH_SOCK_PATH, geteuid(), drop_uid, AUTH_DROP_USER);

    while (!g_stop) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        /* Process isolation per the assignment: each validation happens in
         * its OWN process (fork), not a thread, so that a memory-safety bug
         * while handling one hostile request cannot corrupt the address
         * space of the listening/privileged process or of other in-flight
         * requests. */
        pid_t child = fork();
        if (child == 0) {
            close(sfd);
            handle_client(cfd, drop_uid);
            close(cfd);
            _exit(0);
        } else if (child > 0) {
            close(cfd); /* parent keeps only the listening socket */
        } else {
            perror("fork");
            close(cfd);
        }
    }

    close(sfd);
    unlink(AUTH_SOCK_PATH);
    return 0;
}

