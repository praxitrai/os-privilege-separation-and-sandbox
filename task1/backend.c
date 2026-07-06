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
