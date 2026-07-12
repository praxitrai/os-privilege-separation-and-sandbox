/*
 * sandbox.c - user-space malware analysis sandbox controller
 * -------------------------------------------------------------------------
 * Runs an untrusted binary as a child process (fork+execve) and supervises
 * it EXTERNALLY: the child never participates in its own monitoring or
 * termination (it doesn't even know the sandbox exists). Three concurrent
 * activities are handled by pthreads:
 *
 *   1. waiter thread   - blocks in waitpid(), detects normal/abnormal exit
 *   2. timer thread     - enforces a hard wall-clock deadline
 *   3. resource thread  - periodically samples CPU time & RSS from
 *                         /proc/<pid>/stat and /proc/<pid>/status and
 *                         enforces CPU-time / memory ceilings
 *
 * All three threads share a small struct protected by a mutex (attempt 1)
 * and, for the single "should we kill it yet" decision, an atomic flag
 * (attempt 2) -- both are demonstrated because the report specifically
 * discusses why plain `volatile` is not a substitute for either.
 *
 * Build: gcc -O2 -Wall -Wextra -pthread -o sandbox sandbox.c
 * Run  : ./sandbox <time_limit_sec> <mem_limit_kb> <cpu_limit_sec> -- <binary> [args...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

typedef struct {
    pid_t    child_pid;
    long     time_limit_sec;
    long     mem_limit_kb;
    long     cpu_limit_sec;

    pthread_mutex_t lock;      /* guards the human-readable fields below */
    int      child_exited;     /* set by waiter thread                    */
    int      exit_status;
    long     last_rss_kb;
    long     last_cpu_sec;

    atomic_bool kill_requested;  /* the ONE cross-thread decision flag:
                                     any monitor thread may set this, the
                                     terminator reacts to it. atomic_bool
                                     (C11 <stdatomic.h>) gives a defined,
                                     race-free read/write under the C
                                     memory model -- plain `volatile` does
                                     not (see report Q9). */
    atomic_bool stop_monitoring;  /* tells monitor threads to wind down    */

    char     violation_reason[128];
    FILE     *logfp;
} sandbox_state_t;

static void log_line(sandbox_state_t *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(s->logfp, "[%s] ", ts);
    vfprintf(s->logfp, fmt, ap);
    fprintf(s->logfp, "\n");
    fflush(s->logfp);
    va_end(ap);
}
/* ---- resource sampling, entirely from OUTSIDE the child ---- */
static int read_proc_stat_cpu_ticks(pid_t pid, unsigned long long *utime,
                                     unsigned long long *stime) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* Field 14 = utime, 15 = stime (man 5 proc). The comm field (2) can
     * contain spaces/parentheses, so skip past the LAST ')' first. */
    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    char *rparen = strrchr(buf, ')');
    if (!rparen) return -1;
    unsigned long long u = 0, st = 0;
    /* fields after ")  " : state(3) ppid(4) pgrp(5) session(6) tty_nr(7)
     * tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12) cmajflt(13)
     * utime(14) stime(15) ... */
    int field = 2;
    char *p = rparen + 1;
    while (*p == ' ') p++;
    char tokbuf[1024];
    strncpy(tokbuf, p, sizeof(tokbuf) - 1);
    tokbuf[sizeof(tokbuf)-1] = '\0';
    char *save = NULL;
    char *tok = strtok_r(tokbuf, " ", &save);
    while (tok) {
        field++;
        if (field == 14) u = strtoull(tok, NULL, 10);
        if (field == 15) { st = strtoull(tok, NULL, 10); break; }
        tok = strtok_r(NULL, " ", &save);
    }
    *utime = u; *stime = st;
    return 0;
}

static long read_proc_status_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "VmRSS:", 6)) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}
