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
