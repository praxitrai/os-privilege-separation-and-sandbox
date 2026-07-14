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
static int process_alive(pid_t pid) {
    /* kill(pid,0) with no signal delivered: pure existence probe, does not
     * require the child's cooperation and cannot be blocked by it. */
    return kill(pid, 0) == 0;
}

/* Kill the child hard, escalating SIGTERM -> SIGKILL if it ignores the
 * first. The untrusted binary has no say in this whatsoever. */
static void terminate_child(sandbox_state_t *s, const char *reason) {
    pthread_mutex_lock(&s->lock);
    strncpy(s->violation_reason, reason, sizeof(s->violation_reason) - 1);
    pthread_mutex_unlock(&s->lock);

    log_line(s, "ENFORCEMENT: %s -- sending SIGTERM to pid %d",
              reason, s->child_pid);
    kill(s->child_pid, SIGTERM);

    for (int i = 0; i < 20; i++) { /* ~2s grace period, checked from outside */
        if (!process_alive(s->child_pid)) return;
        usleep(100 * 1000);
    }
    if (process_alive(s->child_pid)) {
        log_line(s, "ENFORCEMENT: pid %d ignored SIGTERM, sending SIGKILL",
                  s->child_pid);
        kill(s->child_pid, SIGKILL);
    }
}

/* ---- thread 1: wall-clock timer ---- */
static void *timer_thread(void *arg) {
    sandbox_state_t *s = (sandbox_state_t *)arg;
    struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);

    while (!atomic_load(&s->stop_monitoring)) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) +
                          (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= (double)s->time_limit_sec) {
            atomic_store(&s->kill_requested, true);
            terminate_child(s, "wall-clock time limit exceeded");
            return NULL;
        }
        usleep(100 * 1000); /* poll 10x/sec: independent of child cooperation */
    }
    return NULL;
}

/* ---- thread 2: resource sampler (CPU time + RSS) ---- */
static void *resource_thread(void *arg) {
    sandbox_state_t *s = (sandbox_state_t *)arg;
    long clk_tck = sysconf(_SC_CLK_TCK);

    while (!atomic_load(&s->stop_monitoring)) {
        unsigned long long ut = 0, st = 0;
        if (read_proc_stat_cpu_ticks(s->child_pid, &ut, &st) == 0) {
            long cpu_sec = (long)((ut + st) / (clk_tck > 0 ? clk_tck : 100));
            long rss_kb = read_proc_status_rss_kb(s->child_pid);

            pthread_mutex_lock(&s->lock);
            s->last_cpu_sec = cpu_sec;
            if (rss_kb >= 0) s->last_rss_kb = rss_kb;
            pthread_mutex_unlock(&s->lock);

            if (cpu_sec >= s->cpu_limit_sec) {
                atomic_store(&s->kill_requested, true);
                terminate_child(s, "CPU time limit exceeded");
                return NULL;
            }
            if (rss_kb >= 0 && rss_kb >= s->mem_limit_kb) {
                atomic_store(&s->kill_requested, true);
                terminate_child(s, "memory (RSS) limit exceeded");
                return NULL;
            }
            log_line(s, "sample: cpu=%lds rss=%ldKB (limits cpu=%lds rss=%ldKB)",
                      cpu_sec, rss_kb, s->cpu_limit_sec, s->mem_limit_kb);
        } else {
            /* /proc/<pid>/stat vanished: child has already exited. */
            return NULL;
        }
        usleep(250 * 1000); /* sample 4x/sec */
    }
    return NULL;
}
static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s <time_limit_sec> <mem_limit_kb> <cpu_limit_sec> -- <binary> [args...]\n",
        argv0);
}

int main(int argc, char **argv) {
    if (argc < 6) { usage(argv[0]); return 1; }
    long time_limit = strtol(argv[1], NULL, 10);
    long mem_limit  = strtol(argv[2], NULL, 10);
    long cpu_limit  = strtol(argv[3], NULL, 10);

    int sep = 4;
    if (strcmp(argv[sep], "--") != 0) { usage(argv[0]); return 1; }
    int bin_idx = sep + 1;
    if (bin_idx >= argc) { usage(argv[0]); return 1; }

    sandbox_state_t state;
    memset(&state, 0, sizeof(state));
    state.time_limit_sec = time_limit;
    state.mem_limit_kb   = mem_limit;
    state.cpu_limit_sec  = cpu_limit;
    pthread_mutex_init(&state.lock, NULL);
    atomic_store(&state.kill_requested, false);
    atomic_store(&state.stop_monitoring, false);

    state.logfp = fopen("sandbox.log", "a");
    if (!state.logfp) state.logfp = stderr;

    log_line(&state, "==== new run: %s, limits time=%lds mem=%ldKB cpu=%lds ====",
              argv[bin_idx], time_limit, mem_limit, cpu_limit);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* --- Child: exec the untrusted binary. It has no idea a sandbox
         * exists; it is not handed any file descriptor, signal handler, or
         * cooperative hook to interact with the controller. Isolation here
         * additionally rests on execve() replacing the address space
         * entirely, so nothing from the parent (secrets, open privileged
         * fds, etc.) is inherited into the untrusted code beyond what a
         * normal fork+exec would carry -- which we minimize further with
         * an rlimit safety net below as defense in depth. */
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)cpu_limit + 2; /* small grace over the soft
                                                 external enforcement so the
                                                 kernel is a backstop, not
                                                 the primary mechanism */
        rl.rlim_max = (rlim_t)cpu_limit + 2;
        setrlimit(RLIMIT_CPU, &rl);

        execve(argv[bin_idx], &argv[bin_idx], NULL);
        /* only reached if execve failed */
        perror("execve");
        _exit(127);
    }

    /* --- Parent: supervise, never participate in the child's own logic. */
    state.child_pid = pid;
    log_line(&state, "spawned child pid=%d", pid);

    pthread_t t_wait, t_timer, t_res;
    pthread_create(&t_wait, NULL, waiter_thread, &state);
    pthread_create(&t_timer, NULL, timer_thread, &state);
    pthread_create(&t_res, NULL, resource_thread, &state);

    pthread_join(t_wait, NULL);
    atomic_store(&state.stop_monitoring, true);
    pthread_join(t_timer, NULL);
    pthread_join(t_res, NULL);

    pthread_mutex_lock(&state.lock);
    log_line(&state, "==== run complete: exited=%d cpu=%lds rss=%ldKB "
                      "kill_requested=%d reason='%s' ====",
              state.child_exited, state.last_cpu_sec, state.last_rss_kb,
              atomic_load(&state.kill_requested),
              state.violation_reason[0] ? state.violation_reason : "none");
    pthread_mutex_unlock(&state.lock);

    pthread_mutex_destroy(&state.lock);
    if (state.logfp != stderr) fclose(state.logfp);
    return 0;
}
