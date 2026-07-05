/*
 * frontend.c - untrusted input collector
 * -------------------------------------------------------------------------
 * Runs entirely as an ordinary, unprivileged user. It never opens the
 * protected credential database, never links against libcrypt for
 * comparison, and holds no elevated capabilities at any point in its
 * life. Its only job is to collect a username/password from the person
 * at the keyboard and hand the request to backend.c over a UNIX domain
 * socket, then report back whatever the backend decided.
 *
 * Build: gcc -O2 -Wall -Wextra -o frontend frontend.c
 * Run  : as a normal user, after backend is running.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include "authproto.h"

static void secure_wipe(void *buf, size_t len) {
    explicit_bzero(buf, len);
    __asm__ __volatile__("" ::: "memory");
}

/* Read a password from the terminal with echo disabled, so it never
 * appears on screen or in shell history/argv (which `ps` on other users'
 * sessions could otherwise observe). */
static int read_password(char *buf, size_t buflen) {
    struct termios oldt, newt;
    int have_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);

    if (have_tty) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);
    } else {
        /* stdin is not a terminal (e.g. piped input during automated
         * testing/grading). We cannot suppress echo of something that
         * was never echoed by a tty in the first place, so just read it;
         * interactive use still gets the no-echo behaviour above. */
        fprintf(stderr, "[frontend] warning: stdin is not a tty, password "
                        "will not be masked\n");
    }

    printf("Password: ");
    fflush(stdout);
    if (!fgets(buf, (int)buflen, stdin)) {
        if (have_tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        return -1;
    }
    printf("\n");
    if (have_tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);

    size_t l = strlen(buf);
    if (l && buf[l - 1] == '\n') buf[l - 1] = '\0';
    return 0;
}
int main(int argc, char **argv) {
    if (geteuid() == 0) {
        fprintf(stderr, "frontend: refusing to run as root -- this process "
                        "is deliberately unprivileged.\n");
        return 1;
    }

    /* --- Shared-memory-backed buffer for the password on this side too,
     * for the same reason as the backend: an explicit, lockable region we
     * can wipe as a unit rather than trusting stack reuse. */
    size_t pagesz = (size_t)sysconf(_SC_PAGESIZE);
    void *pwbuf = mmap(NULL, pagesz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (pwbuf == MAP_FAILED) { perror("mmap"); return 1; }
    mlock(pwbuf, pagesz);

    auth_request_t req;
    memset(&req, 0, sizeof(req));
    req.magic = AUTH_MAGIC_REQ;

    if (argc > 1) {
        strncpy(req.username, argv[1], AUTH_USER_MAX - 1);
    } else {
        printf("Username: ");
        fflush(stdout);
        if (!fgets(req.username, AUTH_USER_MAX, stdin)) return 1;
        size_t l = strlen(req.username);
        if (l && req.username[l - 1] == '\n') req.username[l - 1] = '\0';
    }

    if (read_password((char *)pwbuf, pagesz) != 0) {
        fprintf(stderr, "frontend: failed to read password\n");
        munlock(pwbuf, pagesz);
        munmap(pwbuf, pagesz);
        return 1;
    }
    strncpy(req.password, (char *)pwbuf, AUTH_PASS_MAX - 1);
    secure_wipe(pwbuf, pagesz); /* done with the shared copy immediately */
    munlock(pwbuf, pagesz);
    munmap(pwbuf, pagesz);

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); secure_wipe(&req, sizeof(req)); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, AUTH_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect (is backend running?)");
        secure_wipe(&req, sizeof(req));
        close(sfd);
        return 1;
    }
/* Note: we do NOT send our uid/gid in the request. The backend reads
     * it straight from the kernel via SO_PEERCRED on its side, so a
     * malicious frontend cannot lie about who it is. */
    ssize_t w = write(sfd, &req, sizeof(req));
    secure_wipe(&req, sizeof(req)); /* wipe our copy the instant it's sent */
    if (w != (ssize_t)sizeof(req)) {
        fprintf(stderr, "frontend: short write to backend\n");
        close(sfd);
        return 1;
    }

    auth_response_t resp;
    ssize_t r = read(sfd, &resp, sizeof(resp));
    close(sfd);
    if (r != (ssize_t)sizeof(resp) || resp.magic != AUTH_MAGIC_RESP) {
        fprintf(stderr, "frontend: bad/short response from backend\n");
        return 1;
    }

    printf("%s\n", resp.granted ? "ACCESS GRANTED" : "ACCESS DENIED");
    if (resp.error_code != AUTH_ERR_NONE) {
        fprintf(stderr, "frontend: backend reported code=%d (%s)\n",
                resp.error_code, resp.message);
    }
    return resp.granted ? 0 : 2;
}
