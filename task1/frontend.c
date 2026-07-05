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
