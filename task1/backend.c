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
