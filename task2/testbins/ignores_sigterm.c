#include <signal.h>
#include <unistd.h>
#include <stdio.h>
/* Simulates malware that tries to survive graceful termination -- the
 * sandbox must escalate to SIGKILL, which cannot be caught or ignored. */
static void handler(int sig) { (void)sig; /* swallow SIGTERM */ }
int main(void) {
    signal(SIGTERM, handler);
    for (;;) { usleep(200000); }
    return 0;
}
                        
