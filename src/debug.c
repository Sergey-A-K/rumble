#include "rumble.h"
#include "private.h"
#include <signal.h>

#include <execinfo.h>
#include <errno.h>
#include <ucontext.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <bits/types/siginfo_t.h>


static void         signal_handler(int sig, siginfo_t *info, void *ucontext);
struct sigaction    sigact;
uint32_t            lastClick = 0;
int                 alreadyDead = 0;


static void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (sig == SIGQUIT || sig == SIGHUP) {
        printf("User ended the program - bye bye!\n");
        cleanup();
    } else if (sig == SIGPIPE) { printf("SIGPIPE - Client disconnected\n");
    } else if (sig == SIGKILL) { printf("SIGKILL - Rumble got killed :(\n");
        cleanup();
    } else if (sig == SIGTERM) { printf("SIGTERM - Rumble got killed :(\n");
        cleanup();
    } else if (sig == SIGINT) {
        if (time(0) - lastClick < 2) {
            cleanup();
            exit(0);
        }
        printf("SIGINT (Ctrl+C detected). Press it again to exit rumble.\n");
        lastClick = time(0);
    } else {
        if (!alreadyDead) {
            void * array[50];
            alreadyDead++;
            ucontext_t * context = (ucontext_t *) ucontext;
            rumble_debug(NULL, "debug", "Caught signal %d (%s), address is %p\n", sig, strsignal(sig), info->si_addr);
            rumble_debug(NULL, "debug", "PID=%d \n", getpid());
            rumble_debug(NULL, "debug", "signo=%d/%s\n", sig, strsignal(sig));
            rumble_debug(NULL, "debug", "code=%d (not always applicable)\n", info->si_code);
            rumble_debug(NULL, "debug", "\nContext: 0x%08lx\n", (unsigned long) ucontext);
            rumble_debug(NULL, "debug", "Register stuff:\n"
                "  R8:  0x%08x   R9: 0x%08x  R10: 0x%08x  R11: 0x%08x\n"
                "  R12: 0x%08x  R13: 0x%08x  R14: 0x%08x  R15: 0x%08x\n"
                "  RDI: 0x%08x  RSI: 0x%08x  RBP: 0x%08x  RBX: 0x%08x\n"
                "  RDX: 0x%08x  RAX: 0x%08x  RCX: 0x%08x  RSP: 0x%08x\n"
                "  RIP: 0x%08x  EFL: 0x%08x  CSGSFS: 0x%08x  ERR: 0x%08x\n"
                "  TRAPNO: 0x%08x  OLDMASK: 0x%08x  CR2: 0x%08x",
                context->uc_mcontext.gregs[0],  context->uc_mcontext.gregs[1],
                context->uc_mcontext.gregs[2],  context->uc_mcontext.gregs[3],  context->uc_mcontext.gregs[4],
                context->uc_mcontext.gregs[5],  context->uc_mcontext.gregs[6],  context->uc_mcontext.gregs[7],
                context->uc_mcontext.gregs[8],  context->uc_mcontext.gregs[9],  context->uc_mcontext.gregs[10],
                context->uc_mcontext.gregs[11], context->uc_mcontext.gregs[12], context->uc_mcontext.gregs[13],
                context->uc_mcontext.gregs[14], context->uc_mcontext.gregs[15], context->uc_mcontext.gregs[16],
                context->uc_mcontext.gregs[17], context->uc_mcontext.gregs[18], context->uc_mcontext.gregs[19],
                context->uc_mcontext.gregs[20], context->uc_mcontext.gregs[21], context->uc_mcontext.gregs[22]);

            int size = backtrace(array, 50);
            char ** messages = backtrace_symbols(array, size);

            // skip first stack frame (points here)
            for (int i = 1; i < size && messages != NULL; ++i)
                rumble_debug(NULL, "debug", "[backtrace]: (%d) %s\n", i, messages[i]);

            cleanup();
        } else exit(0);
    }
}


void attach_debug() {
    sigact.sa_sigaction = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART | SA_SIGINFO;
    sigaction(SIGKILL, &sigact, 0);
    sigaction(SIGINT, &sigact, 0);
    sigaction(SIGSEGV, &sigact, 0);
    sigaction(SIGSTKFLT, &sigact, 0);
    sigaction(SIGHUP, &sigact, 0);
    sigaction(SIGQUIT, &sigact, 0);
    sigaction(SIGPIPE, &sigact, 0);
    sigaction(SIGKILL, &sigact, 0);

}
