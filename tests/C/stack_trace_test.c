/*
 * Stack Trace Test - Native C Program
 *
 * This demonstrates proper stack trace capture with native code.
 * Unlike Python, each function creates a real stack frame that eBPF can see.
 */

#include <stdio.h>
#include <unistd.h>

void crash_function() {
    printf("  → crash_function() - about to crash...\n");
    fflush(stdout);
    usleep(100000);  // 0.1 seconds

    // NULL pointer dereference - guaranteed SIGSEGV
    *(int*)0 = 42;
}

void level_3() {
    printf("  → level_3() called\n");
    usleep(100000);
    crash_function();
}

void level_2() {
    printf("  → level_2() called\n");
    usleep(100000);
    level_3();
}

void level_1() {
    printf("  → level_1() called\n");
    usleep(100000);
    level_2();
}

int main() {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("       Amon Stack Trace Test - Native C Code\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    printf("Process started (PID: %d)\n\n", getpid());
    printf("Call chain:\n");
    printf("  main()\n");

    level_1();

    printf("This line never executes\n");
    return 0;
}
