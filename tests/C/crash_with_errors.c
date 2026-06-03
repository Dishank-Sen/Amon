// crash_with_errors.c
// Demonstrates signal vs noise filtering
// This does many successful operations + a few failures before crashing
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    printf("Starting test: many successful ops + failures + crash\n");

    // 100 successful reads - should NOT appear in report (noise)
    for (int i = 0; i < 100; i++) {
        int fd = open("/etc/hostname", O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // A few failures - SHOULD appear in report (signal!)
    printf("Attempting to open non-existent files (errors)...\n");
    open("/nonexistent/file1.txt", O_RDONLY);  // ERROR: -ENOENT
    open("/nonexistent/file2.txt", O_RDONLY);  // ERROR: -ENOENT
    open("/root/secret.txt", O_RDONLY);         // ERROR: -EACCES (permission denied)

    // More successful operations
    for (int i = 0; i < 50; i++) {
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // One more error right before crash
    printf("Final error before crash...\n");
    open("/this/does/not/exist", O_RDONLY);     // ERROR: -ENOENT

    // A few more successful ops
    int fd = open("/etc/hostname", O_RDONLY);
    close(fd);

    printf("About to crash...\n");
    sleep(1);

    // Crash!
    int *ptr = NULL;
    *ptr = 42;   // SIGSEGV

    return 0;
}
