// crash_test.c
#include <stdio.h>
// #include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    printf("Starting...\n");

    // simulate some real work before crash
    // open some files — your recorder should capture these
    int fd = open("/etc/hostname", O_RDONLY);
    close(fd);

    fd = open("/etc/passwd", O_RDONLY);
    close(fd);

    sleep(1);

    // deliberately cause a segfault
    // dereference a null pointer
    int *ptr = NULL;
    *ptr = 42;   // SIGSEGV here

    return 0;
}