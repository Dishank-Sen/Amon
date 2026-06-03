// test_connect.c
// Comprehensive test for connect() syscall tracking
// Tests: successful connections, failures (ECONNREFUSED, ETIMEDOUT),
//        and async connections (EINPROGRESS)

#include <stdio.h>
// #include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>

void print_separator() {
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

void try_connect_blocking(const char *ip, int port, const char *desc) {
    printf("\n[TEST] %s\n", desc);
    printf("  Target: %s:%d (blocking)\n", ip, port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("  ❌ Socket creation failed\n");
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("  ❌ Invalid IP address\n");
        close(sock);
        return;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = (end.tv_sec - start.tv_sec) * 1000 +
              (end.tv_nsec - start.tv_nsec) / 1000000;

    if (ret == 0) {
        printf("  ✅ Connected successfully! (took %ld ms)\n", ms);
        printf("  Socket FD: %d\n", sock);
    } else {
        printf("  ❌ Connection failed (took %ld ms)\n", ms);
        printf("  Error: %s (errno=%d)\n", strerror(errno), errno);
    }

    close(sock);
}

void try_connect_nonblocking(const char *ip, int port, const char *desc) {
    printf("\n[TEST] %s\n", desc);
    printf("  Target: %s:%d (non-blocking)\n", ip, port);

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        printf("  ❌ Socket creation failed\n");
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("  ❌ Invalid IP address\n");
        close(sock);
        return;
    }

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    if (ret == 0) {
        printf("  ✅ Connected immediately!\n");
        printf("  Socket FD: %d\n", sock);
    } else if (errno == EINPROGRESS) {
        printf("  ⏳ Connection in progress (EINPROGRESS)\n");
        printf("  This is NORMAL for non-blocking sockets\n");
        printf("  Socket FD: %d\n", sock);
    } else {
        printf("  ❌ Connection failed\n");
        printf("  Error: %s (errno=%d)\n", strerror(errno), errno);
    }

    close(sock);
}

void try_connect_with_timeout(const char *ip, int port, const char *desc, int timeout_sec) {
    printf("\n[TEST] %s\n", desc);
    printf("  Target: %s:%d (timeout: %ds)\n", ip, port, timeout_sec);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("  ❌ Socket creation failed\n");
        return;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("  ❌ Invalid IP address\n");
        close(sock);
        return;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    clock_gettime(CLOCK_MONOTONIC, &end);
    long ms = (end.tv_sec - start.tv_sec) * 1000 +
              (end.tv_nsec - start.tv_nsec) / 1000000;

    if (ret == 0) {
        printf("  ✅ Connected! (took %ld ms)\n", ms);
    } else {
        printf("  ❌ Connection failed (took %ld ms)\n", ms);
        printf("  Error: %s (errno=%d)\n", strerror(errno), errno);

        if (errno == ETIMEDOUT) {
            printf("  ⏱️  Connection timed out (ETIMEDOUT)\n");
        }
    }

    close(sock);
}

int main() {
    printf("\n");
    print_separator();
    printf("   AMON CONNECT SYSCALL TEST\n");
    printf("   Testing various connection scenarios\n");
    print_separator();
    printf("\n");
    printf("This program will:\n");
    printf("  1. Test successful connections\n");
    printf("  2. Test connection refused (ECONNREFUSED)\n");
    printf("  3. Test connection timeout (ETIMEDOUT)\n");
    printf("  4. Test non-blocking async (EINPROGRESS)\n");
    printf("  5. Crash with SIGSEGV to trigger report generation\n");
    printf("\n");
    print_separator();

    // Test 1: Successful connection to Google DNS
    try_connect_blocking("8.8.8.8", 53,
        "Successful connection to public DNS");

    sleep(1);

    // Test 2: Connection refused (nothing listening on port)
    try_connect_blocking("127.0.0.1", 9999,
        "Connection refused (ECONNREFUSED)");

    sleep(1);

    // Test 3: Another connection refused
    try_connect_blocking("127.0.0.1", 8888,
        "Another connection refused");

    sleep(1);

    // Test 4: Connection timeout (unreachable)
    // Using TEST-NET-1 (192.0.2.0/24) - reserved, guaranteed no route
    try_connect_with_timeout("192.0.2.1", 80,
        "Connection timeout (ETIMEDOUT)", 3);

    sleep(1);

    // Test 5: Non-blocking connection (EINPROGRESS)
    try_connect_nonblocking("8.8.8.8", 53,
        "Non-blocking async connection (EINPROGRESS)");

    sleep(1);

    // Test 6: Multiple quick connection attempts
    printf("\n[TEST] Rapid connection attempts\n");
    for (int i = 0; i < 3; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(7777 + i),
        };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        printf("  Attempt %d: port %d... ", i+1, 7777+i);
        int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        printf("%s\n", ret == 0 ? "connected" : "refused");

        close(sock);
    }

    printf("\n");
    print_separator();
    printf("   TEST SUMMARY\n");
    print_separator();
    printf("\n");
    printf("Expected events in crash report:\n");
    printf("  • 1 successful connection (8.8.8.8:53)\n");
    printf("  • 5 failed connections (ECONNREFUSED)\n");
    printf("  • 1 timeout (ETIMEDOUT) - marked as SLOW\n");
    printf("  • 1 async connection (EINPROGRESS) - NOT an error\n");
    printf("\n");
    printf("Total: ~8-10 connect events\n");
    printf("Errors: 6 (NOT counting EINPROGRESS)\n");
    printf("Slow ops: 1 (ETIMEDOUT)\n");
    printf("\n");
    print_separator();

    printf("\n⏳ Waiting 2 seconds before crash...\n\n");
    sleep(2);

    printf("💥 Triggering crash (SIGSEGV)...\n\n");

    // Trigger segmentation fault
    int *ptr = NULL;
    *ptr = 42;

    return 0;
}
