#!/usr/bin/env python3
"""
Real-world network crash test for Amon
Makes actual network connections then crashes
"""

import socket
import time
import ctypes

def test_successful_connection():
    """Connect to Google DNS - should succeed"""
    print("[+] Testing successful connection to 8.8.8.8:53...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("8.8.8.8", 53))
        print("    ✓ Connected successfully")
        sock.close()
    except Exception as e:
        print(f"    ✗ Failed: {e}")

def test_connection_refused():
    """Connect to localhost on closed port - should get ECONNREFUSED"""
    print("[+] Testing connection refused (127.0.0.1:9999)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect(("127.0.0.1", 9999))
        print("    ? Unexpected success")
        sock.close()
    except ConnectionRefusedError:
        print("    ✓ Got ECONNREFUSED as expected")
    except Exception as e:
        print(f"    ✗ Unexpected error: {e}")

def test_connection_timeout():
    """Connect to non-routable IP - should timeout"""
    print("[+] Testing connection timeout (192.0.2.1:80)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        start = time.time()
        sock.connect(("192.0.2.1", 80))  # TEST-NET-1, should timeout
        print("    ? Unexpected success")
        sock.close()
    except socket.timeout:
        elapsed = time.time() - start
        print(f"    ✓ Timeout after {elapsed:.1f}s")
    except Exception as e:
        print(f"    ✗ Error: {e}")

def test_http_request():
    """Make real HTTP connection to example.com"""
    print("[+] Testing HTTP connection to example.com:80...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(("93.184.216.34", 80))  # example.com IP
        print("    ✓ Connected to example.com")

        # Send minimal HTTP request
        sock.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        response = sock.recv(100)
        print(f"    ✓ Got response: {len(response)} bytes")
        sock.close()
    except Exception as e:
        print(f"    ✗ Failed: {e}")

def test_multiple_connections():
    """Make several quick connections"""
    print("[+] Testing multiple rapid connections...")
    for i in range(3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(("8.8.8.8", 53))
            sock.close()
            print(f"    ✓ Connection {i+1}/3 succeeded")
        except Exception as e:
            print(f"    ✗ Connection {i+1}/3 failed: {e}")

def trigger_crash():
    """Trigger segmentation fault to generate crash report"""
    print("\n[!] Triggering crash...")
    time.sleep(0.5)  # Brief pause so last events are captured

    # Dereference null pointer - guaranteed SIGSEGV
    ctypes.string_at(0)

if __name__ == "__main__":
    print("═══════════════════════════════════════════════════════════")
    print("       Amon Network Crash Test - Real World Demo")
    print("═══════════════════════════════════════════════════════════\n")

    test_successful_connection()
    time.sleep(0.5)

    test_connection_refused()
    time.sleep(0.5)

    test_connection_timeout()
    time.sleep(0.5)

    test_http_request()
    time.sleep(0.5)

    test_multiple_connections()
    time.sleep(0.5)

    trigger_crash()
