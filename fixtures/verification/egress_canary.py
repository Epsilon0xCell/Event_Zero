"""Egress canary for the verification stage.

The corpus verification stage runs inside a network-disabled
container (docker run --network none). This canary asserts that the
isolation is real: it attempts several outbound connections and a
DNS resolution, and it PASSES only if every attempt fails. If any
outbound connection succeeds, the canary exits 1 and the job fails:
the no-outbound property is enforced by design and proven per run,
not assumed.
"""
import socket, sys

TARGETS = [("1.1.1.1", 53), ("8.8.8.8", 53), ("93.184.216.34", 80)]

def main():
    ok = True
    for host, port in TARGETS:
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            print(f"CANARY FAIL: outbound connection to {host}:{port} succeeded")
            ok = False
        except OSError as e:
            print(f"canary: {host}:{port} unreachable as required ({type(e).__name__})")
    try:
        socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        print("CANARY FAIL: DNS resolution succeeded")
        ok = False
    except OSError:
        print("canary: DNS resolution failed as required")
    print("EGRESS CANARY: PASS (no outbound connectivity)" if ok else "EGRESS CANARY: FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
