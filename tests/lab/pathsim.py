#!/usr/bin/env python3
"""A fake multi-hop path on a TUN device, for tracer tests (§21.10).

Echo requests (ICMPv4 and ICMPv6) to the destination with TTL t below HOPS
get Time Exceeded from router t after t * HOP_DELAY_MS; TTL HOPS or more gets
an echo reply from the destination after HOPS * HOP_DELAY_MS. Router LOSSY
drops a share LOSS of its own Time Exceeded replies (as a router that rate
limits ICMP does); FORWARD_LOSS drops that share of the packets passing
router LOSSY, so the loss shows at every hop after it too.

Addresses (documentation ranges):
  destination  198.51.100.10        2001:db8:100::10
  router t     192.0.2.t            2001:db8:2::t

Usage: pathsim.py <tun device>. Settings come from the environment.
"""
import fcntl
import heapq
import os
import random
import struct
import sys
import threading
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

HOPS = int(os.environ.get("HOPS", "5"))
LOSSY = int(os.environ.get("LOSSY", "3"))
LOSS = float(os.environ.get("LOSS", "0.3"))
FORWARD_LOSS = float(os.environ.get("FORWARD_LOSS", "0"))
HOP_DELAY = float(os.environ.get("HOP_DELAY_MS", "1")) / 1000.0
random.seed(int(os.environ.get("SEED", "1")))

DEST4 = bytes([198, 51, 100, 10])
DEST6 = bytes.fromhex("20010db8010000000000000000000010")


def router4(t):
    return bytes([192, 0, 2, t])


def router6(t):
    return bytes.fromhex("20010db8000200000000000000000000")[:15] + bytes([t])


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, payload):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 1, 0, src, dst)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload


def icmp4(typ, code, rest):
    m = struct.pack("!BBH", typ, code, 0) + rest
    return m[:2] + struct.pack("!H", csum(m)) + m[4:]


def ipv6(src, dst, payload):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), 58, 64, src, dst) + payload


def icmp6(src, dst, typ, code, rest):
    m = struct.pack("!BBH", typ, code, 0) + rest
    pseudo = src + dst + struct.pack("!I3xB", len(m), 58)
    return m[:2] + struct.pack("!H", csum(pseudo + m)) + m[4:]


class Sender(threading.Thread):
    """Writes packets to the TUN device at their due time."""

    def __init__(self, fd):
        super().__init__(daemon=True)
        self.fd = fd
        self.heap = []
        self.seq = 0
        self.cv = threading.Condition()

    def at(self, due, pkt):
        with self.cv:
            self.seq += 1
            heapq.heappush(self.heap, (due, self.seq, pkt))
            self.cv.notify()

    def run(self):
        while True:
            with self.cv:
                while not self.heap:
                    self.cv.wait()
                due, _, pkt = self.heap[0]
                wait = due - time.monotonic()
                if wait > 0.002:
                    self.cv.wait(wait - 0.001)
                    continue
                heapq.heappop(self.heap)
            while time.monotonic() < due:
                pass  # spin the last millisecond for precise timing
            os.write(self.fd, pkt)


def answer(ttl, now, reply, exceeded):
    """Schedule the answer to a probe that left with `ttl`."""
    passes_lossy = ttl > LOSSY
    if passes_lossy and random.random() < FORWARD_LOSS:
        return None
    if ttl < HOPS:
        if ttl == LOSSY and random.random() < LOSS:
            return None
        return now + ttl * HOP_DELAY, exceeded(ttl)
    return now + HOPS * HOP_DELAY, reply()


def main():
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", sys.argv[1].encode(), IFF_TUN | IFF_NO_PI))
    sender = Sender(fd)
    sender.start()
    while True:
        p = os.read(fd, 65535)
        now = time.monotonic()
        if not p:
            continue
        version = p[0] >> 4
        if version == 4 and len(p) >= 28 and p[9] == 1:
            ihl = (p[0] & 15) * 4
            ttl, src, dst, body = p[8], p[12:16], p[16:20], p[ihl:]
            if dst != DEST4 or body[0] != 8:
                continue
            quoted = p[: ihl + 8]
            got = answer(
                ttl,
                now,
                lambda: ipv4(DEST4, src, icmp4(0, 0, body[4:])),
                lambda t: ipv4(router4(t), src, icmp4(11, 0, b"\0\0\0\0" + quoted)),
            )
        elif version == 6 and len(p) >= 48 and p[6] == 58:
            ttl, src, dst, body = p[7], p[8:24], p[24:40], p[40:]
            if dst != DEST6 or body[0] != 128:
                continue
            quoted = p[:1232]
            got = answer(
                ttl,
                now,
                lambda: ipv6(DEST6, src, icmp6(DEST6, src, 129, 0, body[4:])),
                lambda t: ipv6(router6(t), src, icmp6(router6(t), src, 3, 0, b"\0\0\0\0" + quoted)),
            )
        else:
            continue
        if got:
            sender.at(*got)


if __name__ == "__main__":
    main()
