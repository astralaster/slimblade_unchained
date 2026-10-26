#!/usr/bin/env python3
"""Measure a SlimBlade Pro HID report interval.

Timestamps every incoming report on a hidraw node and reports the interval
distribution. The median is the payload cadence; the histogram shows whether the
firmware keeps up. Full-speed USB frames are 1 ms, so intervals quantise to
whole milliseconds and are bucketed that way.

    ./measure_rate.py                      # wired mouse interface, 8 s
    ./measure_rate.py --pid 80d6           # 2.4 GHz receiver, mouse interface
    ./measure_rate.py -d /dev/hidraw9 -s 6

Spin the ball continuously while it runs. Reports are only emitted when motion
or button state changes (see docs, section 14.2), so idle time shows up as long
gaps rather than a low rate.
"""

import argparse
import os
import re
import select
import sys
import time

VENDOR = "047D"
INTERFACE = ":1.0/"  # mouse interface; :1.1 is the vendor/config interface


def find_device(pid):
    """Locate the mouse hidraw node for a 047d:pid device.

    HID_ID lives on the parent HID device's uevent, not the hidraw node's.
    """
    hits = []
    for name in sorted(os.listdir("/sys/class/hidraw")):
        hid = f"/sys/class/hidraw/{name}"
        try:
            uevent = open(f"{hid}/device/uevent").read()
        except OSError:
            continue
        match = re.search(r"HID_ID=0003:0000([0-9A-F]{4}):0000([0-9A-F]{4})", uevent)
        if not match or match.group(1) != VENDOR or match.group(2).upper() != pid.upper():
            continue
        node = f"/dev/{name}"
        if not os.path.exists(node):
            continue
        if INTERFACE not in os.path.realpath(f"{hid}/device"):
            continue
        hits.append(node)
    return hits


def capture(node, seconds):
    fd = os.open(node, os.O_RDONLY | os.O_NONBLOCK)
    stamps = []
    deltas = []
    deadline = time.perf_counter() + seconds
    try:
        while True:
            remain = deadline - time.perf_counter()
            if remain <= 0:
                break
            ready, _, _ = select.select([fd], [], [], remain)
            if not ready:
                break
            buf = os.read(fd, 8192)
            now = time.perf_counter()
            count = len(buf) // 7
            for i in range(count):
                stamps.append(now)
                dx = int.from_bytes(buf[i * 7 + 1:i * 7 + 3], "little", signed=True)
                dy = int.from_bytes(buf[i * 7 + 3:i * 7 + 5], "little", signed=True)
                deltas.append((dx, dy))
    finally:
        os.close(fd)
    return stamps, deltas


def report(stamps, deltas):
    if len(stamps) < 10:
        print("not enough reports — was the ball moving?")
        return 1

    span = stamps[-1] - stamps[0]
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    live = sorted(g for g in gaps if g < 0.050)

    print(f"reports      : {len(stamps)} over {span:.3f} s  ({(len(stamps) - 1) / span:.1f}/s)")
    if not live:
        print("no continuous motion captured")
        return 1

    median = live[len(live) // 2]
    p90 = live[int(len(live) * 0.90)]
    p99 = live[int(len(live) * 0.99)]
    print(f"interval     : median {median * 1000:.3f} ms  ->  {1 / median:.1f} Hz")
    print(f"               p90 {p90 * 1000:.2f} ms   p99 {p99 * 1000:.2f} ms   "
          f"max<50ms {live[-1] * 1000:.2f} ms")

    buckets = {}
    for gap in live:
        ticks = max(1, round(gap * 1000))
        buckets[ticks] = buckets.get(ticks, 0) + 1
    print("frame ticks  :")
    for ticks in sorted(buckets):
        share = 100 * buckets[ticks] / len(live)
        label = f"{ticks} ms" if ticks < 9 else ">=9 ms"
        print(f"  {label:>6}   {buckets[ticks]:6d}  {share:5.1f}%  {'#' * int(share / 2)}")

    dx = sum(abs(x) for x, _ in deltas)
    dy = sum(abs(y) for _, y in deltas)
    zero = sum(1 for x, y in deltas if x == 0 and y == 0)
    print(f"motion       : sum|dx| {dx}  sum|dy| {dy}  ->  {(dx + dy) / span:.0f} counts/s")
    print(f"               mean |dx| {dx / len(deltas):.2f}  mean |dy| {dy / len(deltas):.2f}  "
          f"per report")
    print(f"zero-delta   : {zero}/{len(deltas)} ({100 * zero / len(deltas):.1f}%)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="measure SlimBlade Pro report interval")
    ap.add_argument("-d", "--device", help="hidraw node (default: auto-detect)")
    ap.add_argument("-p", "--pid", default="80d7",
                    help="USB product id: 80d7 wired, 80d6 2.4 GHz receiver")
    ap.add_argument("-s", "--seconds", type=float, default=8.0)
    args = ap.parse_args()

    node = args.device
    if not node:
        hits = find_device(args.pid)
        if not hits:
            sys.exit(f"no 047d:{args.pid} mouse interface found")
        if len(hits) > 1:
            print(f"note: multiple matches, using {hits[0]} (of {', '.join(hits)})")
        node = hits[0]

    print(f"device       : {node}")
    stamps, deltas = capture(node, args.seconds)
    return report(stamps, deltas)


if __name__ == "__main__":
    sys.exit(main())
