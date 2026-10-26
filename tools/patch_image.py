#!/usr/bin/env python3
"""Build patched SlimBlade Pro v4.49 firmware containers.

Input is the STOCK container extracted from Kensington's official updater
(Kensington-Slimblade-Pro-V4.49.zip -> the .exe -> container, 128,112 bytes,
sha256 e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7).

Nothing produced here is redistributable: the output is Kensington's firmware.

    ./patch_image.py --src container.bin --rate 1000
    ./patch_image.py --src container.bin --map 0:1,1:0
    ./patch_image.py --src container.bin --rate 500 --map 0:1,1:0 -o both.bin

--rate edits the wired-mode loop divider only (one byte, 0x1c466).
--map installs the button hook (0x19d2c -> 0x21ac) and a 256-byte lookup table
      at 0x21bc, in dead space. ``0:1,1:0`` swaps HID button bits 0 and 1.

Both Beken image CRCs are regenerated after every edit.
"""

import argparse
import hashlib
import struct
import sys

STOCK_SHA256 = "e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7"
IMAGE_SIZE = 0x1F470

# (hz -> loop divider). rate = 1000 / divider, paced by USB SOF.
DIVIDER = {125: 0x08, 167: 0x06, 250: 0x04, 333: 0x03, 500: 0x02, 1000: 0x01}
RATE_SITE = 0x1C466

# button publish site and the dead space behind it
BUTTON_SITE = 0x19D2C
HOOK = 0x21AC
LUT = 0x21BC

APP_CRC = 0x2010
APP_CRC_RANGE = (0x2020, 0x1F470)
STACK_CRC = 0x1F70
STACK_CRC_RANGE = (0x1F80, 0x1F470)


def crc32_beken(data):
    """Reflected CRC-32, poly 0xEDB88320, init 0xFFFFFFFF, NO final xor.

    This is the variant Beken uses for both image headers. Plain zlib.crc32()
    does not match because it applies a final xor.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return crc


def bl_bytes(site, target):
    """Encode a Thumb-2 BL from `site` to `target`."""
    off = target - (site + 4)
    if not -(1 << 24) <= off < (1 << 24) or off & 1:
        raise ValueError(f"bl offset out of range: {off:#x}")
    s = (off >> 24) & 1
    i1, i2 = (off >> 23) & 1, (off >> 22) & 1
    j1, j2 = (~(i1 ^ s)) & 1, (~(i2 ^ s)) & 1
    return struct.pack(
        "<HH",
        0xF000 | (s << 10) | ((off >> 12) & 0x3FF),
        0xD000 | (j1 << 13) | (j2 << 11) | ((off >> 1) & 0x7FF),
    )


def parse_map(spec):
    """Parse '0:1,1:0' into [(src_bit, dst_bit)], validating it is a bijection."""
    pairs = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        src, dst = (int(x, 0) for x in item.split(":"))
        if not (0 <= src < 8 and 0 <= dst < 8):
            raise ValueError(f"bit out of range in {item!r}")
        pairs.append((src, dst))
    srcs = [s for s, _ in pairs]
    dsts = [d for _, d in pairs]
    if len(set(srcs)) != len(srcs) or len(set(dsts)) != len(dsts):
        raise ValueError("mapping is not one-to-one")
    return pairs


def build_lut(pairs):
    """Table mapping an old button byte to a new one. Unlisted bits pass through."""
    dst_bits = {d for _, d in pairs}
    lut = bytearray(256)
    for value in range(256):
        out = 0
        for bit in range(8):
            if bit in dst_bits:
                continue
            out |= ((value >> bit) & 1) << bit
        for src, dst in pairs:
            out |= ((value >> src) & 1) << dst
        lut[value] = out
    return bytes(lut)


def build_hook(lut_addr):
    """Interpose a lookup table on the stock byte copy.

    The original site does `ldrb r0,[r4,#2] ; strb r0,[r4,#1]` (copy the raw
    button byte into the published byte). The hook reproduces that pair with a
    table lookup in between:

        0x21ac  ldrb r0,[r4,#2]
        0x21ae  ldr  r1,[pc,#8]      ; -> 0x21b8
        0x21b0  ldrb r0,[r1,r0]
        0x21b2  strb r0,[r4,#1]
        0x21b4  bx   lr
        0x21b6  nop
        0x21b8  .word lut_addr
    """
    return bytes.fromhex("a078" "0249" "085c" "6070" "7047" "c046") + struct.pack("<I", lut_addr)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", default="container.bin", help="stock container")
    ap.add_argument("-o", "--out", help="output path (default derived from options)")
    ap.add_argument("--rate", type=int, choices=sorted(DIVIDER), help="wired report rate in Hz")
    ap.add_argument("--map", help="button bit permutation, e.g. 0:1,1:0")
    ap.add_argument("--force", action="store_true", help="skip the stock sha256 check")
    args = ap.parse_args(argv)

    blob = open(args.src, "rb").read()
    if len(blob) != IMAGE_SIZE:
        sys.exit(f"{args.src}: expected {IMAGE_SIZE} bytes, got {len(blob)}")
    digest = hashlib.sha256(blob).hexdigest()
    img = bytearray(blob)

    # Re-running on an already patched image would move the stitch, not just
    # change a constant, so require a clean base unless explicitly forced.
    if digest != STOCK_SHA256:
        if not args.force:
            sys.exit(f"{args.src}: not the stock container (sha256 {digest})")
        if img[BUTTON_SITE:BUTTON_SITE + 2] != b"\xe8\xf7":
            sys.exit(f"{args.src}: button site is not a BL; refusing to re-hook")

    if not args.rate and not args.map:
        sys.exit("nothing to do: pass --rate and/or --map")

    parts = []
    if args.rate:
        img[RATE_SITE] = DIVIDER[args.rate]
        parts.append(f"{args.rate}hz")

    if args.map:
        pairs = parse_map(args.map)
        img[BUTTON_SITE:BUTTON_SITE + 4] = bl_bytes(BUTTON_SITE, HOOK)
        hook = build_hook(LUT)
        img[HOOK:HOOK + len(hook)] = hook
        img[LUT:LUT + 256] = build_lut(pairs)
        parts.append("map" + "".join(f"{s}-{d}" for s, d in pairs))

    lo, hi = APP_CRC_RANGE
    img[APP_CRC:APP_CRC + 4] = struct.pack("<I", crc32_beken(img[lo:hi]))
    lo, hi = STACK_CRC_RANGE
    img[STACK_CRC:STACK_CRC + 4] = struct.pack("<I", crc32_beken(img[lo:hi]))

    out = args.out or "container-" + "-".join(parts) + ".bin"
    open(out, "wb").write(img)
    print(out, hashlib.sha256(img).hexdigest())


if __name__ == "__main__":
    main()
