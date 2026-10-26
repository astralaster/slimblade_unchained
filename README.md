# Slimblade unchained

This repo provides scripts to patch the official v4.49 firmware of kensington slimblade pro to unlock 1khz usb polling in wired mode.
Its based on https://github.com/SirTremain/slimblade work reverse engineering the firmware and done with the help of deepseek.

# Instructions

## Download the official firmware v4.49 zip file.
https://accobrands.co.jp/wp/wp-content/uploads/Kensington-Slimblade-Pro-V4.49.zip
## Extract the firmware from the zip
```sh
unzip -o "Kensington-Slimblade-Pro-V4.49.zip"        # -> .exe, 3,008,000 bytes
python3 - <<'EOF'
exe = open("Kensington Slimblade Pro V4.49.exe","rb").read()
base = 0x21f0db - 0x1e7d1          # device descriptor found at EXE 0x21f0db
open("container.bin","wb").write(exe[base:base+128112])
EOF
```

## Patch the firmware

`container.bin` is the stock image extracted from Kensington's updater

```sh
python3 tools/patch_image.py --src container.bin --rate 1000
```
`--rate` accepts 125, 167, 250, 333, 500, 1000 (divider = 1000/Hz).

## Building the flasher

The CLI is upstream work, not included here. Clone it and drop the crate in:

```sh
cargo build --release -p slimblade-cli -p rate-flash
```
## Flashing

```sh
# 1. identify the vendor hidraw for 047d:80d7 interface :1.1
# 2. enter the loader (0x0d report); the device re-enumerates as 25a7:fabe
target/release/slimblade --device /dev/hidrawN --timeout-seconds 10 enter-loader --confirm

# 3. flash a locally built container, hash pinned on the command line.
#    The wrapper re-finds the loader itself and proves the `d2` query before
#    anything is erased.
target/release/rate-flash /dev/hidrawM firmware/container-1000hz.bin \
  811c11e09a17aef52eb1d3fed3b4587ea00de8471bbb2c8d3f6f2e828740bd98
```

A successful run prints `write/verify: 100% (3748/3748)`, then
`application=047d:80d7 bcdDevice=0449`. To roll back, repeat with
`container.bin` (the stock image) and its hash.

## Verifying

```sh
python3 tools/measure_rate.py -s 8          # wired mouse interface (047d:80d7)
```

Spin the ball continuously. The device only emits when motion or button state
changes, so idle stretches appear as long gaps rather than a low rate.


# sha-256 checksums of files

| file | checksum |
| --- | --- |
| Kensington-Slimblade-Pro-V4.49.zip | dffe13ab063cb9614669914295b273bda0e5906bc5af75b3f73cd2da5f0f41ac |
| stock | e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7 |
| 1khz | 811c11e09a17aef52eb1d3fed3b4587ea00de8471bbb2c8d3f6f2e828740bd98 |
