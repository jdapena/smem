# smemcap

A replacement for the BusyBox `smemcap` utility that captures a richer
snapshot of `/proc` for offline analysis with `smem`.

## Why a custom smemcap?

The standard BusyBox `smemcap` has been essentially unchanged since 2008.
It captures only five `/proc` entries per process:

```
meminfo  version  [pid]/smaps  [pid]/cmdline  [pid]/stat
```

This version adds:

| File | Why it matters |
|------|----------------|
| `[pid]/smaps_rollup` | Pre-summed smaps (kernel ≥ 4.14) — makes offline analysis faster |
| `[pid]/status` | `VmPeak`, `VmSwap`, thread count, `NSpid` — not available in smaps |
| `[pid]/cgroup` | Which app container owns the process (essential for webOS) |
| `swaps` | Active swap/zram devices and their total/used sizes |
| `pressure/memory` | PSI memory pressure at capture time (kernel ≥ 4.20) |

Files that don't exist on the target kernel (e.g. no PSI support, no
`smaps_rollup`) are silently skipped.

## Building

### Dynamic binary (smallest, requires glibc on target)

```bash
gcc -Os -o smemcap smemcap.c
strip smemcap
# result: ~15 KB
```

### Static binary with musl (self-contained, no runtime dependencies)

```bash
# Requires musl-tools: apt install musl-tools
musl-gcc -Os -static -flto -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -o smemcap smemcap.c
strip smemcap
# result: ~46 KB
```

### Cross-compiling for ARM/AArch64 targets

Replace the compiler with your cross toolchain and build statically so
the binary runs regardless of what libc (if any) is on the device:

```bash
# AArch64 (webOS on modern LG TVs, Raspberry Pi 4, etc.)
aarch64-linux-gnu-gcc -Os -static -o smemcap smemcap.c
strip smemcap

# ARMv7 hard-float (older embedded boards)
arm-linux-gnueabihf-gcc -Os -static -o smemcap smemcap.c
strip smemcap
```

For musl-based cross toolchains (e.g. from
[musl.cc](https://musl.cc) or Buildroot):

```bash
aarch64-linux-musl-gcc -Os -static -o smemcap smemcap.c
strip smemcap
```

## Usage

Identical to standard smemcap — pipe to a file and copy it off the device:

```bash
smemcap > capture.tar
# then on the analysis machine:
smem --source capture.tar
```
