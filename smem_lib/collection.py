"""Raw data collection and computation from /proc or tarfile sources."""

import functools
import multiprocessing
import os
import re
import sys
from typing import Dict

from smem_lib import _globals as _g
from smem_lib.utils import filters, fromunits
from smem_lib.readers import MemData, ProcessData

# Worker processes rely on inheriting the parent's _g.options/_g.proc state,
# which only happens with the "fork" start method. Python 3.14 changed the
# default to "forkserver" on Linux, under which workers are fresh processes
# with an uninitialized _g and silently produce no data. smem is a Linux
# /proc tool, so "fork" is always available; pin it explicitly.
_mp_context = multiprocessing.get_context("fork")


def Pool(*args, **kwargs):
    return _mp_context.Pool(*args, **kwargs)


def totalmem():
    if _g.options.realmem:
        return fromunits(_g.options.realmem) / 1024
    else:
        memdata = MemData()
        return memdata("memtotal")


def pidmaps_with_pid(pid) -> (int, Dict[int, Dict[str, int]]):
    return pid, pidmaps(pid)


def pidmaps(pid) -> Dict[int, Dict[str, int]]:
    maps = {}
    start = None
    seen = False
    empty = True
    warned = False
    try:
        mapdata = _g.proc.mapdata(pid)
    except:
        return {}

    for l in mapdata:
        empty = False
        f = l.split()
        if f[-1] == "kB":
            if f[0].startswith("Pss"):
                seen = True
            maps[start][f[0][:-1].lower()] = int(f[1])
        elif "-" in f[0] and ":" not in f[0]:  # looks like a mapping range
            start, end = f[0].split("-")
            start = int(start, 16)
            name = "<anonymous>"
            if len(f) > 5:
                name = f[5]
            maps[start] = dict(
                end=int(end, 16),
                mode=f[1],
                offset=int(f[2], 16),
                device=f[3],
                inode=f[4],
                name=name,
            )

    if not empty and not seen and not warned:
        print("Warning: Kernel does not appear to support PSS measurement")
        warned = True
        if not _g.options.sort:
            _g.options.sort = "rss"

    if _g.options.mapfilter:
        f = {}
        for m in maps:
            if not filters(_g.options.mapfilter, m, lambda x: maps[x]["name"]):
                f[m] = maps[m]
        return f
    return maps


def aggregate_name(name, mode=""):
    if name.startswith("[") or name.startswith("<"):
        return name
    elif name.startswith("anon_inode"):
        return name
    elif name.startswith("/usr/lib") or name.startswith("/lib"):
        return "[system libraries]"
    elif name.startswith("/dev/shm"):
        return "[shm]"
    elif (name.startswith("/dev/dri") or name.startswith("/dev/mali") or
          name.startswith("/dev/pvr") or name.startswith("/dev/kgsl") or
          name.startswith("/dev/galcore") or
          "udmabuf" in name):
        return "[gpu devices]"
    elif name.startswith("/dev"):
        return "[other devices]"
    elif name.startswith("/usr/share/fonts") or name.startswith("/var/cache/fontconfig"):
        return "[fonts]"
    elif name.startswith("/memfd:") and "x" in mode:
        return "[jit code]"
    elif name.startswith("/memfd:"):
        return "[memfd]"
    elif name.endswith(".so") or re.search(r"\.so\.\d", name):
        return "[other libraries]"
    elif name.endswith(".pak") or name.endswith(".dat") or name.endswith(".bin"):
        return "[resources]"
    elif "x" in mode:
        return "[executables]"
    return "[other mappings]"


def maptotals(pids, allowed_cpu_count, is_aggregate=False):
    filtered_pids = filter(
        lambda pid: not filters(_g.options.processfilter, pid, _g.proc.pidcmd) and
                    not filters(_g.options.userfilter, pid, _g.proc.pidusername) and
                    not filters(_g.options.cgroupfilter, pid, _g.proc.pidcgroup),
        pids)

    totals = {}
    pids_lists = {}
    with Pool(processes=allowed_cpu_count) as pool:
        for pid, maps in pool.map(pidmaps_with_pid, filtered_pids):
            if len(maps) == 0:
                continue
            seen = {}
            for m in list(maps.keys()):
                name = maps[m]["name"]
                if is_aggregate:
                    name = aggregate_name(name, maps[m].get("mode", ""))
                if name not in totals:
                    t = dict(
                        size=0,
                        rss=0,
                        pss=0,
                        shared_clean=0,
                        shared_dirty=0,
                        private_clean=0,
                        count=0,
                        private_dirty=0,
                        referenced=0,
                        swap=0,
                        pids=0,
                        shared_exec=0,
                        shared_data=0,
                        priv_ro=0,
                        priv_rw=0,
                    )
                else:
                    t = totals[name]

                for k in t:
                    t[k] += maps[m].get(k, 0)

                mode = maps[m].get("mode", "")
                seg_shared = maps[m].get("shared_clean", 0) + maps[m].get("shared_dirty", 0)
                seg_private = maps[m].get("private_clean", 0) + maps[m].get("private_dirty", 0)
                if "x" in mode:
                    t["shared_exec"] += seg_shared
                else:
                    t["shared_data"] += seg_shared
                if "w" in mode:
                    t["priv_rw"] += seg_private
                else:
                    t["priv_ro"] += seg_private

                t["count"] += 1
                if name not in seen:
                    t["pids"] += 1
                    seen[name] = 1
                    pids_lists.setdefault(name, []).append(str(pid))
                totals[name] = t
    for name in list(totals.keys()):
        totals[name]["pids_list"] = ",".join(pids_lists[name])

    return totals


def pidmaps_rollup(pid) -> Dict[int, Dict[str, int]]:
    try:
        smaps_rollup_lines = _g.proc.readlines("%s/smaps_rollup" % pid)
    except:
        return {}
    if not smaps_rollup_lines:
        return {}
    header = smaps_rollup_lines[0]
    stats = smaps_rollup_lines[1:]
    maps = {}

    header_parts = header.split()
    start, end = header_parts[0].split("-")
    start = int(start, 16)
    name = header_parts[5] if len(header_parts) > 5 else "<rollup>"
    maps[start] = dict(
        end=int(end, 16),
        mode=header_parts[1],
        offset=int(header_parts[2], 16),
        device=header_parts[3],
        inode=header_parts[4],
        name=name,
    )

    for stat in stats:
        key = stat[0:16].rstrip(': ')
        value = stat[17:-3].strip()
        maps[start][key.lower()] = int(value)

    return maps


def pidtotals(pid, pidmaps_f=pidmaps) -> Dict[str, int]:
    maps = pidmaps_f(pid)
    if len(maps) == 0:
        return dict(pid=pid, maps=0)

    t = dict(
        pid=pid,
        size=0,
        rss=0,
        pss=0,
        shared_clean=0,
        shared_dirty=0,
        private_clean=0,
        private_dirty=0,
        referenced=0,
        swap=0,
    )
    for m in list(maps.keys()):
        for k in t:
            t[k] += maps[m].get(k, 0)

    t["uss"] = t["private_clean"] + t["private_dirty"]
    t["maps"] = len(maps)

    return t


def usertotals(pids, allowed_cpu_count, pidmaps_f=pidmaps):
    filtered_pids = list(filter(
        lambda p: not filters(_g.options.processfilter, p, _g.proc.pidcmd) and
                  not filters(_g.options.userfilter, p, _g.proc.pidusername) and
                  not filters(_g.options.cgroupfilter, p, _g.proc.pidcgroup),
        pids))

    totals = {}
    with Pool(processes=allowed_cpu_count) as pool:
        all_maps = pool.map(pidmaps_f, filtered_pids)
        for i in range(len(all_maps)):
            maps = all_maps[i]
            pid = filtered_pids[i]
            if len(maps) == 0:
                continue
            user = _g.proc.piduser(pid)

            if user not in totals:
                t = dict(
                    size=0,
                    rss=0,
                    pss=0,
                    shared_clean=0,
                    shared_dirty=0,
                    private_clean=0,
                    count=0,
                    private_dirty=0,
                    referenced=0,
                    swap=0,
                )
            else:
                t = totals[user]

            for m in list(maps.keys()):
                for k in t:
                    t[k] += maps[m].get(k, 0)

            t["count"] += 1
            totals[user] = t

    return totals


def processtotals(pids, allowed_cpu_count, pidmaps_f=pidmaps):
    filtered_pids = filter(
        lambda pid: not filters(_g.options.processfilter, pid, _g.proc.pidcmd) and
                    not filters(_g.options.userfilter, pid, _g.proc.pidusername) and
                    not filters(_g.options.cgroupfilter, pid, _g.proc.pidcgroup),
        pids)
    totals = {}
    with Pool(processes=allowed_cpu_count) as pool:
        for p in pool.map(functools.partial(pidtotals, pidmaps_f=pidmaps_f), filtered_pids):
            if p["maps"] != 0:
                totals[p["pid"]] = p

    return totals


_DRM_MEM_RE = re.compile(r'^drm-(total|memory)-([\w]+):\s*(\d+)(?:\s*(KiB|MiB|GiB))?\s*$')
_DRM_UNITS = {None: 1, "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}


def _drm_region_class(region):
    """Map a DRM memory region name to 'vram' or 'gtt' (None if neither).

    amdgpu: vram, gtt; xe: vram0.., gtt; i915: local0.. (device memory).
    """
    if region.startswith("vram") or region.startswith("local"):
        return "vram"
    if region == "gtt":
        return "gtt"
    return None


def pid_gpu_memory(pid):
    """Return per-GPU VRAM/GTT totals for one process via DRM fdinfo.

    Returns a dict keyed by pdev (PCI address string), each value a dict with
    'driver' and summed memory region keys in KiB (e.g. 'vram', 'gtt').
    Returns {} when no DRM GPU fds are found or fdinfo is unavailable.

    Follows the kernel DRM client usage stats spec: drm-total-<region> is
    preferred over the legacy drm-memory-<region>, values without a unit
    are bytes, and fds sharing a drm-client-id (e.g. dup'd fds) describe
    the same client and are counted once.
    """
    result = {}
    seen = set()
    for fd in _g.proc.list_pid_fdinfo(pid):
        content = _g.proc.read_fdinfo(pid, fd)
        if not content:
            continue
        pdev = None
        driver = None
        client_id = None
        regions = {"total": {}, "memory": {}}
        for line in content.splitlines():
            if line.startswith("drm-pdev:"):
                pdev = line.split(":", 1)[1].strip()
            elif line.startswith("drm-driver:"):
                driver = line.split(":", 1)[1].strip()
            elif line.startswith("drm-client-id:"):
                client_id = line.split(":", 1)[1].strip()
            else:
                m = _DRM_MEM_RE.match(line)
                if m:
                    kind, region, val, unit = m.groups()
                    regions[kind][region] = int(val) * _DRM_UNITS[unit] // 1024
        if not pdev:
            continue
        if client_id is not None:
            key = (pdev, driver, client_id)
            if key in seen:
                continue
            seen.add(key)
        chosen = regions["total"] or regions["memory"]
        entry = result.setdefault(pdev, {"driver": driver or ""})
        for region, val in chosen.items():
            cls = _drm_region_class(region)
            if cls:
                entry[cls] = entry.get(cls, 0) + val
    return result


def processtotals_gpu(pids, allowed_cpu_count, pidmaps_f=None):
    """Like processtotals() but adds gpu_vram and gpu_gtt keys (KiB) per process."""
    if pidmaps_f is None:
        pidmaps_f = pidmaps_rollup if _g.proc.use_smaps_rollup() else pidmaps
    base = processtotals(pids, allowed_cpu_count, pidmaps_f)
    with Pool(processes=allowed_cpu_count) as pool:
        gpu_results = pool.map(pid_gpu_memory, list(base.keys()))
    for pid, gpu in zip(list(base.keys()), gpu_results):
        base[pid]["gpu_vram"] = sum(v.get("vram", 0) for v in gpu.values())
        base[pid]["gpu_gtt"] = sum(v.get("gtt", 0) for v in gpu.values())
    return base


def gpu_drm_totals():
    """Return AMD VRAM/GTT system-wide totals from sysfs DRM entries.

    Returns a list of dicts, one per card, with keys: card, vram_total,
    vram_used, gtt_total, gtt_used (all in KiB).  Empty list if unavailable.
    """
    results = []
    for card in _g.proc.list_gpu_drm_cards():
        entry = {"card": card}
        for key, filename in (
            ("vram_total", "mem_info_vram_total"),
            ("vram_used",  "mem_info_vram_used"),
            ("gtt_total",  "mem_info_gtt_total"),
            ("gtt_used",   "mem_info_gtt_used"),
            ("vis_vram_total", "mem_info_vis_vram_total"),
            ("vis_vram_used",  "mem_info_vis_vram_used"),
        ):
            raw = _g.proc.read_gpu_drm(card, filename).strip()
            try:
                entry[key] = int(raw) // 1024
            except ValueError:
                pass
        if len(entry) > 1:
            results.append(entry)
    return results


def nvidia_gpu_info():
    """Return NVIDIA GPU metadata from /proc/driver/nvidia/gpus/*/information.

    Returns a list of dicts with keys: pci, model, uuid (strings).
    Empty list if the NVIDIA driver is not loaded or no data is captured.
    """
    results = []
    for pci in _g.proc.list_nvidia_gpus():
        content = _g.proc.read_nvidia_gpu_info(pci)
        if not content:
            continue
        entry = {"pci": pci}
        for line in content.splitlines():
            if line.startswith("Model:"):
                entry["model"] = line.split(":", 1)[1].strip()
            elif line.startswith("GPU UUID:"):
                entry["uuid"] = line.split(":", 1)[1].strip()
        results.append(entry)
    return results


def sortmaps(totals, key):
    l = []
    for pid in totals:
        l.append((totals[pid][key], pid))
    l.sort()
    return [pid for pid, key in l]


def kernelsize() -> int:
    kernelsize = 0
    if not kernelsize and _g.options.kernel:
        try:
            d = os.popen("size %s" % _g.options.kernel).readlines()[1].split()
            if int(d[1]) == 0:  # data part missing, seems like packed file
                # try some heuristic to find gzipped part in kernel image
                packedkernel = open(_g.options.kernel, "rb").read()
                pos = packedkernel.find(b"\x1F\x8B")
                if pos >= 0 and pos < 25000:
                    sys.stderr.write(
                        "Parameter '%s' should be an original uncompressed compiled kernel file.\n"
                        % _g.options.kernel
                    )
                    sys.stderr.write(
                        "Maybe uncompressed kernel can be extracted by the command:\n"
                        "  dd if=%s bs=1 skip=%d | gzip -d >%s.unpacked\n\n"
                        % (_g.options.kernel, pos, _g.options.kernel)
                    )
            else:
                kernelsize = int(int(d[3]) / 1024 + 0.5)
        except:
            pass
    return kernelsize
