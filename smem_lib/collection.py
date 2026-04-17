"""Raw data collection and computation from /proc or tarfile sources."""

import functools
import os
import re
import sys
from multiprocessing import Pool
from typing import Dict

from smem_lib import _globals as _g
from smem_lib.utils import filters, fromunits
from smem_lib.readers import MemData, ProcessData


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
                    not filters(_g.options.userfilter, pid, _g.proc.pidusername),
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
                    )
                else:
                    t = totals[name]

                for k in t:
                    t[k] += maps[m].get(k, 0)
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
                  not filters(_g.options.userfilter, p, _g.proc.pidusername),
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
                    not filters(_g.options.userfilter, pid, _g.proc.pidusername),
        pids)
    totals = {}
    with Pool(processes=allowed_cpu_count) as pool:
        for p in pool.map(functools.partial(pidtotals, pidmaps_f=pidmaps_f), filtered_pids):
            if p["maps"] != 0:
                totals[p["pid"]] = p

    return totals


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
