"""High-level report functions: showpids, showmaps, showdiff, showseries, etc."""

import csv
import json
import os
import re
import sys

from smem_lib import _globals as _g
from smem_lib.collection import (
    maptotals, pidmaps, pidmaps_rollup, processtotals, processtotals_gpu,
    usertotals, kernelsize, totalmem, gpu_drm_totals, nvidia_gpu_info,
)
from smem_lib.readers import MemData, ProcessData, SwapsData, PsiData
from smem_lib.formatting import (
    showamount, showdelta, widthstr, showtable,
    _emit_html, _emit_markdown,
)
from smem_lib.analysis import (
    _group_by_chromium_role, _mem_thresholds,
    _collect_proc_totals, _collect_map_totals, _collect_system_values,
    _series_label, _collect_series_snapshot,
)


def showchromium(pidmaps_f=pidmaps) -> None:
    p = _g.proc.pids()
    pt = processtotals(p, _g.proc.allowed_cpu_count(), pidmaps_f)
    cmdlines = {pid: _g.proc.pidcmd(pid) for pid in pt}
    groups = _group_by_chromium_role(pt, cmdlines)
    pss_min, rss_min = _mem_thresholds()
    if pss_min or rss_min:
        groups = {k: g for k, g in groups.items()
                  if g['pss'] >= pss_min and g['rss'] >= rss_min}

    fields = dict(
        role=(
            "Role",
            lambda k: groups[k]['label'],
            widthstr("role", _g.options.role_width, 44),
            None,
            "Chromium process role",
        ),
        count=("Count", lambda k: groups[k]['count'], "% 5s", sum, "number of processes"),
        swap=("Swap",  lambda k: groups[k]['swap'],  "% 8a", sum, "swap consumed"),
        uss=("USS",   lambda k: groups[k]['uss'],   "% 8a", sum, "unique set size"),
        rss=("RSS",   lambda k: groups[k]['rss'],   "% 8a", sum, "resident set size"),
        pss=("PSS",   lambda k: groups[k]['pss'],   "% 8a", sum, "proportional set size"),
    )
    columns = _g.options.columns or "role count pss uss rss"
    showtable(list(groups.keys()), fields, columns.split(), _g.options.sort or "pss")


def showpids(pidmaps_f=pidmaps) -> None:
    p = _g.proc.pids()
    if getattr(_g.options, 'gpu', False):
        pt = processtotals_gpu(p, _g.proc.allowed_cpu_count(), pidmaps_f)
    else:
        pt = processtotals(p, _g.proc.allowed_cpu_count(), pidmaps_f)
    pss_min, rss_min = _mem_thresholds()
    if pss_min or rss_min:
        pt = {k: v for k, v in pt.items()
              if v['pss'] >= pss_min and v['rss'] >= rss_min}

    def showuser(p):
        if _g.options.numeric:
            return _g.proc.piduser(p)
        return _g.proc.pidusername(p)

    fields = dict(
        pid=("PID", lambda n: n, "% 6s", lambda x: len(pt), "process ID"),
        user=(
            "User",
            showuser,
            widthstr("user", _g.options.user_width, 8),
            lambda x: len(dict.fromkeys(x)),
            "owner of process",
        ),
        command=(
            "Command",
            _g.proc.pidcmd,
            widthstr("command", _g.options.cmd_width, 27),
            None,
            "process command line",
        ),
        maps=("Maps", lambda n: pt[n]["maps"], "% 5s", sum, "total number of mappings"),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swap space consumed (ignoring sharing)",
        ),
        uss=("USS", lambda n: pt[n]["uss"], "% 8a", sum, "unique set size"),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["size"],
            "% 8a",
            sum,
            "virtual set size (total virtual memory mapped)",
        ),
        vmpeak=(
            "VmPeak",
            lambda n: _g.proc.pidvmpeak(n),
            "% 8a",
            None,
            "peak resident set size (from /proc/[pid]/status)",
        ),
        cgroup=(
            "CGroup",
            lambda n: _g.proc.pidcgroup(n),
            widthstr("cgroup", _g.options.cgroup_width, 24),
            None,
            "primary cgroup path (from /proc/[pid]/cgroup)",
        ),
        gpu_vram=(
            "GPU VRAM",
            lambda n: pt[n].get("gpu_vram", 0),
            "% 9a",
            sum,
            "GPU VRAM allocated (via DRM fdinfo, requires kernel 5.10+)",
        ),
        gpu_gtt=(
            "GPU GTT",
            lambda n: pt[n].get("gpu_gtt", 0),
            "% 9a",
            sum,
            "GPU GTT (system RAM mapped to GPU) allocated (via DRM fdinfo)",
        ),
    )
    columns = _g.options.columns or "pid user command swap uss pss rss"
    showtable(list(pt.keys()), fields, columns.split(), _g.options.sort or "pss")


def showmaps(is_aggregate=False) -> None:
    p = _g.proc.pids()
    pt = maptotals(p, _g.proc.allowed_cpu_count(), is_aggregate)
    pss_min, rss_min = _mem_thresholds()
    if pss_min or rss_min:
        pt = {k: v for k, v in pt.items()
              if v['pss'] >= pss_min and v['rss'] >= rss_min}

    fields = dict(
        map=(
            "Map",
            lambda n: n,
            widthstr("map", _g.options.mapping_width, 40),
            len,
            "mapping name",
        ),
        count=(
            "Count",
            lambda n: pt[n]["count"],
            "% 5s",
            sum,
            "number of mappings found",
        ),
        pids=(
            "PIDs count",
            lambda n: pt[n]["pids"],
            "% 5s",
            sum,
            "number of PIDs using mapping",
        ),
        pids_list=(
            "PIDs list",
            lambda n: pt[n]["pids_list"],
            widthstr("pids_list", _g.options.pids_width, 40),
            len,
            "list of pids",
        ),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swap space consumed (ignoring sharing)",
        ),
        uss=(
            "USS",
            lambda n: pt[n]["private_clean"] + pt[n]["private_dirty"],
            "% 8a",
            sum,
            "unique set size",
        ),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["size"],
            "% 8a",
            sum,
            "virtual set size (total virtual address space mapped)",
        ),
        avgpss=(
            "AVGPSS",
            lambda n: int(1.0 * pt[n]["pss"] / pt[n]["pids"]),
            "% 8a",
            sum,
            "average PSS per PID",
        ),
        avguss=(
            "AVGUSS",
            lambda n: int(
                1.0 * (pt[n]["private_clean"] + pt[n]["private_dirty"]) / pt[n]["pids"]
            ),
            "% 8a",
            sum,
            "average USS per PID",
        ),
        avgrss=(
            "AVGRSS",
            lambda n: int(1.0 * pt[n]["rss"] / pt[n]["pids"]),
            "% 8a",
            sum,
            "average RSS per PID",
        ),
        shared_exec=(
            "Shared exec",
            lambda n: pt[n]["shared_exec"],
            "% 11a",
            sum,
            "RSS in shared executable mappings (code)",
        ),
        shared_data=(
            "Shared data",
            lambda n: pt[n]["shared_data"],
            "% 11a",
            sum,
            "RSS in shared non-executable mappings (shared data/mmap)",
        ),
        priv_ro=(
            "Priv r/o",
            lambda n: pt[n]["priv_ro"],
            "% 8a",
            sum,
            "RSS in private read-only mappings (constants, rodata)",
        ),
        priv_rw=(
            "Priv r/w",
            lambda n: pt[n]["priv_rw"],
            "% 8a",
            sum,
            "RSS in private read-write mappings (relocations, data, stack, heap)",
        ),
    )
    columns = _g.options.columns or "map pids avgpss pss"
    showtable(list(pt.keys()), fields, columns.split(), _g.options.sort or "pss")


def showusers(pidmaps_f=pidmaps) -> None:
    p = _g.proc.pids()
    pt = usertotals(p, _g.proc.allowed_cpu_count(), pidmaps_f=pidmaps_f)
    pss_min, rss_min = _mem_thresholds()
    if pss_min or rss_min:
        pt = {k: v for k, v in pt.items()
              if v['pss'] >= pss_min and v['rss'] >= rss_min}

    def showuser(u):
        if _g.options.numeric:
            return u
        return _g.proc.username(u)

    fields = dict(
        user=(
            "User",
            showuser,
            widthstr("user", _g.options.user_width, 8),
            None,
            "user name or ID",
        ),
        count=("Count", lambda n: pt[n]["count"], "% 5s", sum, "number of processes"),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swapspace consumed (ignoring sharing)",
        ),
        uss=(
            "USS",
            lambda n: pt[n]["private_clean"] + pt[n]["private_dirty"],
            "% 8a",
            sum,
            "unique set size",
        ),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "virtual set size (total virtual memory mapped)",
        ),
    )
    columns = _g.options.columns or "user count swap uss pss rss"
    showtable(list(pt.keys()), fields, columns.split(), _g.options.sort or "pss")


def showgpu() -> None:
    """Show system-wide GPU memory info: AMD VRAM totals and NVIDIA metadata."""
    drm = gpu_drm_totals()
    nvidia = nvidia_gpu_info()

    if not drm and not nvidia:
        print("No GPU memory information available.")
        print("(AMD VRAM requires amdgpu driver; NVIDIA requires proprietary driver.)")
        return

    if drm:
        mt = totalmem()
        fields = dict(
            card=("Card", lambda n: drm[n]["card"], "%-10s", None, "DRM card name"),
            vram_total=("VRAM Total", lambda n: drm[n].get("vram_total", 0), "%10a", sum, "total VRAM"),
            vram_used=("VRAM Used",  lambda n: drm[n].get("vram_used",  0), "%10a", sum, "used VRAM"),
            gtt_total=("GTT Total",  lambda n: drm[n].get("gtt_total",  0), "%10a", sum, "total GTT"),
            gtt_used=("GTT Used",   lambda n: drm[n].get("gtt_used",   0), "%10a", sum, "used GTT"),
        )
        columns = _g.options.columns or "card vram_total vram_used gtt_total gtt_used"
        showtable(list(range(len(drm))), fields, columns.split(), _g.options.sort or "card")

    if nvidia:
        if drm:
            print("")
        print("%-16s  %-44s  %s" % ("PCI address", "Model", "UUID"))
        for g in nvidia:
            print("%-16s  %-44s  %s" % (
                g.get("pci", ""), g.get("model", "unknown")[:44], g.get("uuid", ""),
            ))


def showsystem() -> None:
    t = totalmem()
    ki = kernelsize()
    m = MemData()

    mt = m("memtotal")
    f = m("memfree")

    fh = max(t - mt - ki, 0)
    u = m("anonpages") + m("mapped")
    kd = mt - f - u
    kdc = m("buffers") + m("sreclaimable") + (m("cached") - m("mapped"))

    l = [
        ("firmware/hardware", fh, 0),
        ("kernel image", ki, 0),
        ("kernel dynamic memory", kd, kdc),
        ("userspace memory", u, m("mapped")),
        ("free memory", f, f),
    ]

    fields = dict(
        order=("Order", lambda n: n, "% 1s", lambda x: "", "hierarchical order"),
        area=("Area", lambda n: l[n][0], "%-24s", lambda x: "", "memory area"),
        used=("Used", lambda n: l[n][1], "%10a", sum, "area in use"),
        cache=(
            "Cache",
            lambda n: l[n][2],
            "%10a",
            sum,
            "area used as reclaimable cache",
        ),
        noncache=(
            "Noncache",
            lambda n: l[n][1] - l[n][2],
            "%10a",
            sum,
            "area not reclaimable",
        ),
    )

    columns = _g.options.columns or "area used cache noncache"
    showtable(list(range(len(l))), fields, columns.split(), _g.options.sort or "order")

    sw = SwapsData()
    if sw.available():
        print("")
        print("%-36s %10s %10s" % ("Swap device", "Size", "Used"))
        for s in sw.swaps:
            print("%-36s %10s %10s" % (
                s['filename'][:36],
                showamount(s['size'], s['size']),
                showamount(s['used'], s['size']),
            ))

    psi = PsiData()
    if psi.available():
        print("")
        print("Memory pressure (PSI):  some avg10=%.2f%%  full avg10=%.2f%%" % (
            psi.get('some', 'avg10'), psi.get('full', 'avg10')))


def showseries():
    def _sort_key(p):
        m = re.search(r'\d+', os.path.basename(p))
        return int(m.group()) if m else float('inf')

    sources = sorted(_g.options.series, key=_sort_key)
    col_keys = ['t%d' % i for i in range(len(sources))]
    raw_headers = [_series_label(src) for src in sources]
    seen_h = {}
    col_headers = []
    for h in raw_headers:
        if h in seen_h:
            seen_h[h] += 1
            col_headers.append('%s_%d' % (h, seen_h[h]))
        else:
            seen_h[h] = 0
            col_headers.append(h)

    snapshots = []
    display_names = {}
    for src, col_key in zip(sources, col_keys):
        pss, names = _collect_series_snapshot(src)
        snapshots.append(pss)
        display_names.update(names)

    if not snapshots:
        return

    all_keys = []
    seen_keys = set()
    for snap in snapshots:
        for k in snap:
            if k not in seen_keys:
                all_keys.append(k)
                seen_keys.add(k)

    pss_min, _ = _mem_thresholds()
    rows = []
    for key in all_keys:
        vals = [snap.get(key, 0) for snap in snapshots]
        if pss_min and max(vals) < pss_min:
            continue
        delta = vals[-1] - vals[0] if len(vals) > 1 else 0
        row = {'key': key, 'name': display_names.get(key, key), 'delta_pss': delta}
        for ck, v in zip(col_keys, vals):
            row[ck] = v
        rows.append(row)

    sort_key = _g.options.sort or 'delta_pss'
    if sort_key == 'delta_pss':
        rows.sort(key=lambda r: abs(r['delta_pss']), reverse=not _g.options.reverse)
    else:
        rows.sort(key=lambda r: r.get(sort_key, 0), reverse=bool(_g.options.reverse))

    if _g.options.output == 'json':
        out = []
        for r in rows:
            entry = {'name': r['name']}
            for ck, ch in zip(col_keys, col_headers):
                entry[ch] = r[ck]
            entry['delta_pss'] = r['delta_pss']
            out.append(entry)
        print(json.dumps(out, indent=2))
        return

    if _g.options.output == 'csv':
        writer = csv.writer(sys.stdout)
        if not _g.options.no_header:
            writer.writerow(['name'] + col_headers + ['delta_pss'])
        for r in rows:
            writer.writerow([r['name']] + [r[ck] for ck in col_keys] + [r['delta_pss']])
        return

    mt = totalmem()

    if _g.options.output == 'html':
        all_col_hdrs = (
            ['Role' if _g.options.chromium else ('Map' if (_g.options.mappings or _g.options.aggregates) else 'Command')]
            + col_headers + ['\u0394PSS'])
        display_rows, raw_rows = [], []
        for r in rows:
            d_row = [r['name']]
            rv_row = [r['name']]
            for ck in col_keys:
                d_row.append(str(showamount(r[ck], mt)))
                rv_row.append(r[ck])
            d_row.append(showdelta(r['delta_pss'], mt))
            rv_row.append(r['delta_pss'])
            display_rows.append(d_row)
            raw_rows.append(rv_row)
        bar_col = len(col_keys) if col_keys else None
        _emit_html('smem series', all_col_hdrs, display_rows, raw_rows, bar_col)
        return

    if _g.options.output == 'markdown':
        name_hdr = ('Role' if _g.options.chromium
                    else ('Map' if (_g.options.mappings or _g.options.aggregates) else 'Command'))
        if _g.options.chromium:
            name_w = _g.options.role_width if _g.options.role_width > 0 else 44
        elif _g.options.mappings or _g.options.aggregates:
            name_w = _g.options.mapping_width if _g.options.mapping_width > 0 else 40
        else:
            name_w = _g.options.cmd_width if _g.options.cmd_width > 0 else 27
        all_col_hdrs = [name_hdr] + col_headers + ['\u0394PSS']
        display_rows = []
        for r in rows:
            d_row = [r['name'][:name_w]]
            for ck in col_keys:
                d_row.append(str(showamount(r[ck], mt)))
            d_row.append(showdelta(r['delta_pss'], mt))
            display_rows.append(d_row)
        alignments = ['l'] + ['r'] * (len(col_keys) + 1)
        _emit_markdown(all_col_hdrs, display_rows, alignments)
        return

    if _g.options.chromium:
        name_hdr = 'Role'
        name_default = _g.options.role_width if _g.options.role_width > 0 else 44
    elif _g.options.mappings or _g.options.aggregates:
        name_hdr = 'Map'
        name_default = _g.options.mapping_width if _g.options.mapping_width > 0 else 40
    else:
        name_hdr = 'Command'
        name_default = _g.options.cmd_width if _g.options.cmd_width > 0 else 27

    if _g.options.autosize:
        name_w = max([len(r['name']) for r in rows] + [len(name_hdr)], default=name_default)
        other_w = len(col_keys) * 9 + 10
        try:
            _, tty_w = os.popen("stty size", "r").read().split()
            tty_w = int(tty_w)
        except Exception:
            tty_w = 80
        name_w = min(name_w, max(10, tty_w - other_w))
    else:
        name_w = name_default

    name_fmt = '%%-%d.%ds' % (name_w, name_w)

    if not _g.options.no_header:
        parts = [name_fmt % name_hdr]
        for ch in col_headers:
            parts.append('%8.8s' % ch)
        parts.append('%9.9s' % 'DPSS')
        print(' '.join(parts))

    for r in rows:
        parts = [name_fmt % r['name']]
        for ck in col_keys:
            parts.append('%8s' % showamount(r[ck], mt))
        parts.append('%9s' % showdelta(r['delta_pss'], mt))
        print(' '.join(parts))


def showdiff():
    source_a, source_b = _g.options.diff

    if _g.options.mappings or _g.options.aggregates:
        data_a = _collect_map_totals(source_a, _g.options.aggregates)
        data_b = _collect_map_totals(source_b, _g.options.aggregates)
        all_keys = set(data_a) | set(data_b)
        rows = []
        for name in all_keys:
            a = data_a.get(name, {})
            b = data_b.get(name, {})
            uss_a = a.get('private_clean', 0) + a.get('private_dirty', 0)
            uss_b = b.get('private_clean', 0) + b.get('private_dirty', 0)
            status = ' ' if name in data_a and name in data_b else ('+' if name in data_b else '-')
            rows.append(dict(
                status=status, map=name,
                pss_a=a.get('pss', 0), pss_b=b.get('pss', 0),
                delta_pss=b.get('pss', 0) - a.get('pss', 0),
                uss_a=uss_a, uss_b=uss_b, delta_uss=uss_b - uss_a,
                rss_a=a.get('rss', 0), rss_b=b.get('rss', 0),
                delta_rss=b.get('rss', 0) - a.get('rss', 0),
                swap_a=a.get('swap', 0), swap_b=b.get('swap', 0),
                delta_swap=b.get('swap', 0) - a.get('swap', 0),
            ))
        default_columns = 'status map pss_a pss_b delta_pss'

    elif _g.options.system:
        sys_a = {area: (used, cache) for area, used, cache in _collect_system_values(source_a)}
        sys_b = {area: (used, cache) for area, used, cache in _collect_system_values(source_b)}
        order = [area for area, _, _ in _collect_system_values(source_a)]
        rows = []
        for area in order:
            a_used, a_cache = sys_a[area]
            b_used, b_cache = sys_b.get(area, (0, 0))
            rows.append(dict(
                area=area,
                used_a=a_used, used_b=b_used, delta_used=b_used - a_used,
                cache_a=a_cache, cache_b=b_cache, delta_cache=b_cache - a_cache,
                noncache_a=a_used - a_cache, noncache_b=b_used - b_cache,
                delta_noncache=(b_used - b_cache) - (a_used - a_cache),
            ))
        default_columns = 'area used_a used_b delta_used'

    elif _g.options.chromium:
        data_a, cmdlines_a = _collect_proc_totals(source_a)
        data_b, cmdlines_b = _collect_proc_totals(source_b)
        groups_a = _group_by_chromium_role(data_a, cmdlines_a)
        groups_b = _group_by_chromium_role(data_b, cmdlines_b)
        rows = []
        for key in set(groups_a) | set(groups_b):
            a = groups_a.get(key, {})
            b = groups_b.get(key, {})
            status = ' ' if key in groups_a and key in groups_b else ('+' if key in groups_b else '-')
            rows.append(dict(
                status=status,
                role=b.get('label') or a.get('label', key),
                count_a=a.get('count', 0), count_b=b.get('count', 0),
                pss_a=a.get('pss', 0), pss_b=b.get('pss', 0),
                delta_pss=b.get('pss', 0) - a.get('pss', 0),
                uss_a=a.get('uss', 0), uss_b=b.get('uss', 0),
                delta_uss=b.get('uss', 0) - a.get('uss', 0),
                rss_a=a.get('rss', 0), rss_b=b.get('rss', 0),
                delta_rss=b.get('rss', 0) - a.get('rss', 0),
                swap_a=a.get('swap', 0), swap_b=b.get('swap', 0),
                delta_swap=b.get('swap', 0) - a.get('swap', 0),
            ))
        default_columns = 'status role count_a count_b pss_a pss_b delta_pss'

    else:
        data_a, cmdlines_a = _collect_proc_totals(source_a)
        data_b, cmdlines_b = _collect_proc_totals(source_b)
        rows = []
        for pid in set(data_a) | set(data_b):
            cmd_a = cmdlines_a.get(pid, '')
            cmd_b = cmdlines_b.get(pid, '')
            in_a, in_b = pid in data_a, pid in data_b
            if in_a and in_b and cmd_a != cmd_b:
                a = data_a[pid]
                rows.append(dict(status='-', pid=pid, command=cmd_a,
                                 pss_a=a['pss'], pss_b=0, delta_pss=-a['pss'],
                                 uss_a=a['uss'], uss_b=0, delta_uss=-a['uss'],
                                 rss_a=a['rss'], rss_b=0, delta_rss=-a['rss'],
                                 swap_a=a['swap'], swap_b=0, delta_swap=-a['swap']))
                b = data_b[pid]
                rows.append(dict(status='+', pid=pid, command=cmd_b,
                                 pss_a=0, pss_b=b['pss'], delta_pss=b['pss'],
                                 uss_a=0, uss_b=b['uss'], delta_uss=b['uss'],
                                 rss_a=0, rss_b=b['rss'], delta_rss=b['rss'],
                                 swap_a=0, swap_b=b['swap'], delta_swap=b['swap']))
                continue
            a = data_a.get(pid, {})
            b = data_b.get(pid, {})
            status = ' ' if in_a and in_b else ('+' if in_b else '-')
            rows.append(dict(
                status=status, pid=pid, command=cmd_b if in_b else cmd_a,
                pss_a=a.get('pss', 0), pss_b=b.get('pss', 0),
                delta_pss=b.get('pss', 0) - a.get('pss', 0),
                uss_a=a.get('uss', 0), uss_b=b.get('uss', 0),
                delta_uss=b.get('uss', 0) - a.get('uss', 0),
                rss_a=a.get('rss', 0), rss_b=b.get('rss', 0),
                delta_rss=b.get('rss', 0) - a.get('rss', 0),
                swap_a=a.get('swap', 0), swap_b=b.get('swap', 0),
                delta_swap=b.get('swap', 0) - a.get('swap', 0),
            ))
        default_columns = 'status pid command pss_a pss_b delta_pss'

    pss_min, rss_min = _mem_thresholds()
    if (pss_min or rss_min) and not _g.options.system:
        rows = [r for r in rows
                if max(r.get('pss_a', 0), r.get('pss_b', 0)) >= pss_min
                and max(r.get('rss_a', 0), r.get('rss_b', 0)) >= rss_min]

    sort_key = _g.options.sort or 'delta_pss' if not _g.options.system else 'area'
    if sort_key in ('delta_pss', 'delta_uss', 'delta_rss', 'delta_swap',
                    'delta_used', 'delta_cache', 'delta_noncache'):
        rows.sort(key=lambda r: abs(r[sort_key]), reverse=not _g.options.reverse)
    else:
        rows.sort(key=lambda r: r.get(sort_key, 0), reverse=bool(_g.options.reverse))

    columns = (_g.options.columns or default_columns).split()

    mt = totalmem()
    st = MemData()("swaptotal")

    MEM_COLS  = {'pss_a', 'pss_b', 'uss_a', 'uss_b', 'rss_a', 'rss_b',
                 'used_a', 'used_b', 'cache_a', 'cache_b', 'noncache_a', 'noncache_b'}
    SWAP_COLS = {'swap_a', 'swap_b'}
    DELTA_MEM = {'delta_pss', 'delta_uss', 'delta_rss',
                 'delta_used', 'delta_cache', 'delta_noncache'}
    DELTA_SWP = {'delta_swap'}

    HEADERS = {
        'status': '', 'pid': 'PID', 'command': 'Command', 'map': 'Map', 'area': 'Area',
        'role': 'Role', 'count_a': 'CNT_A', 'count_b': 'CNT_B',
        'pss_a': 'PSS_A', 'pss_b': 'PSS_B', 'delta_pss': '\u0394PSS',
        'uss_a': 'USS_A', 'uss_b': 'USS_B', 'delta_uss': '\u0394USS',
        'rss_a': 'RSS_A', 'rss_b': 'RSS_B', 'delta_rss': '\u0394RSS',
        'swap_a': 'SWAP_A', 'swap_b': 'SWAP_B', 'delta_swap': '\u0394SWAP',
        'used_a': 'USED_A', 'used_b': 'USED_B', 'delta_used': '\u0394USED',
        'cache_a': 'CACHE_A', 'cache_b': 'CACHE_B', 'delta_cache': '\u0394CACHE',
        'noncache_a': 'NCACHE_A', 'noncache_b': 'NCACHE_B', 'delta_noncache': '\u0394NCACHE',
    }

    if _g.options.output == 'json':
        print(json.dumps(rows, indent=2))
        return

    if _g.options.output == 'csv':
        writer = csv.writer(sys.stdout)
        if not _g.options.no_header:
            writer.writerow(columns)
        for row in rows:
            writer.writerow([row[c] for c in columns])
        return

    if _g.options.output == 'html':
        col_hdrs = [HEADERS.get(c, c) for c in columns]
        display_rows, raw_rows = [], []
        for row in rows:
            d_row, r_row = [], []
            for c in columns:
                v = row[c]
                r_row.append(v)
                if c in MEM_COLS:
                    d_row.append(str(showamount(v, mt)))
                elif c in SWAP_COLS:
                    d_row.append(str(showamount(v, st)))
                elif c in DELTA_MEM:
                    d_row.append(showdelta(v, mt))
                elif c in DELTA_SWP:
                    d_row.append(showdelta(v, st))
                else:
                    d_row.append(str(v))
            display_rows.append(d_row)
            raw_rows.append(r_row)
        bar_col = next((i for i, c in enumerate(columns) if c == 'pss_b'), None)
        _emit_html('smem diff', col_hdrs, display_rows, raw_rows, bar_col)
        return

    if _g.options.output == 'markdown':
        col_hdrs = [HEADERS.get(c, c) for c in columns]
        TEXT_COLS = {'status', 'command', 'map', 'area', 'role', 'pid', 'count_a', 'count_b'}
        cmd_w  = _g.options.cmd_width     if _g.options.cmd_width     > 0 else 27
        map_w  = _g.options.mapping_width if _g.options.mapping_width > 0 else 40
        role_w = _g.options.role_width    if _g.options.role_width    > 0 else 44
        display_rows = []
        for row in rows:
            d_row = []
            for c in columns:
                v = row[c]
                if c in MEM_COLS:
                    d_row.append(str(showamount(v, mt)))
                elif c in SWAP_COLS:
                    d_row.append(str(showamount(v, st)))
                elif c in DELTA_MEM:
                    d_row.append(showdelta(v, mt))
                elif c in DELTA_SWP:
                    d_row.append(showdelta(v, st))
                elif c == 'command':
                    d_row.append(str(v)[:cmd_w])
                elif c == 'map':
                    d_row.append(str(v)[:map_w])
                elif c == 'role':
                    d_row.append(str(v)[:role_w])
                else:
                    d_row.append(str(v))
            display_rows.append(d_row)
        alignments = ['l' if c in TEXT_COLS else 'r' for c in columns]
        _emit_markdown(col_hdrs, display_rows, alignments)
        return

    # Text table
    cmd_w  = _g.options.cmd_width     if _g.options.cmd_width     > 0 else 27
    map_w  = _g.options.mapping_width if _g.options.mapping_width > 0 else 40
    role_w = _g.options.role_width    if _g.options.role_width    > 0 else 44

    TEXT_OVERFLOW = ('command', 'map', 'role')
    FIXED_W = {'status': 1, 'pid': 6, 'count_a': 5, 'count_b': 5, 'area': 24}
    text_w = {}
    for c in columns:
        if c not in TEXT_OVERFLOW:
            continue
        default = cmd_w if c == 'command' else (role_w if c == 'role' else map_w)
        if _g.options.autosize:
            sizes = [len(HEADERS.get(c, c))]
            for row in rows:
                sizes.append(len(str(row.get(c, ''))))
            text_w[c] = max(sizes)
        else:
            text_w[c] = default
    if _g.options.autosize:
        overflow_cols = [c for c in columns if c in TEXT_OVERFLOW]
        if overflow_cols:
            oc = overflow_cols[0]
            other_w = sum(
                FIXED_W.get(c, 9 if c in DELTA_MEM | DELTA_SWP else 8)
                for c in columns if c != oc and c not in TEXT_OVERFLOW
            ) + sum(text_w[c] for c in columns if c in TEXT_OVERFLOW and c != oc)
            other_w += len(columns) - 1
            try:
                _, tty_w = os.popen("stty size", "r").read().split()
                tty_w = int(tty_w)
            except Exception:
                tty_w = 80
            text_w[oc] = min(text_w[oc], max(10, tty_w - other_w))

    col_fmt = []
    col_fn  = []
    for c in columns:
        if c == 'status':
            col_fmt.append('%-1s');  col_fn.append(lambda v: v)
        elif c == 'pid':
            col_fmt.append('%6s');   col_fn.append(lambda v: v)
        elif c == 'command':
            w = text_w.get(c, cmd_w)
            col_fmt.append('%%-%d.%ds' % (w, w))
            col_fn.append(lambda v: v)
        elif c == 'map':
            w = text_w.get(c, map_w)
            col_fmt.append('%%-%d.%ds' % (w, w))
            col_fn.append(lambda v: v)
        elif c == 'area':
            col_fmt.append('%-24s');  col_fn.append(lambda v: v)
        elif c == 'role':
            w = text_w.get(c, role_w)
            col_fmt.append('%%-%d.%ds' % (w, w))
            col_fn.append(lambda v: v)
        elif c in ('count_a', 'count_b'):
            col_fmt.append('%5s');    col_fn.append(lambda v: v)
        elif c in MEM_COLS:
            col_fmt.append('%8s')
            col_fn.append(lambda v, t=mt: showamount(v, t))
        elif c in SWAP_COLS:
            col_fmt.append('%8s')
            col_fn.append(lambda v, t=st: showamount(v, t))
        elif c in DELTA_MEM:
            col_fmt.append('%9s')
            col_fn.append(lambda v, t=mt: showdelta(v, t))
        elif c in DELTA_SWP:
            col_fmt.append('%9s')
            col_fn.append(lambda v, t=st: showdelta(v, t))
        else:
            col_fmt.append('%8s');   col_fn.append(lambda v: v)

    fmt = ' '.join(col_fmt)
    if not _g.options.no_header:
        print(fmt % tuple(HEADERS.get(c, c) for c in columns))
    for row in rows:
        print(fmt % tuple(fn(row[c]) for fn, c in zip(col_fn, columns)))
