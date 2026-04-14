"""Higher-level analysis: Chromium roles, multi-source collection helpers."""

import os
import re

from smem_lib import _globals as _g
from smem_lib.utils import fromunits
from smem_lib.readers import MemData, ProcessData
from smem_lib.collection import (
    maptotals, pidmaps, pidmaps_rollup, processtotals,
    kernelsize, totalmem,
)


def chromium_role(cmd, chromium_binaries):
    """Return (role_label, group_key) for a Chromium process, or (None, None)."""
    if not cmd:
        return None, None
    binary = cmd.split()[0]
    name = os.path.basename(binary)
    m = re.search(r'--type=(\S+)', cmd)
    if m:
        type_val = m.group(1)
        if type_val == 'renderer':
            am = re.search(r'--app-id=(\S+)', cmd)
            detail = am.group(1) if am else ''
            label = ('%s [renderer] %s' % (name, detail)).rstrip()
            return label, '%s\x00renderer\x00%s' % (name, detail)
        if type_val == 'utility':
            sm = re.search(r'--utility-sub-type=(\S+)', cmd)
            detail = sm.group(1) if sm else ''
            label = ('%s [utility] %s' % (name, detail)).rstrip()
            return label, '%s\x00utility\x00%s' % (name, detail)
        label = '%s [%s]' % (name, type_val)
        return label, '%s\x00%s' % (name, type_val)
    if binary in chromium_binaries:
        return '%s [browser]' % name, '%s\x00browser' % name
    return None, None


def _group_by_chromium_role(pt, cmdlines):
    """Group process totals by Chromium role. Returns {group_key: {...}}."""
    chromium_binaries = {
        cmdlines[pid].split()[0]
        for pid in pt
        if re.search(r'--type=', cmdlines.get(pid, ''))
    }
    groups = {}
    for pid in pt:
        label, key = chromium_role(cmdlines.get(pid, ''), chromium_binaries)
        if key is None:
            continue
        if key not in groups:
            groups[key] = dict(label=label, pss=0, uss=0, rss=0, swap=0, count=0)
        g = groups[key]
        g['pss']   += pt[pid]['pss']
        g['uss']   += pt[pid]['uss']
        g['rss']   += pt[pid]['rss']
        g['swap']  += pt[pid]['swap']
        g['count'] += 1
    return groups


def _mem_thresholds():
    """Return (min_pss_kb, min_rss_kb) from options, 0 if not set."""
    pss = fromunits(_g.options.min_pss) // 1024 if _g.options.min_pss else 0
    rss = fromunits(_g.options.min_rss) // 1024 if _g.options.min_rss else 0
    return pss, rss


def _collect_proc_totals(source):
    _g.options.source = source
    _g.proc = ProcessData()
    pidmaps_f = pidmaps_rollup if _g.proc.use_smaps_rollup() else pidmaps
    pids = _g.proc.pids()
    totals = processtotals(pids, _g.proc.allowed_cpu_count(), pidmaps_f)
    cmdlines = {pid: _g.proc.pidcmd(pid) for pid in totals}
    return totals, cmdlines


def _collect_map_totals(source, is_aggregate=False):
    _g.options.source = source
    _g.proc = ProcessData()
    pids = _g.proc.pids()
    return maptotals(pids, _g.proc.allowed_cpu_count(), is_aggregate)


def _collect_system_values(source):
    _g.options.source = source
    _g.proc = ProcessData()
    m = MemData()
    t = totalmem()
    ki = kernelsize()
    mt = m("memtotal")
    f = m("memfree")
    fh = max(t - mt - ki, 0)
    u = m("anonpages") + m("mapped")
    kd = mt - f - u
    kdc = m("buffers") + m("sreclaimable") + (m("cached") - m("mapped"))
    return [
        ("firmware/hardware", fh, 0),
        ("kernel image", ki, 0),
        ("kernel dynamic memory", kd, kdc),
        ("userspace memory", u, m("mapped")),
        ("free memory", f, f),
    ]


def _series_label(path):
    """Derive a short column header from a tarfile path."""
    name = os.path.basename(path)
    name = re.sub(r'\.(tar\.gz|tar\.bz2|tar\.xz|tar|tgz|tbz2)$', '', name, flags=re.I)
    m = re.search(r'(\d{4}[._-]\d{2}[._-]\d{2}[._T-]\d{2}[._-]\d{2}(?:[._-]\d{2})?)', name)
    if m:
        return m.group(1)
    return name


def _collect_series_snapshot(source):
    """Return ({key: pss_kb}, {key: display_name}) for one capture."""
    if _g.options.chromium:
        totals, cmdlines = _collect_proc_totals(source)
        groups = _group_by_chromium_role(totals, cmdlines)
        return {k: groups[k]['pss'] for k in groups}, {k: groups[k]['label'] for k in groups}
    elif _g.options.mappings or _g.options.aggregates:
        totals = _collect_map_totals(source, _g.options.aggregates)
        return {name: totals[name]['pss'] for name in totals}, {}
    else:
        totals, cmdlines = _collect_proc_totals(source)
        pss = {}
        for pid in totals:
            cmd = cmdlines.get(pid, '?')
            pss[cmd] = pss.get(cmd, 0) + totals[pid]['pss']
        return pss, {}
