"""Output formatting: text tables, HTML, Markdown, and supporting utilities."""

import csv
import json
import os
import re
import sys
from typing import Sized

from smem_lib import _globals as _g
from smem_lib.utils import units
from smem_lib.collection import totalmem
from smem_lib.readers import MemData


def showamount(a, total: float):
    if _g.options.abbreviate:
        return units(a * 1024)
    elif _g.options.percent:
        if total == 0:
            return "N/A"
        return "%.2f%%" % (100.0 * a / total)
    return a


def showdelta(a, total):
    """Format a signed memory delta for display."""
    if a == 0:
        return '0'
    if _g.options.abbreviate:
        return ('+' if a > 0 else '-') + units(abs(a) * 1024)
    elif _g.options.percent:
        return 'N/A' if total == 0 else '%+.2f%%' % (100.0 * a / total)
    return '%+d' % a


def widthstr(field, width, default) -> str:
    if width == 0:
        return "%s"
    if width < 0:
        size = default
    else:
        size = width
        _g.ignore_autosize.add(field)
    return "%-{size}.{size}s".format(size=size)


def autosize(columns: Sized, fields, rows):
    colsizes = {}
    for c in columns:
        if c in _g.ignore_autosize:
            continue
        sizes = [1]

        if not _g.options.no_header:
            sizes.append(len(fields[c][0]))

        if (_g.options.abbreviate or _g.options.percent) and "a" in fields[c][2]:
            sizes.append(7)
        else:
            for r in rows:
                sizes.append(len(str(fields[c][1](r))))

        colsizes[c] = max(sizes)

    overflowcols = (set(["command", "map"]) & set(columns)) - _g.ignore_autosize
    if len(overflowcols) > 0:
        overflowcol = overflowcols.pop()
        totnoflow = sum(colsizes.values()) - colsizes[overflowcol]
        try:
            ttyrows, ttycolumns = os.popen("stty size", "r").read().split()
            ttyrows, ttycolumns = int(ttyrows), int(ttycolumns)
        except:
            ttyrows, ttycolumns = (24, 80)
        maxflowcol = ttycolumns - totnoflow - len(columns)
        maxflowcol = max(maxflowcol, 10)
        colsizes[overflowcol] = min(colsizes[overflowcol], maxflowcol)

    return colsizes


def showfields(fields, f) -> None:
    if type(f) in (list, set):
        print("unknown fields: " + " ".join(f))
    else:
        print("unknown field %s" % f)
    print("known fields:")
    for l in sorted(fields):
        print("%-8s %s" % (l, fields[l][-1]))


_HTML_CSS = """\
body{font-family:monospace;font-size:13px;margin:16px}
h1{font-size:14px;font-weight:bold;margin-bottom:8px}
table{border-collapse:collapse;width:max-content}
th,td{padding:3px 10px;text-align:right;border-bottom:1px solid #ddd;white-space:nowrap}
th:first-child,td:first-child{text-align:left}
th{background:#f0f0f0;cursor:pointer;user-select:none}
th:hover{background:#e0e0e0}
th.asc::after{content:" \u25b2";font-size:10px}
th.desc::after{content:" \u25bc";font-size:10px}
tr:hover td{background:rgba(0,0,0,0.03)}
.bar-cell{position:relative;min-width:60px}
.bar-bg{position:absolute;left:0;top:1px;bottom:1px;background:rgba(70,130,180,0.22);z-index:0;border-radius:2px}
.bar-val{position:relative;z-index:1}
"""

_HTML_JS = """\
(function(){
var ths=document.querySelectorAll('th'),sortCol=-1,sortAsc=true;
ths.forEach(function(th,i){
  th.addEventListener('click',function(){
    var tbody=th.closest('table').querySelector('tbody');
    var rows=Array.from(tbody.querySelectorAll('tr'));
    var asc=(sortCol===i)?!sortAsc:true;
    sortCol=i;sortAsc=asc;
    ths.forEach(function(t){t.className='';});
    th.className=asc?'asc':'desc';
    rows.sort(function(a,b){
      var av=a.querySelectorAll('td')[i].dataset.val||'';
      var bv=b.querySelectorAll('td')[i].dataset.val||'';
      var an=parseFloat(av),bn=parseFloat(bv);
      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    });
    rows.forEach(function(r){tbody.appendChild(r);});
  });
});
})();
"""


def _html_escape(s):
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _emit_html(title, col_headers, display_rows, raw_rows, bar_col=None):
    """Emit a self-contained sortable HTML table to stdout."""
    bar_max = None
    if bar_col is not None and raw_rows:
        try:
            bar_max = max(float(r[bar_col]) for r in raw_rows
                         if r[bar_col] not in ('', None))
        except (ValueError, TypeError):
            bar_max = None
        if not bar_max or bar_max <= 0:
            bar_col = None

    lines = [
        '<!DOCTYPE html><html><head><meta charset="utf-8">',
        '<title>%s</title>' % _html_escape(title),
        '<style>%s</style></head><body>' % _HTML_CSS,
        '<h1>%s</h1><table><thead><tr>' % _html_escape(title),
    ]
    for h in col_headers:
        lines.append('<th>%s</th>' % _html_escape(h))
    lines.append('</tr></thead><tbody>')
    for d_row, r_row in zip(display_rows, raw_rows):
        lines.append('<tr>')
        for j, (d, r) in enumerate(zip(d_row, r_row)):
            dv = _html_escape(d)
            rv = _html_escape(str(r))
            if bar_col is not None and j == bar_col:
                try:
                    pct = min(100.0, 100.0 * float(r) / bar_max)
                except (ValueError, TypeError):
                    pct = 0.0
                lines.append('<td class="bar-cell" data-val="%s">'
                             '<div class="bar-bg" style="width:%.1f%%"></div>'
                             '<span class="bar-val">%s</span></td>' % (rv, pct, dv))
            else:
                lines.append('<td data-val="%s">%s</td>' % (rv, dv))
        lines.append('</tr>')
    lines.append('</tbody></table><script>%s</script></body></html>' % _HTML_JS)
    print('\n'.join(lines))


def _emit_markdown(col_headers, display_rows, alignments):
    """Emit a GFM-compatible markdown table to stdout."""
    widths = [max(len(str(col_headers[i])),
                  max((len(str(r[i])) for r in display_rows), default=0),
                  3)
              for i in range(len(col_headers))]

    def fmt_row(cells):
        parts = []
        for cell, w, align in zip(cells, widths, alignments):
            s = str(cell)
            parts.append(s.ljust(w) if align == 'l' else s.rjust(w))
        return '| ' + ' | '.join(parts) + ' |'

    print(fmt_row(col_headers))
    seps = [(':' + '-' * (w - 1) if a == 'l' else '-' * (w - 1) + ':')
            for w, a in zip(widths, alignments)]
    print('| ' + ' | '.join(seps) + ' |')
    for row in display_rows:
        print(fmt_row(row))


def showtable(rows, fields, columns, sort) -> None:
    if sort not in fields:
        showfields(fields, sort)
        sys.exit(-1)

    missing = set(columns) - set(fields)
    if len(missing) > 0:
        showfields(fields, missing)
        sys.exit(-1)

    sorted_rows = sorted(rows, key=lambda n: fields[sort][1](n), reverse=bool(_g.options.reverse))

    if _g.options.output == 'json':
        data = [{c: fields[c][1](n) for c in columns} for n in sorted_rows]
        print(json.dumps(data, indent=2))
        return

    if _g.options.output == 'csv':
        writer = csv.writer(sys.stdout)
        if not _g.options.no_header:
            writer.writerow(columns)
        for n in sorted_rows:
            writer.writerow([fields[c][1](n) for c in columns])
        return

    mt = totalmem()
    memdata = MemData()
    st = memdata("swaptotal")

    if _g.options.output == 'html':
        col_hdrs = [fields[c][0] for c in columns]
        display_rows, raw_rows = [], []
        for n in sorted_rows:
            d_row, r_row = [], []
            for c in columns:
                raw = fields[c][1](n)
                r_row.append(raw)
                fmt = fields[c][2]
                if 'a' in fmt:
                    total = st if c == 'swap' else mt
                    d_row.append(str(showamount(raw, total)))
                else:
                    d_row.append(str(raw))
            display_rows.append(d_row)
            raw_rows.append(r_row)
        bar_col = next((i for i, c in enumerate(columns) if c in ('pss', 'used')), None)
        _emit_html('smem', col_hdrs, display_rows, raw_rows, bar_col)
        return

    if _g.options.output == 'markdown':
        col_hdrs = [fields[c][0] for c in columns]
        display_rows = []
        for n in sorted_rows:
            d_row = []
            for c in columns:
                raw = fields[c][1](n)
                fmt = fields[c][2]
                if 'a' in fmt:
                    total = st if c == 'swap' else mt
                    d_row.append(str(showamount(raw, total)))
                else:
                    try:
                        d_row.append((fmt % raw).strip())
                    except (TypeError, ValueError):
                        d_row.append(str(raw))
            display_rows.append(d_row)
        alignments = ['l' if fields[c][2].startswith('%-') else 'r' for c in columns]
        _emit_markdown(col_hdrs, display_rows, alignments)
        return

    header = ""
    table_format = ""
    formatter = []

    if _g.options.autosize:
        colsizes = autosize(columns, fields, rows)
    else:
        colsizes = {}

    for n in columns:
        f = fields[n][2]
        if "a" in f:
            if n == "swap":
                formatter.append(lambda x: showamount(x, st))
            else:
                formatter.append(lambda x: showamount(x, mt))
            f = f.replace("a", "s")
        else:
            formatter.append(lambda x: x)
        if n in colsizes:
            f = re.sub(r"[0-9]+", str(colsizes[n]), f)
        table_format += f + " "
        header += f % fields[n][0] + " "

    if not _g.options.no_header:
        print(header)

    for n in sorted_rows:
        r = [fields[c][1](n) for c in columns]
        print(table_format % tuple([f(v) for f, v in zip(formatter, r)]))

    if _g.options.totals:
        t = []
        for c in columns:
            f = fields[c][3]
            if f:
                t.append(f([fields[c][1](n) for n in rows]))
            else:
                t.append("")

        print("-" * len(header))
        print(table_format % tuple([f(v) for f, v in zip(formatter, t)]))
