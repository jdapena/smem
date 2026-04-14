# smem

smem is a tool for meaningful memory reporting on Linux systems. Unlike existing tools, smem can report **proportional set size (PSS)**, which is a more accurate representation of the memory used by libraries and applications in a virtual memory system.

Because large portions of physical memory are typically shared among multiple applications, the standard measure **RSS** (resident set size) significantly overestimates memory usage. PSS instead measures each application's "fair share" of each shared area to give a realistic measure.

## Features

- Per-process, per-mapping, per-user, and system-wide memory reports
- PSS, USS, RSS, VSS, and swap columns
- Chromium/Electron process role breakdown (`--chromium`)
- Aggregate mapping categories (`--aggregates`): system libraries, heap, JIT code, GPU devices, etc.
- Time-series PSS analysis across multiple captures (`--series`)
- Side-by-side diff between two captures (`--diff`)
- Filter by process name, mapping name, or user
- Multiple output formats: plain table, JSON, CSV, HTML (sortable), Markdown
- Reads live data from `/proc` or from offline smemcap tarfile captures
- Installable as a Python package (`pip install .` / `pipx install .`)

## Requirements

- Linux kernel 2.6.27 or later
- Python 3.6 or later
- No external dependencies

## Installation

**Run directly from the repository:**

```bash
git clone https://github.com/jdapena/smem.git
cd smem
sudo ./smem
```

**Install globally with pipx (recommended):**

```bash
pipx install git+https://github.com/jdapena/smem.git
```

**Install with pip:**

```bash
pip install .
```

## Usage

```bash
# Live system (requires access to /proc)
sudo smem

# From an offline smemcap capture
smem -S capture.tar

# Show aggregated mapping categories
smem -S capture.tar -A

# Show Chromium/WebAppMgr process roles
smem -S capture.tar -C

# Compare two captures
smem --diff before.tar after.tar --min-pss 5M

# PSS time-series across captures, Chromium breakdown
smem --series t1.tar t2.tar t3.tar -C

# Output formats
smem -S capture.tar -o html > report.html
smem -S capture.tar -o markdown
smem -S capture.tar -o json
smem -S capture.tar -o csv

# Common options
smem -k           # human-readable units (K/M/G)
smem -p           # percentages
smem -t           # show totals row
smem -r           # reverse sort
smem -s pss       # sort by field
smem --min-pss 1M # exclude entries below threshold
```

Run `smem --help` for the full option reference.

## Credits

This project is a fork of [kwkroeger/smem](https://github.com/kwkroeger/smem), which is itself a Python 3 port of the original [smem](http://www.selenic.com/smem/).

Changes in this fork:
- Reorganized into a Python package (`smem_lib/`) installable via pip/pipx
- Added `--aggregates` (`-A`) for higher-level mapping category view
- Added `--chromium` (`-C`) for Chromium/Electron process role breakdown
- Added `--series` for PSS time-series analysis across multiple captures
- Added `--diff` for side-by-side comparison of two captures
- Added HTML, Markdown, JSON, and CSV output formats (`--output`)
- Added `--min-pss` / `--min-rss` threshold filters
- Added `--pids` column for mapping reports

## License

GNU General Public License v2 or later. See [LICENSE](LICENSE) for the full text.
