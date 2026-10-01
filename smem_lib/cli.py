"""Argument parsing and main entry point."""

import argparse
import errno
import sys

from smem_lib import _globals as _g
from smem_lib.readers import ProcessData
from smem_lib.collection import pidmaps, pidmaps_rollup
from smem_lib.reports import (
    showchromium, showpids, showmaps, showusers, showsystem, showgpu, showseries, showdiff,
)


def parse_arguments(argv=None) -> argparse.Namespace:

    argparser = argparse.ArgumentParser(
        prog="smem",
        description="""
                    smem is a tool that can give numerous reports on memory usage on Linux systems.
                    Unlike existing tools, smem can report proportional set size (PSS), which is a
                    more meaningful representation of the amount of memory used by libraries and
                    applications in a virtual memory system.
                    """,
        epilog="""
               For more information please visit:
               https://github.com/kwkroeger/smem
               """,
    )

    argparser.add_argument(
        "-H", "--no-header", action="store_true", help="Disable header line"
    )

    argparser.add_argument(
        "-c", "--columns", default=None, type=str, help="Columns to show"
    )

    argparser.add_argument(
        "-a",
        "--autosize",
        action="store_true",
        help="Size columns to fit terminal size",
    )

    argparser.add_argument(
        "-R", "--realmem", default=None, type=str, help="Amount of physical RAM"
    )

    argparser.add_argument(
        "-K", "--kernel", default=None, type=str, help="Path to kernel image"
    )

    filter_group = argparser.add_argument_group("Filter")
    filter_group.add_argument(
        "-P", "--processfilter", default=None, type=str, help="Process filter regex"
    )

    filter_group.add_argument(
        "-M", "--mapfilter", default=None, type=str, help="Process map regex"
    )

    filter_group.add_argument(
        "-U", "--userfilter", default=None, type=str, help="Process users regex"
    )

    filter_group.add_argument(
        "-G", "--cgroupfilter", default=None, type=str, help="Process cgroup path regex"
    )

    filter_group.add_argument(
        "--min-pss", default=None, type=str,
        help="Exclude entries with PSS below threshold (e.g. 1M, 500K)",
    )

    filter_group.add_argument(
        "--min-rss", default=None, type=str,
        help="Exclude entries with RSS below threshold (e.g. 1M, 500K)",
    )

    show_group = argparser.add_argument_group("Show")
    show_group.add_argument(
        "-A", "--aggregates", action="store_true", help="Show mapping aggregates"
    )

    show_group.add_argument(
        "-C", "--chromium", action="store_true",
        help="Show Chromium process roles (browser, renderer, gpu-process, etc.)",
    )

    show_group.add_argument(
        "-m", "--mappings", action="store_true", help="Show mappings"
    )

    show_group.add_argument("-u", "--users", action="store_true", help="Show users")

    show_group.add_argument(
        "-w", "--system", action="store_true", help="Show whole system"
    )

    show_group.add_argument(
        "--gpu", action="store_true",
        help="Show GPU memory (adds gpu_vram/gpu_gtt columns; use with -w for GPU totals)",
    )

    show_group.add_argument(
        "-p", "--percent", action="store_true", help="Show percentage"
    )

    show_group.add_argument(
        "-k", "--abbreviate", action="store_true", help="Show unit suffixes"
    )

    show_group.add_argument("-t", "--totals", action="store_true", help="Show totals")

    show_group.add_argument(
        "-o", "--output",
        default="table",
        choices=["table", "json", "csv", "html", "markdown"],
        help="Output format (default: table)",
    )

    sort_group = argparser.add_argument_group("Sort")
    sort_group.add_argument("-n", "--numeric", action="store_true", help="Numeric sort")

    sort_group.add_argument(
        "-s", "--sort", default=None, type=str, help="Field to sort on"
    )

    sort_group.add_argument("-r", "--reverse", action="store_true", help="Reverse sort")

    width_group = argparser.add_argument_group("Width")
    width_group.add_argument(
        "--cmd-width",
        default=-1,
        type=int,
        help="Text width for commands (0=as needed)",
    )

    width_group.add_argument(
        "--name-width",
        default=-1,
        type=int,
        help="Text width for command names (0=as needed)",
    )

    width_group.add_argument(
        "--user-width",
        default=-1,
        type=int,
        help="Text width for user names (0=as needed)",
    )

    width_group.add_argument(
        "--mapping-width",
        default=-1,
        type=int,
        help="Text width for mapping names (0=as needed)",
    )

    width_group.add_argument(
        "--role-width",
        default=-1,
        type=int,
        help="Text width for Chromium role names (0=as needed)",
    )

    width_group.add_argument(
        "--pids-width",
        default=-1,
        type=int,
        help="Text width for PIDS list names (0=as needed)",
    )

    width_group.add_argument(
        "--cgroup-width",
        default=-1,
        type=int,
        help="Text width for cgroup path column (0=as needed)",
    )

    argparser.add_argument(
        "-S", "--source", default=None, type=str, help="/proc data source"
    )

    argparser.add_argument(
        "--diff", nargs=2, metavar=("OLD", "NEW"),
        help="Compare two captures (tarfiles)",
    )

    argparser.add_argument(
        "--series", nargs='+', metavar="TAR",
        help="Show PSS time-series across multiple captures (tarfiles)",
    )

    argparser.add_argument(
        "--pid",
        default=None,
        type=int,
        help="Show just process memory based on one pid",
    )

    return argparser.parse_args()


def main() -> None:
    """Main entry point for smem."""
    _g.options = parse_arguments(sys.argv)
    _g.ignore_autosize = set()
    _g.proc = ProcessData()
    pidmaps_f = pidmaps_rollup if _g.proc.use_smaps_rollup() else pidmaps

    try:
        if _g.options.series:
            showseries()
        elif _g.options.diff:
            showdiff()
        elif _g.options.chromium:
            showchromium(pidmaps_f)
        elif _g.options.mappings:
            showmaps()
        elif _g.options.aggregates:
            showmaps(True)
        elif _g.options.users:
            showusers(pidmaps_f)
        elif _g.options.system:
            showsystem()
            if _g.options.gpu:
                print("")
                showgpu()
        elif _g.options.gpu and not any([
                _g.options.mappings, _g.options.aggregates,
                _g.options.users, _g.options.chromium]):
            showgpu()
            print("")
            showpids(pidmaps_f)
        else:
            showpids(pidmaps_f)
    except IOError as e:
        if e.errno == errno.EPIPE:
            pass
    except KeyboardInterrupt:
        pass
