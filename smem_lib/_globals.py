# Shared mutable globals, initialized by cli.main() before any show* call.
# All modules import this as:  from smem_lib import _globals as _g

options = None          # argparse.Namespace set by main()
proc = None             # ProcessData instance set by main()
ignore_autosize = set() # set of field names excluded from autosize
