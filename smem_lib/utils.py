"""Pure utility functions with no intra-package dependencies."""

import re
import sys
from typing import Optional


def units(x) -> str:
    s = ""
    if x == 0:
        return "0"
    for s in ("", "K", "M", "G", "T"):
        if x < 1024:
            break
        x /= 1024.0
    return "%.1f%s" % (x, s)


def fromunits(x) -> Optional[int]:
    s = dict(
        k=2**10,
        K=2**10,
        kB=2**10,
        KB=2**10,
        M=2**20,
        MB=2**20,
        G=2**30,
        GB=2**30,
        T=2**40,
        TB=2**40,
    )
    for k, v in list(s.items()):
        if x.endswith(k):
            return int(float(x[: -len(k)]) * v)
    sys.stderr.write("Memory size should be written with units, for example 1024M\n")
    sys.exit(-1)


def filters(opt, arg, *sources) -> bool:
    if not opt:
        return False
    for f in sources:
        if re.search(opt, f(arg)):
            return False
    return True
