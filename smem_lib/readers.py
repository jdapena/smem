"""Data source abstraction: live /proc and tarfile backends."""

import os
import pwd
import re
import tarfile
from io import TextIOWrapper
from multiprocessing import cpu_count
from typing import List, Union

from smem_lib import _globals as _g


class UIDCache(object):
    """Class for a simple ID Cache"""

    def __init__(self) -> None:
        self._cache = {}

    def __call__(self, uid):
        """Return if the entry is in cache, else populate the cache"""
        return self._cache.setdefault(uid, self._getpwuid(uid))

    @staticmethod
    def _getpwuid(uid: int) -> Union[int, str]:
        """Return the password database entry for the UID otherwise store just the UID"""
        try:
            return pwd.getpwuid(uid)[0]
        except KeyError:
            return str(uid)


class ProcReader(object):
    def __init(self) -> None:
        pass

    def listpids(self) -> List[str]:
        return []

    def piduser(self, pid):
        return -1

    def read(self, filename) -> str:
        """Return the file as a string"""
        return ""

    def username(self, uid):
        return "?" if uid == -1 else "%d" % uid

    def use_smaps_rollup(self):
        return False

    def allowed_cpu_count(self):
        return 1


class ProcFSReader(ProcReader):
    def __init__(self) -> None:
        self._uidcache = UIDCache()

    def listpids(self) -> List[str]:
        for e in os.listdir("/proc"):
            if e.isdigit():
                yield e

    def piduser(self, pid):
        """Return PID user data"""
        try:
            return os.stat("/proc/%d" % pid).st_uid
        except:
            return -1

    def read(self, filename) -> str:
        """Return the file as a string"""
        return open("/proc/" + filename).read()

    def username(self, uid):
        """Return username from UID cache"""
        return "?" if uid == -1 else self._uidcache(uid)

    def use_smaps_rollup(self):
        return os.access("/proc/%s/smaps_rollup" % os.getpid(), os.R_OK)

    def allowed_cpu_count(self):
        return cpu_count()


class TarfileReader(ProcReader):
    def __init__(self, filename) -> None:
        self._filename = filename
        self._tar = tarfile.open(filename)

    def listpids(self) -> List[str]:
        for tarinfo in self._tar:
            if tarinfo.name.endswith('/smaps'):
                yield tarinfo.name.split('/')[-2]

    def piduser(self, pid):
        try:
            return self._tar.getmember("%d" % pid).uid
        except KeyError:
            return -1

    def read(self, filename) -> str:
        """Return the file as a string"""
        try:
            f = self._tar.extractfile(filename)
            return TextIOWrapper(f).read() if f is not None else ''
        except KeyError:
            return ''

    def use_smaps_rollup(self):
        return any(m.name.endswith('/smaps_rollup') for m in self._tar.getmembers())


class Proc(object):
    """Helper class to handle /proc/ filesystem data"""

    def __init__(self) -> None:
        self._reader = _g.options.source and TarfileReader(_g.options.source) or ProcFSReader()

    def listpids(self) -> List[str]:
        return self._reader.listpids()

    def read(self, filename) -> str:
        """Return the file as a string"""
        return self._reader.read(filename)

    def readlines(self, filename):
        """Return the file as a list of lines"""
        return self.read(filename).splitlines(True)

    def piduser(self, pid):
        return self._reader.piduser(pid)

    def username(self, uid):
        return self._reader.username(uid)

    def version(self):
        """Return Linux version data"""
        return self.readlines("version")[0]

    def use_smaps_rollup(self):
        return self._reader.use_smaps_rollup()

    def allowed_cpu_count(self):
        return self._reader.allowed_cpu_count()


class MemData(Proc):
    """Class accessing and storing /proc/meminfo data"""

    def __init__(self) -> None:
        super().__init__()
        self._memdata = {}

        regex = re.compile("(?P<name>\\S+):\\s+(?P<amount>\\d+) kB")
        for line in self.readlines("meminfo"):
            match = regex.match(line)
            if match:
                self._memdata[match.group("name").lower()] = int(match.group("amount"))

    def __call__(self, entry):
        """Return the entry when the object is called"""
        return self._memdata[entry]


class ProcessData(Proc):
    """Helper class to handle /proc/<pid> filesystem data"""

    def __init__(self) -> None:
        super().__init__()

    def _iskernel(self, pid):
        """Check if it's a kernel pid"""
        return self.pidcmd(pid) == ""

    def pids(self) -> List[int]:
        """Get a list of PIDs"""
        return [
            int(e)
            for e in self.listpids()
            if not self._iskernel(e)
            and ((_g.options.pid and _g.options.pid == int(e)) or not _g.options.pid)
        ]

    def mapdata(self, pid):
        """Return PID smaps data"""
        return self.readlines("%s/smaps" % pid)

    def pidcmd(self, pid):
        """Return PID cmdline data"""
        try:
            c = self.read("%s/cmdline" % pid)[:-1]
            return c.replace("\0", " ")
        except:
            return "?"

    def pidusername(self, pid):
        """Return PID username"""
        return self.username(self.piduser(pid))

    def pidcgroup(self, pid):
        """Return the primary cgroup path for a process, empty string if unavailable.

        Prefers the memory controller path (cgroup v1) or the unified hierarchy
        path (cgroup v2), falling back to the first entry found.
        """
        content = self.read('%s/cgroup' % pid)
        first = ''
        for line in content.splitlines():
            parts = line.split(':', 2)
            if len(parts) != 3:
                continue
            if not first:
                first = parts[2]
            if parts[1] == '':        # cgroup v2 unified hierarchy
                return parts[2]
            if parts[1] == 'memory':  # cgroup v1 memory controller
                return parts[2]
        return first

    def pidvmpeak(self, pid):
        """Return VmPeak in KB from /proc/[pid]/status, or 0 if unavailable."""
        content = self.read('%s/status' % pid)
        for line in content.splitlines():
            if line.startswith('VmPeak:'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        pass
        return 0


class SwapsData(Proc):
    """Parses /proc/swaps into a list of active swap device records."""

    def __init__(self) -> None:
        super().__init__()
        self._swaps = []
        for line in self.readlines('swaps')[1:]:  # skip header row
            parts = line.split()
            if len(parts) >= 5:
                try:
                    self._swaps.append(dict(
                        filename=parts[0],
                        type=parts[1],
                        size=int(parts[2]),
                        used=int(parts[3]),
                        priority=int(parts[4]),
                    ))
                except (ValueError, IndexError):
                    pass

    @property
    def swaps(self):
        return self._swaps

    def available(self):
        return bool(self._swaps)


class PsiData(Proc):
    """Parses /proc/pressure/memory (PSI, kernel >= 4.20).

    Provides some/full avg10/avg60/avg300 stall percentages and cumulative
    total stall time in microseconds.
    """

    def __init__(self) -> None:
        super().__init__()
        self._psi = {}
        for line in self.readlines('pressure/memory'):
            parts = line.split()
            if not parts:
                continue
            level = parts[0]  # 'some' or 'full'
            d = {}
            for kv in parts[1:]:
                k, _, v = kv.partition('=')
                try:
                    d[k] = float(v) if '.' in v else int(v)
                except ValueError:
                    pass
            if d:
                self._psi[level] = d

    def available(self):
        return bool(self._psi)

    def get(self, level, key, default=0.0):
        return self._psi.get(level, {}).get(key, default)
