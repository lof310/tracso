"""Utilities, ELF parsing, and injection sources"""

import concurrent.futures
import os
import subprocess

from . import logger
from .config import ELF_TIMEOUT

# |------------------------------|
# |======> Logging helpers <=====|
# |------------------------------|

# TODO maybe


def log(opts, *args):
    """Write a decision line to stderr when --verbose is on."""
    if opts is None or getattr(opts, "verbose", False):
        logger.info(" ".join(str(a) for a in args))


# |--------------------------------|
# |======> Printing helpers <======|
# |--------------------------------|

# ====== ANSI COLORS ======

_RESET = "\033[0m"


def _wrap(code, text, on):
    if not on:
        return text
    return f"\033[{code}m{text}{_RESET}"


def _bold(text, on=True):
    return _wrap("1", text, on)


def _dim(text, on=True):
    return _wrap("2", text, on)


def _red(text, on=True):
    return _wrap("31", text, on)


def _green(text, on=True):
    return _wrap("32", text, on)


def _yellow(text, on=True):
    return _wrap("33", text, on)


def _blue(text, on=True):
    return _wrap("34", text, on)


def _magenta(text, on=True):
    return _wrap("35", text, on)


def _cyan(text, on=True):
    return _wrap("36", text, on)


class Palette:
    """ANSI helpers pre-bound to an enabled/disabled flag.

    Usage:
        p = Palette(color_enabled)
        stream.write(f"{p.bold('tracso')} \u00b7 {p.dim('pid:1234')}\\n")
    """

    __slots__ = ("on",)

    def __init__(self, enabled):
        self.on = bool(enabled)

    def bold(self, t):
        return _bold(t, self.on)

    def dim(self, t):
        return _dim(t, self.on)

    def red(self, t):
        return _red(t, self.on)

    def green(self, t):
        return _green(t, self.on)

    def yellow(self, t):
        return _yellow(t, self.on)

    def blue(self, t):
        return _blue(t, self.on)

    def magenta(self, t):
        return _magenta(t, self.on)

    def cyan(self, t):
        return _cyan(t, self.on)


def v_pad(text, width):
    """Right-pad `text` to `width` visible characters.

    Must be called BEFORE adding ANSI codes, otherwise the escape
    sequences count towards the field width and columns misalign.
    """
    if len(text) >= width:
        return text
    return text + " " * (width - len(text))


# ====== Size and Bar formatting ======


def fmt_size(n):
    """Human-readable byte count: B / KB / MB / GB."""
    if n is None:
        return "?"
    n = int(n)
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 ** 3):.2f} GB"


def bar(value, maximum, width=16):
    """Return a width-cell block bar scaled to `maximum`."""
    if maximum <= 0 or width <= 0:
        return " " * width
    filled = int(round(width * value / maximum))
    if filled < 0:
        filled = 0
    if filled > width:
        filled = width
    return "\u2588" * filled + "\u2591" * (width - filled)


# |-----------------------------|
# |======> Name handling <======|
# |-----------------------------|


def strip_so_suffix(name):
    """Remove cpython/abi3 version suffixes from a .so basename."""
    for tag in (".cpython-", ".abi3."):
        i = name.find(tag)
        if i != -1 and (name.endswith(".so") or name.endswith(".pyd")):
            ext = name[name.rfind(".") :]
            return name[:i] + ext
    return name


def py_name(modname, depth):
    """Return a graph node label for a Python module.

    depth == 0 -> full dotted path
    depth  > 0 -> at most `depth` dotted components
    """
    s = str(modname)
    if depth <= 0:
        return "py:" + s
    parts = s.split(".")
    if len(parts) <= depth:
        return "py:" + s
    return "py:" + ".".join(parts[:depth])


# |---------------------------|
# |======> ELF parsing <======|
# |---------------------------|


def bracket(line):
    """Extract the value inside the first [...] of a readelf line."""
    i = line.find("[")
    if i < 0:
        return None
    j = line.find("]", i + 1)
    if j < 0:
        return None
    return line[i + 1 : j]


def elf_dynamic(path, opts):
    """Return {'soname', 'needed', 'rpath'} for an ELF file, memoized per run."""
    cached = opts.elf_cache.get(path)
    if cached is not None:
        return cached

    data = {"soname": os.path.basename(path), "needed": [], "rpath": []}

    try:
        proc = subprocess.run(
            ["readelf", "--wide", "-d", path],
            capture_output=True,
            text=True,
            timeout=ELF_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        opts.elf_cache[path] = data
        return data

    for line in proc.stdout.splitlines():
        if "(NEEDED)" in line:
            val = bracket(line)
            if val:
                data["needed"].append(val)
        elif "(SONAME)" in line:
            val = bracket(line)
            if val:
                data["soname"] = val
        elif "(RUNPATH)" in line or "(RPATH)" in line:
            val = bracket(line)
            if val:
                data["rpath"].extend(p for p in val.split(":") if p)

    opts.elf_cache[path] = data
    return data


def prefetch_elf(paths, opts):
    """Parse ELF headers in parallel to hide subprocess latency."""
    if not paths:
        return
    workers = min(32, (os.cpu_count() or 1) * 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda p: elf_dynamic(p, opts), paths))


def ldconfig_map():
    """Return {soname: path} from ldconfig -p, or {} on failure."""
    try:
        proc = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True,
            text=True,
            timeout=ELF_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}

    out = {}
    for line in proc.stdout.splitlines():
        if " => " not in line:
            continue
        left, right = line.strip().split(" => ", 1)
        soname = left.split("(", 1)[0].strip()
        path = right.strip()
        if soname and path:
            out[soname] = path
    return out


# |----------------------------------|
# |======> Process inspection <======|
# |----------------------------------|


def maps_libs(pid):
    """Return sorted list of .so paths currently mapped by pid."""
    libs = set()
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.rstrip().split(maxsplit=5)
                if len(parts) < 6:
                    continue
                path = parts[5].strip()
                if path.endswith(" (deleted)"):
                    path = path[:-10]
                if (
                    ".so" in path
                    and not path.startswith("[")
                    and not path.startswith("/dev/")
                ):
                    libs.add(path)
    except OSError:
        return []
    return sorted(libs)


def is_python_pid(pid, libs=None):
    """True if the process is Python, PyPy, or embeds libpython."""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""

    name = os.path.basename(exe).lower()
    if (
        name == "python"
        or name.startswith("python3")
        or name.startswith("python2")
        or "pypy" in name
    ):
        return True

    if libs:
        for p in libs:
            base = os.path.basename(p)
            if base.startswith("libpython") and ".so" in base:
                return True
    return False


def get_ld_preload(pid):
    """Return list of LD_PRELOAD entries from the target's environ."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            for item in f.read().split(b"\0"):
                if item.startswith(b"LD_PRELOAD="):
                    raw = item.split(b"=", 1)[1].decode(errors="replace")
                    return [p for p in raw.replace(":", " ").split() if p]
    except OSError:
        pass
    return []


def get_child_pids(pid):
    """Return live child pids of pid, excluding the parent itself."""
    children = []
    task_dir = f"/proc/{pid}/task"
    if not os.path.isdir(task_dir):
        return []

    try:
        for tid in os.listdir(task_dir):
            try:
                with open(f"{task_dir}/{tid}/children") as f:
                    children.extend(f.read().split())
            except OSError:
                continue
    except OSError:
        return []

    result = []
    for c in set(children):
        if not c.isdigit() or c == str(pid):
            continue
        if not os.path.exists(f"/proc/{c}"):
            continue
        result.append(c)
    return result


# |-----------------------------------|
# |======> Path classification <======|
# |-----------------------------------|


def is_so_path(path):
    b = os.path.basename(path)
    return b.endswith(".so") or ".so." in b


_SITE_MARKERS = (
    "/site-packages/",
    "/dist-packages/",
    "/lib/python",  # conda: .../lib/python3.11/site-packages/foo.so
    "/.local/lib/",  # pip --user
)


def derive_module(path):
    """Best-effort Python module name derived from a .so path."""
    # stdlib C extensions: /usr/lib/python3.X/lib-dynload/_ssl.so
    if "/lib-dynload/" in path:
        base = strip_so_suffix(os.path.basename(path))
        for ext in (".so", ".pyd"):
            if base.endswith(ext):
                base = base[: -len(ext)]
                break
        return base

    for marker in _SITE_MARKERS:
        if marker in path:
            rel = path.split(marker, 1)[1]
            parts = rel.split("/")
            if len(parts) < 2:
                return None
            mods = []
            for part in parts[:-1]:
                if part.endswith((".dist-info", ".egg-info")):
                    break
                mods.append(part)
            base = strip_so_suffix(os.path.basename(path))
            if base.endswith(".so"):
                base = base[:-3]
            elif base.endswith(".pyd"):
                base = base[:-4]
            mods.append(base)
            return ".".join(mods)

    if ".egg/" in path:
        rel = path.split(".egg/", 1)[1]
        return rel.rsplit(".", 1)[0].replace("/", ".")

    return None


def resolve_soname(soname, rpaths, opts):
    """Resolve a NEEDED entry to an absolute path via rpaths, then ldconfig"""
    for rpath in rpaths:
        if not rpath:
            continue
        full = os.path.join(rpath, soname)
        if os.path.exists(full):
            try:
                return os.path.realpath(full)
            except OSError:
                continue
    return opts.ldmap.get(soname)


# |---------------------------------------|
# |======> Injected Python sources <======|
# |---------------------------------------|

SITE_CODE = r"""
import sys, os, json, atexit, types

_dlopens = []
_hook_status = "ok"

if hasattr(sys, "addaudithook"):
    def _hook(event, args):
        if event == "ctypes.dlopen":
            try:
                _dlopens.append([os.path.basename(args[0]), args[0]])
            except Exception:
                pass
    try:
        sys.addaudithook(_hook)
    except Exception as e:
        _hook_status = "addaudithook failed: " + repr(e)
else:
    _hook_status = "python < 3.8, ctypes.dlopen hook unavailable"


def _dump():
    try:
        modules = []
        for m in list(sys.modules):
            mod = sys.modules[m]
            if mod is None:
                continue
            spec = getattr(mod, "__spec__", None)
            path = getattr(spec, "origin", None) if spec is not None else None
            if not path or not isinstance(path, str):
                path = getattr(mod, "__file__", None)
            modules.append([m, path])

        imports = []
        for _m in list(sys.modules):
            mod = sys.modules[_m]
            if mod is None:
                continue
            try:
                _d = vars(mod)
            except Exception:
                continue
            for _v in list(_d.values()):
                if not isinstance(_v, types.ModuleType):
                    continue
                _n = getattr(_v, "__name__", None)
                if _n and _n != _m and _n in sys.modules:
                    imports.append([_m, _n])

        out = os.environ.get("SOTRACE_OUT")
        if out:
            out = out.replace("%p", str(os.getpid()))
            with open(out, "w") as f:
                json.dump({
                    "modules": modules,
                    "dlopens": _dlopens,
                    "imports": imports,
                    "interp": {
                        "exe": sys.executable,
                        "version": sys.version,
                        "prefix": sys.prefix,
                    },
                    "_hook_status": _hook_status,
                    "_source": "site",
                }, f)
    except Exception:
        pass


atexit.register(_dump)
"""


INJECT_CODE = r"""
import sys, json

modules = []
try:
    snapshot = list(sys.modules.items())
except Exception:
    snapshot = []

for name, mod in snapshot:
    if mod is None:
        continue
    try:
        spec = getattr(mod, "__spec__", None)
        origin = getattr(spec, "origin", None) if spec is not None else None
        if not origin or not origin.startswith("/"):
            origin = getattr(mod, "__file__", None)
        if not origin or not origin.startswith("/"):
            continue
        modules.append([str(name), str(origin)])
    except Exception:
        continue

interp = {}
try:
    interp["exe"] = sys.executable
    interp["version"] = sys.version
    interp["prefix"] = sys.prefix
except Exception:
    pass

try:
    with open(r"__OUT__", "w") as f:
        json.dump({
            "modules": modules,
            "interp": interp,
            "_source": "inject",
            "_hook_status": "inject-only",
        }, f)
except Exception:
    pass
"""
