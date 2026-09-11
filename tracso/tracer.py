"""Tracing and rendering logic"""

import csv
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from . import logger
from .config import GDB_TIMEOUT, PROC_POLL_INTERVAL, PROC_POLLS
from .utils import (INJECT_CODE, SITE_CODE, Palette, bar, derive_module,
                    elf_dynamic, fmt_size, get_child_pids, get_ld_preload,
                    is_python_pid, is_so_path, log, maps_libs, prefetch_elf,
                    py_name, resolve_soname, strip_so_suffix, v_pad)

# |--------------------------------------|
# |========> Graph construction <========|
# |--------------------------------------|


def walk_so(path, opts, seen, edges, dashed, cycles, stack, depth):
    """Recursively walk transitive .so dependencies of `path`."""
    if path in seen:
        return

    seen.add(path)
    info = elf_dynamic(path, opts)
    parent = strip_so_suffix(info["soname"])
    opts.path_by_name[parent] = path

    if depth >= opts.depth:
        return

    stack.add(path)

    rpaths = list(info.get("rpath", ()))
    if rpaths:
        origin = os.path.dirname(path)
        rpaths = [
            r.replace("$ORIGIN", origin).replace("${ORIGIN}", origin) for r in rpaths
        ]

    for dep in info["needed"]:
        resolved = resolve_soname(dep, rpaths, opts)

        if resolved:
            child_info = elf_dynamic(resolved, opts)
            child = strip_so_suffix(child_info["soname"])
            opts.path_by_name[child] = resolved
            edge = (parent, child)

            if resolved in stack:
                cycles.add(edge)

            edges.add(edge)

            if resolved not in seen:
                walk_so(resolved, opts, seen, edges, dashed, cycles, stack, depth + 1)
        else:
            child = strip_so_suffix(dep)
            opts.path_by_name.setdefault(child, None)
            edge = (parent, child)
            edges.add(edge)
            dashed.add(edge)

    stack.remove(path)


def trace_pid(pid, opts, seen, edges, dashed, cycles, child_depth=0):
    """Trace a live process: mapped .so files plus Python attribution."""
    libs = maps_libs(pid)
    real_paths = set()
    for path in libs:
        try:
            real_paths.add(os.path.realpath(path))
        except OSError as exc:
            logger.error(str(exc))

    if not opts.interp.get("exe"):
        try:
            exe = os.path.realpath(f"/proc/{pid}/exe")
            if os.path.exists(exe):
                opts.interp["exe"] = exe
        except OSError:
            pass

    # Running process overrides ldconfig cache.
    for path in real_paths:
        opts.ldmap[os.path.basename(path)] = path

    if not opts.target_label:
        opts.target_label = f"pid:{pid}"

    if is_python_pid(pid, libs):
        data = inject_sys_modules(pid, opts)
        if data:
            log(
                opts,
                f"tracso: injected into pid {pid}, "
                f"{len(data.get('modules', []))} modules",
            )
            add_python_edges(data, real_paths, opts, edges)
        else:
            log(
                opts,
                f"tracso: injection failed, using path-derived "
                f"attribution for pid {pid}",
            )
            add_site_package_fallback(real_paths, opts, edges)

    for preload in get_ld_preload(pid):
        try:
            rp = os.path.realpath(preload)
        except OSError:
            continue
        if rp in real_paths or os.path.exists(rp):
            info = elf_dynamic(rp, opts)
            so = strip_so_suffix(info["soname"])
            opts.path_by_name[so] = rp
            edges.add(("env:LD_PRELOAD", so))

    prefetch_elf(sorted(real_paths), opts)

    root_names = set()
    for rp in sorted(real_paths):
        info = elf_dynamic(rp, opts)
        root_names.add(strip_so_suffix(info["soname"]))
        walk_so(rp, opts, seen, edges, dashed, cycles, set(), 0)

    children = {c for _, c in edges}
    for name in sorted(root_names):
        if name not in children:
            edges.add((opts.target_label, name))

    if child_depth < 2:
        for child_pid in get_child_pids(pid):
            trace_pid(child_pid, opts, seen, edges, dashed, cycles, child_depth + 1)


def add_python_edges(data, allowed_paths, opts, edges):
    """Turn sitecustomize / gdb-injection output into graph edges."""
    for entry in data.get("modules", []):
        if isinstance(entry, (list, tuple)) and len(entry) == 2 and entry[0]:
            opts.all_py_names.add(str(entry[0]))

    raw_modules = []
    for entry in data.get("modules", []):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        modname, path = entry
        if not modname or not path or not isinstance(path, str):
            continue
        if not os.path.isabs(path):
            continue
        try:
            rp = os.path.realpath(path)
        except OSError:
            continue

        if allowed_paths is not None:
            if rp not in allowed_paths:
                continue
        elif not is_so_path(rp):
            continue

        raw_modules.append((str(modname), rp))

    for modname, rp in raw_modules:
        info = elf_dynamic(rp, opts)
        so = strip_so_suffix(info["soname"])
        opts.path_by_name[so] = rp
        edges.add((py_name(modname, opts.name_depth), so))

    for entry in data.get("dlopens", []):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        modname, path = entry
        if not path:
            continue
        try:
            rp = os.path.realpath(str(path))
        except OSError:
            continue
        if allowed_paths is not None and rp not in allowed_paths:
            continue
        if allowed_paths is None and not is_so_path(rp):
            continue
        info = elf_dynamic(rp, opts)
        so = strip_so_suffix(info["soname"])
        opts.path_by_name[so] = rp
        edges.add((py_name(str(modname), opts.name_depth), so))

    for entry in data.get("imports", []):
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            continue
        _importer, _imported = entry
        _importer = str(_importer)
        _imported = str(_imported)
        if _importer not in opts.all_py_names or _imported not in opts.all_py_names:
            continue
        parent = py_name(_importer, opts.name_depth)
        child = py_name(_imported, opts.name_depth)
        if child != parent:
            opts.py_imports[child].add(parent)

    status = data.get("_hook_status")
    if status and status != "ok":
        log(opts, "tracso: python-side hook status:", status)

    if isinstance(data.get("interp"), dict):
        opts.interp = data["interp"]


def add_site_package_fallback(real_paths, opts, edges):
    """When injection fails, infer Python origin from .so path layout."""
    for path in real_paths:
        base = os.path.basename(path)
        if (
            ".cpython-" not in base
            and ".abi3." not in base
            and not base.endswith(".pyd")
        ):
            continue
        if not any(
            marker in path
            for marker in ("/site-packages/", "/dist-packages/", "/lib/python")
        ):
            continue
        mod = derive_module(path)
        if not mod:
            continue
        opts.all_py_names.add(mod)
        info = elf_dynamic(path, opts)
        so = strip_so_suffix(info["soname"])
        opts.path_by_name[so] = path
        edges.add((py_name(mod, opts.name_depth), so))


# |---------------------------------|
# |========> gdb injection <========|
# |---------------------------------|


def inject_sys_modules(pid, opts):
    """Use gdb to dump sys.modules from a running Python process."""
    if not shutil.which("gdb"):
        log(opts, "tracso: gdb not found, skipping Python module injection")
        return None

    tmpdir = tempfile.mkdtemp()
    try:
        out_path = os.path.join(tmpdir, "out.json")
        inject_py = os.path.join(tmpdir, "inject.py")
        gdb_txt = os.path.join(tmpdir, "gdb.txt")

        with open(inject_py, "w") as f:
            f.write(INJECT_CODE.replace("__OUT__", out_path))

        with open(gdb_txt, "w") as f:
            f.write("set pagination off\n")
            f.write("set confirm off\n")
            f.write("set $st = (int)PyGILState_Ensure()\n")
            f.write(
                "call (int)PyRun_SimpleString("
                "\"exec(compile(open('" + inject_py + "').read(),"
                "'inject.py','exec'))\")\n"
            )
            f.write("call (void)PyGILState_Release($st)\n")
            f.write("detach\n")
            f.write("quit\n")

        try:
            proc = subprocess.Popen(
                ["gdb", "-p", str(pid), "-batch", "-nx", "-x", gdb_txt],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                proc.communicate(timeout=GDB_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                log(opts, "tracso: gdb hung, killed")
                return None
        except (OSError, subprocess.SubprocessError) as e:
            log(opts, "tracso: gdb failed:", e)
            return None

        if not os.path.exists(out_path):
            log(opts, "tracsp: gdb ran but produced no output file")
            return None

        try:
            with open(out_path) as f:
                content = f.read()
        except OSError as e:
            log(opts, "tracso: cannot read gdb output:", e)
            return None

        if not content.strip():
            log(opts, "tracso: gdb output file is empty")
            return None

        try:
            return json.loads(content)
        except ValueError as e:
            log(opts, "tracso: gdb output is not valid JSON:", e)
            return None

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# |-----------------------------------|
# |========> Spawn-and-trace <========|
# |-----------------------------------|


def run_spawn(cmd, opts):
    """Run a command with sitecustomize injection, then trace it."""
    tmpdir = tempfile.mkdtemp()
    try:
        sitecustomize = os.path.join(tmpdir, "sitecustomize.py")
        with open(sitecustomize, "w") as f:
            f.write(SITE_CODE)

        env = os.environ.copy()
        old_pp = env.get("PYTHONPATH")
        env["PYTHONPATH"] = tmpdir + (os.pathsep + old_pp if old_pp else "")
        env["SOTRACE_OUT"] = os.path.join(tmpdir, "dump_%p.json")

        proc = subprocess.Popen(cmd, env=env)

        if not opts.target_label:
            opts.target_label = f"run:{os.path.basename(cmd[0])}:{proc.pid}"

        def forward(signum, frame):
            try:
                proc.send_signal(signum)
            except OSError:
                pass

        old_int = signal.signal(signal.SIGINT, forward)
        old_term = signal.signal(signal.SIGTERM, forward)

        try:
            time.sleep(0.25)

            edges = set()
            dashed = set()
            cycles = set()
            seen = set()

            if proc.poll() is None:
                trace_pid(str(proc.pid), opts, seen, edges, dashed, cycles)

            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.send_signal(signal.SIGINT)
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            except OSError:
                pass

            for dump in sorted(glob.glob(os.path.join(tmpdir, "dump_*.json"))):
                try:
                    with open(dump) as f:
                        data = json.load(f)
                    add_python_edges(data, None, opts, edges)
                except (OSError, ValueError):
                    continue

            return edges, dashed, cycles
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# |----------------------------|
# |========> Analysis <========|
# |----------------------------|


def compute_baseline(opts):
    """Sample a bare interpreter to find the always-loaded .so set."""
    if opts.baseline:
        return opts.baseline

    exe = opts.interp.get("exe") or "python3"
    try:
        proc = subprocess.Popen(
            [exe, "-c", "import time; time.sleep(0.5)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        opts.baseline = set()
        return opts.baseline

    libs = []
    try:
        for _ in range(PROC_POLLS):
            time.sleep(PROC_POLL_INTERVAL)
            if proc.poll() is not None:
                break
            cur = maps_libs(proc.pid)
            if any("libpython" in os.path.basename(p) for p in cur):
                libs = cur
                break
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            try:
                proc.kill()
                proc.wait()
            except OSError:
                pass

    opts.baseline = {strip_so_suffix(os.path.basename(p)) for p in libs}
    return opts.baseline


def analyze(edges, opts):
    """Compute graph metrics shared by every renderer."""
    parents = defaultdict(set)
    children = defaultdict(set)
    nodes = set()

    for parent, child in edges:
        parents[child].add(parent)
        children[parent].add(child)
        nodes.add(parent)
        nodes.add(child)

    in_degree = {node: len(parents[node]) for node in nodes}
    sizes = {}

    for node in nodes:
        path = opts.path_by_name.get(node)
        if path:
            try:
                sizes[node] = os.path.getsize(path)
            except OSError:
                pass

    return {
        "parents": parents,
        "children": children,
        "nodes": nodes,
        "in_degree": in_degree,
        "size": sizes,
        "roots": {node for node in nodes if not parents[node]},
    }


def make_source_resolver(metrics, opts):
    """Callable(node) -> set of py:/env: owners.

    Walks only parent edges (which are .so -> .so and .so -> py:),
    never py_imports. A Python module that imports another module
    does not claim the other module's .so files.
    """
    parents = metrics["parents"]
    memo = {}

    def owners(node):
        cached = memo.get(node)
        if cached is not None:
            return cached

        result = set()
        seen = {node}
        frontier = list(parents[node])

        while frontier:
            next_frontier = []
            for p in frontier:
                if p in seen:
                    continue
                seen.add(p)
                if p.startswith(("py:", "env:")):
                    result.add(p)
                else:
                    next_frontier.extend(parents[p])
            frontier = next_frontier

        memo[node] = result
        return result

    return owners


def _so_nodes(metrics, opts):
    """All .so nodes, excluding py:/env: prefixes and the target label."""
    out = []
    for node in metrics["nodes"]:
        if node.startswith(("py:", "env:")) or node == opts.target_label:
            continue
        if ".so" in node or (
            opts.path_by_name.get(node) is not None
            and is_so_path(opts.path_by_name[node])
        ):
            out.append(node)
    return sorted(out)


# |----------------------------------|
# |========> Colour helpers <========|
# |----------------------------------|


def use_color(opts, stream):
    if opts.color == "always":
        return True
    if opts.color == "never":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def paint_node(name, metrics, color):
    if not color:
        return name
    indeg = metrics["in_degree"].get(name, 0)
    outdeg = len(metrics["children"].get(name, ()))
    if indeg > 3 and outdeg > 1:
        return f"\033[33m{name}\033[0m"
    if indeg > 1:
        return f"\033[36m{name}\033[0m"
    return name


def paint_source(name, source_count, metrics, color):
    if not color:
        return name
    outdeg = len(metrics["children"].get(name, ()))
    if source_count > 3 or (source_count > 1 and outdeg > 1):
        return f"\033[33m{name}\033[0m"
    if source_count > 1:
        return f"\033[36m{name}\033[0m"
    return name


# |-----------------------------|
# |========> Renderers <========|
# |-----------------------------|


def _kind_color(node, opts, p):
    """Colour a node by what it is"""
    if node.startswith("py:"):
        return p.cyan(node)
    if node.startswith("env:"):
        return p.magenta(node)
    path = opts.path_by_name.get(node)
    if path and any(
        m in path for m in ("/site-packages/", "/dist-packages/", "/lib/python")
    ):
        return p.green(node)
    if path and path.startswith(("/lib/", "/usr/lib/")):
        return p.dim(node)
    return node


def render_attribution(edges, metrics, opts, stream):
    p = Palette(use_color(opts, stream))
    owners = make_source_resolver(metrics, opts)
    so_nodes = _so_nodes(metrics, opts)

    if not so_nodes:
        stream.write(p.dim("no shared libraries found\n"))
        return

    total_bytes = sum(metrics["size"].get(n, 0) for n in so_nodes)

    interp = opts.interp.get("exe", "")
    interp_tag = os.path.basename(interp) if interp else "?"
    target = opts.target_label or "?"

    stream.write(
        f"{p.bold('tracso')} \u00b7 {target} ({interp_tag}) \u00b7 "
        f"{len(so_nodes)} libs \u00b7 {fmt_size(total_bytes)}\n\n"
    )

    # --- per-package aggregation (fractional for shared .so) ---

    pkg_bytes = defaultdict(int)
    pkg_libs = defaultdict(list)

    for node in so_nodes:
        size = metrics["size"].get(node, 0)
        py = [s for s in owners(node) if s.startswith("py:")]
        if not py:
            continue
        share = size // len(py)
        for s in py:
            pkg_bytes[s] += share
            pkg_libs[s].append(node)

    unattr_bytes = 0
    for node in so_nodes:
        if not [s for s in owners(node) if s.startswith("py:")]:
            unattr_bytes += metrics["size"].get(node, 0)

    # --- notable ---

    notable = _notable_findings(so_nodes, metrics, owners, p, total_bytes)
    if notable:
        stream.write(f"{p.bold('Notable')}\n")
        for line in notable:
            stream.write(f"  {p.dim('*')} {line}\n")
        stream.write("\n")

    # --- heaviest packages ---

    if pkg_bytes:
        top = sorted(pkg_bytes.items(), key=lambda kv: -kv[1])[:10]
        max_b = total_bytes or 1

        stream.write(f"{p.bold('Heaviest packages')}\n")
        for pkg, size in top:
            pct = 100.0 * size / total_bytes if total_bytes else 0.0
            name = p.cyan(v_pad(pkg, 32))
            nlibs = len(pkg_libs[pkg])
            stream.write(
                f"  {name} "
                f"{fmt_size(size):>9}  "
                f"{p.dim(bar(size, max_b))}  "
                f"{pct:5.1f}%  "
                f"{p.dim(f'({nlibs} libs)')}\n"
            )
        if unattr_bytes > 0:
            pct = 100.0 * unattr_bytes / total_bytes if total_bytes else 0.0
            name = p.dim(v_pad("(unattributed / system)", 32))
            stream.write(
                f"  {name} "
                f"{fmt_size(unattr_bytes):>9}  "
                f"{p.dim(bar(unattr_bytes, max_b))}  "
                f"{pct:5.1f}%  "
                f"{p.dim(f'({len([n for n in so_nodes if not owners(n)])} libs)')}\n"
            )
        stream.write("\n")

    # --- most depended-on libraries ---

    top_libs = sorted(
        so_nodes,
        key=lambda n: (-metrics["in_degree"].get(n, 0), -metrics["size"].get(n, 0)),
    )[:15]

    if top_libs:
        max_i = max((metrics["in_degree"].get(n, 0) for n in top_libs), default=1)

        stream.write(f"{p.bold('Most depended-on libraries')}\n")
        for n in top_libs:
            indeg = metrics["in_degree"].get(n, 0)
            size = metrics["size"].get(n, 0)
            py = [s for s in owners(n) if s.startswith("py:")]
            tag = p.cyan(f"{len(py)} py") if py else p.dim("unattributed")
            name_padded = v_pad(n, 40)
            name_colored = _kind_color(name_padded, opts, p)
            stream.write(
                f"  {name_colored} "
                f"{fmt_size(size):>9}  "
                f"{p.dim(bar(indeg, max_i))}  "
                f"in={indeg:<3}  {tag}\n"
            )
        stream.write("\n")

    # --- orphans ---

    orphans = [
        n
        for n in so_nodes
        if not owners(n)
        and metrics["in_degree"].get(n, 0) == 0
        and n not in _ALWAYS_PRESENT
    ]
    unattr = [
        n
        for n in so_nodes
        if not owners(n)
        and metrics["in_degree"].get(n, 0) > 0
        and n not in _ALWAYS_PRESENT
    ]

    if orphans:
        stream.write(
            f"{p.bold('Orphans')} " f"{p.dim('(no Python origin, no .so parent)')}\n"
        )
        for n in sorted(orphans, key=lambda x: -metrics["size"].get(x, 0))[:10]:
            size = metrics["size"].get(n, 0)
            stream.write(f"  {p.red(v_pad(n, 40))} {fmt_size(size):>9}\n")
        if len(orphans) > 10:
            stream.write(f"  {p.dim(f'... and {len(orphans) - 10} more')}\n")
        stream.write("\n")

    stream.write(
        p.dim(
            "Try: tracso --why <lib>  \u00b7  "
            "tracso --tree  \u00b7  "
            "tracso --json | jq"
        )
        + "\n"
    )


_SYSTEM_PREFIXES = ("/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/")

# Libraries present in every ELF process, so never "notable"
_ALWAYS_PRESENT = {
    "ld-linux-x86-64.so.2",
    "ld-linux.so.2",
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libgcc_s.so.1",
}


def _notable_findings(so_nodes, metrics, owners, p, total_bytes):
    """Return up to four sentence-formatted findings."""
    out = []
    total = total_bytes or 1

    # Library owned by more than one py: package (shared dependency).
    shared = []
    for n in so_nodes:
        if n in _ALWAYS_PRESENT:
            continue
        py = [s for s in owners(n) if s.startswith("py:")]
        if len(py) > 1:
            shared.append((n, py))
    shared.sort(key=lambda x: (-len(x[1]), -metrics["size"].get(x[0], 0)))

    if shared:
        n, srcs = shared[0]
        srcs_sorted = sorted(srcs)
        head = ", ".join(srcs_sorted[:3])
        if len(srcs_sorted) > 3:
            head += f", +{len(srcs_sorted) - 3} more"
        out.append(
            f"{p.bold(n)} is loaded directly by "
            f"{p.yellow(str(len(srcs)))} py: packages ({head})"
        )

    # Dominant package.
    pkg_bytes = defaultdict(int)
    for n in so_nodes:
        size = metrics["size"].get(n, 0)
        py = [s for s in owners(n) if s.startswith("py:")]
        if not py:
            continue
        share = size // len(py)
        for s in py:
            pkg_bytes[s] += share

    if pkg_bytes:
        pkg, size = max(pkg_bytes.items(), key=lambda kv: kv[1])
        pct = 100.0 * size / total
        if pct >= 30:
            out.append(
                f"{p.bold(pkg)} owns "
                f"{p.yellow(f'{pct:.0f}%')} of the total footprint "
                f"({fmt_size(size)})"
            )

    # Orphans: no py: owner, no .so parent.
    orphans = [
        n
        for n in so_nodes
        if n not in _ALWAYS_PRESENT
        and not owners(n)
        and metrics["in_degree"].get(n, 0) == 0
    ]
    if orphans:
        ob = sum(metrics["size"].get(n, 0) for n in orphans)
        out.append(
            f"{p.yellow(str(len(orphans)))} libraries with no Python origin "
            f"({fmt_size(ob)}) — dynamically loaded or leaked"
        )

    # Largest non-system library.
    big = sorted(
        (n for n in so_nodes if n not in _ALWAYS_PRESENT),
        key=lambda n: -metrics["size"].get(n, 0),
    )
    if big:
        b = big[0]
        size = metrics["size"].get(b, 0)
        pct = 100.0 * size / total
        if pct >= 20:
            out.append(
                f"{p.bold(b)} alone is {fmt_size(size)} ({pct:.0f}% of the total)"
            )

    return out[:4]


def render_tree(edges, dashed, cycles, metrics, opts, stream):
    color = use_color(opts, stream)
    baseline = compute_baseline(opts)
    visited = set()
    roots = sorted(metrics["roots"]) or sorted(metrics["nodes"])

    def walk(node, prefix, last, root):
        name = paint_node(node, metrics, color)

        if node in visited:
            connector = "" if root else ("└─" if last else "├─")
            stream.write(f"{prefix}{connector}{name}…\n")
            return

        visited.add(node)

        suffix = ""
        for _p in metrics["parents"][node]:
            if (_p, node) in cycles or (node, _p) in cycles:
                suffix = "*"
                break
        if not suffix:
            for _c in metrics["children"][node]:
                if (node, _c) in cycles:
                    suffix = "*"
                    break

        tag = " [baseline]" if node in baseline else ""

        if root:
            stream.write(f"{name}{suffix}{tag}\n")
        else:
            connector = "└─" if last else "├─"
            stream.write(f"{prefix}{connector}{name}{suffix}{tag}\n")

        kids = sorted(metrics["children"][node])
        for i, child in enumerate(kids):
            if root:
                child_prefix = prefix + "  "
            else:
                child_prefix = prefix + ("  " if last else "│ ")
            walk(child, child_prefix, i == len(kids) - 1, False)

    for i, root in enumerate(roots):
        walk(root, "", i == len(roots) - 1, True)


def render_json(edges, dashed, cycles, metrics, opts):
    resolve_sources = make_source_resolver(metrics, opts)
    baseline = compute_baseline(opts)
    nodes = []

    for node in sorted(metrics["nodes"]):
        nodes.append(
            {
                "name": node,
                "path": opts.path_by_name.get(node),
                "size": metrics["size"].get(node),
                "in_degree": metrics["in_degree"].get(node, 0),
                "out_degree": len(metrics["children"].get(node, ())),
                "baseline": node in baseline,
                "sources": (
                    sorted(resolve_sources(node))
                    if not node.startswith(("py:", "env:"))
                    else []
                ),
            }
        )

    edge_list = []
    for parent, child in sorted(edges):
        if (parent, child) in cycles:
            kind = "cycle"
        elif (parent, child) in dashed:
            kind = "missing"
        elif parent.startswith(("py:", "env:")):
            kind = "origin"
        else:
            kind = "needed"
        edge_list.append({"source": parent, "target": child, "kind": kind})

    return {
        "target": opts.target_label,
        "interpreter": opts.interp.get("exe"),
        "nodes": nodes,
        "edges": edge_list,
    }


def render_csv(metrics, opts, stream):
    resolve_sources = make_source_resolver(metrics, opts)
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["soname", "path", "size", "in_degree", "out_degree", "sources"])

    for node in _so_nodes(metrics, opts):
        writer.writerow(
            [
                node,
                opts.path_by_name.get(node) or "",
                metrics["size"].get(node, 0),
                metrics["in_degree"].get(node, 0),
                len(metrics["children"].get(node, ())),
                ";".join(sorted(resolve_sources(node))),
            ]
        )


def dot_escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_dot(edges, dashed, cycles, metrics, opts):
    """Return a Graphviz DOT string tuned for dependency graphs."""
    lines = [
        "digraph G {",
        "  graph [",
        "    rankdir=LR,",
        "    splines=ortho,",
        "    nodesep=0.22,",
        "    ranksep=0.55,",
        "    concentrate=false,",
        "    overlap=false,",
        '    bgcolor="white"',
        "  ];",
        "  node [",
        '    fontname="Menlo,Consolas,monospace",',
        "    fontsize=10,",
        "    shape=box,",
        '    style="rounded,filled",',
        '    margin="0.12,0.06",',
        "    penwidth=1.0",
        "  ];",
        "  edge [",
        "    arrowsize=0.75,",
        "    penwidth=0.9",
        '    fontname="Menlo,Consolas,monospace",',
        "    fontsize=8,",
        "  ];",
    ]

    source_nodes = []
    site_nodes = set()
    system_nodes = set()

    for node in sorted(metrics["nodes"]):
        if node.startswith(("py:", "env:")):
            source_nodes.append(node)
            continue
        path = opts.path_by_name.get(node)
        if path and any(
            m in path for m in ("/site-packages/", "/dist-packages/", "/lib/python")
        ):
            site_nodes.add(node)
        elif path and path.startswith(("/lib/", "/usr/lib/", "/lib64/", "/usr/lib64/")):
            system_nodes.add(node)

    hub_names = {
        "libc.so.6",
        "ld-linux-x86-64.so.2",
        "ld-linux.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "librt.so.1",
        "libgcc_s.so.1",
        "libstdc++.so.6",
    }

    def attrs_for(node):
        a = {}
        if node == opts.target_label:
            a["shape"] = "box"
            a["style"] = "rounded,filled,bold"
            a["fillcolor"] = "#ffffff"
            a["fontcolor"] = "1e3a8a"
            a["color"] = "#1e40af"
            a["penwidth"] = "2.4"
            a["fontsize"] = "11"
            return a
        if node.startswith("py:"):
            a["shape"] = "ellipse"
            a["fillcolor"] = "#dbeafe"
            a["color"] = "#2563eb"
        elif node.startswith("env:"):
            a["shape"] = "hexagon"
            a["fillcolor"] = "#fce7f3"
            a["color"] = "#db2777"
        elif node in site_nodes:
            a["fillcolor"] = "#dcfce7"
            a["color"] = "#16a34a"
        elif node in system_nodes:
            a["fillcolor"] = "#f3f4f6"
            a["color"] = "#9ca3af"
        else:
            a["fillcolor"] = "#fef3c7"
            a["color"] = "#d97706"

        indeg = metrics["in_degree"].get(node, 0)
        if indeg >= 5:
            a["penwidth"] = "1.6"
        elif indeg >= 2:
            a["penwidth"] = "1.2"
        return a

    for node in sorted(metrics["nodes"]):
        a = attrs_for(node)
        attr_str = ", ".join(
            f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}" for k, v in a.items()
        )
        path = opts.path_by_name.get(node) or ""
        tip = path if path else node
        lines.append(
            f'  "{dot_escape(node)}" '
            f'[label="{dot_escape(node)}", '
            f'tooltip="{dot_escape(tip)}", {attr_str}];'
        )

    if source_nodes:
        joined = "; ".join(f'"{dot_escape(n)}"' for n in source_nodes)
        lines.append(f"  {{ rank=source; {joined}; }}")

    if opts.target_label and opts.target_label in metrics["nodes"]:
        lines.append(f' {{ rank=same; "{dot_escape(opts.target_label)}"; }}')

    for parent, child in sorted(edges):
        a = []
        if (parent, child) in cycles:
            a.append("style=dashed")
            a.append('color="#dc2626"')
        elif (parent, child) in dashed:
            a.append("style=dotted")
            a.append('color="#9ca3af"')
        elif parent == opts.target_label:
            a.append('color="#111827"')
            a.append("penwidth=1.6")
        elif parent.startswith(("py:", "env:")):
            a.append('color="#2563eb"')
        else:
            a.append('color="#94a3b8"')

        if child == opts.target_label and parent != opts.target_label:
            a.append("constraint=false")

        if child in hub_names and metrics["in_degree"].get(child, 0) >= 8:
            a.append("constraint=false")

        lines.append(
            f'  "{dot_escape(parent)}" -> "{dot_escape(child)}" ' f'[{", ".join(a)}];'
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def render_why(target, edges, metrics, opts, stream):
    if target not in metrics["nodes"]:
        base = os.path.basename(target)
        candidates = [
            node
            for node in metrics["nodes"]
            if node == base
            or node == target
            or (
                opts.path_by_name.get(node)
                and os.path.basename(opts.path_by_name[node]) == base
            )
        ]
        if not candidates:
            return warn(f"not found: {target}")
        target = sorted(candidates)[0]

    parents = metrics["parents"]
    paths = []
    stack = [(target, [target])]

    while stack:
        if len(paths) > 1000:
            break
        node, path = stack.pop()

        if node.startswith("env:"):
            paths.append(path)
            continue

        if node.startswith("py:"):
            importers = opts.py_imports.get(node, ())
            if importers:
                for imp in importers:
                    if imp not in path:
                        stack.append((imp, path + [imp]))
                continue
            paths.append(path)
            continue

        if not parents[node]:
            paths.append(path)
            continue

        for parent in parents[node]:
            if parent not in path:
                stack.append((parent, path + [parent]))

    unique = []
    seen_paths = set()
    for path in paths:
        key = tuple(path)
        if key not in seen_paths:
            seen_paths.add(key)
            unique.append(path)

    if not unique:
        return warn(f"no path to {target}")

    for path in sorted(unique, key=len):
        stream.write(" → ".join(reversed(path)) + "\n")

    return 0


# |-----------------------------------|
# |========> Output dispatch <========|
# |-----------------------------------|


def _detect_format(args, out):
    if args.json:
        return "json"
    if args.csv:
        return "csv"
    if args.tree:
        return "tree"
    ext = Path(out).suffix.lower()
    if ext in {".dot", ".gv"}:
        return "dot"
    if ext == ".json":
        return "json"
    if ext == ".csv":
        return "csv"
    if ext in {".svg", ".png", ".pdf"}:
        return "image"
    return "attribution"


def write_output(args, opts, edges, dashed, cycles, metrics):
    out = args.output or "-"
    fmt = _detect_format(args, out)

    if fmt == "image":
        if out == "-":
            return logger.error("image output requires a file path")
        if shutil.which("dot") is None:
            return logger.error("graphviz required, install graphviz")
        dot_text = build_dot(edges, dashed, cycles, metrics, opts)
        fmt_name = Path(out).suffix.lstrip(".").lower()
        try:
            proc = subprocess.run(
                ["dot", f"-T{fmt_name}", "-o", out],
                input=dot_text,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            return logger.error(f"dot failed {str(exc)}")
        if proc.returncode != 0:
            return logger.error(f"dot failed {proc.stderr.strip()}")
        return 0

    try:
        stream = sys.stdout if out == "-" else open(out, "w")
    except OSError as exc:
        return logger.error(str(exc))

    try:
        if fmt == "json":
            json.dump(
                render_json(edges, dashed, cycles, metrics, opts), stream, indent=2
            )
            stream.write("\n")
        elif fmt == "csv":
            render_csv(metrics, opts, stream)
        elif fmt == "dot":
            stream.write(build_dot(edges, dashed, cycles, metrics, opts))
        elif fmt == "tree":
            render_tree(edges, dashed, cycles, metrics, opts, stream)
        else:
            render_attribution(edges, metrics, opts, stream)
    finally:
        if stream is not sys.stdout:
            stream.close()
    return 0
