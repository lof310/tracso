# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-09-11

Initial public release.

### Added

- **Process analysis**
  - `tracso <PID>` attaches to a running process and traces every shared
    object currently mapped in its address space.
  - `tracso <path.so>` traces the transitive `DT_NEEDED` closure of a
    single ELF shared object.
  - `tracso --run <cmd>` launches a command under a `sitecustomize`
    injection, traces the child, and captures `sys.modules`,
    `ctypes.dlopen` events, and Python import edges via an audit hook.
  - `tracso --pick` offers an interactive process picker with three
    backends: a Textual TUI, a stdlib curses fallback, and a plain
    numbered list for pipes and CI.
  - `--pick-mode {textual,curses,plain}` forces a specific picker backend.
  - `--pick-py` narrows the picker to Python interpreters.

- **Attribution**
  - Nearest-ancestor attribution: each `.so` is attributed to the `py:`
    package that loads it directly, not to every transitive importer.
    Shared libraries are split fractionally across owners so per-package
    totals sum to 100%.
  - Fallback attribution derives Python package names from `.so` paths
    when gdb-based `sys.modules` injection is unavailable. Covers
    `site-packages`, `dist-packages`, conda (`/lib/python*`),
    `pip --user` (`/.local/lib/`), and `.egg` archives.
  - `--why <SONAME>` reports the exact `.so` → `.so` path from a Python
    module to a target library.

- **Output**
  - Default attribution table with a one-line summary, a `Notable`
    section, a ranked `Heaviest packages` table, a ranked
    `Most depended-on libraries` table, and an `Orphans` section.
  - `--tree` — dependency tree with cycle markers.
  - `--json` — structured graph with nodes, edges, sizes, in-degrees,
    owners, and baseline flags.
  - `--csv` — flat tabular export.
  - `-o <file>.{dot,gv,svg,png,pdf}` — Graphviz output. The `.dot`
    writer sets `splines=polyline`, `concentrate=true`, ranks `py:` and
    `env:` nodes at the source, colours nodes by kind, scales borders by
    in-degree, and attaches the absolute library path as a tooltip.
  - Human-readable sizes (B / KB / MB / GB), percentage bars, and ANSI
    colour that respects `--color {auto,always,never}` and `NO_COLOR`.

- **Configuration**
  - `--depth N` limits the `.so` recursion depth (default 8).
  - `-v` / `--verbose` logs injection decisions to stderr.

### Detection

- `/proc/<pid>/maps` for the mapped-object set.
- `/proc/<pid>/environ` for `LD_PRELOAD` attribution.
- `/proc/<pid>/task/<tid>/children` for child process traversal, with
  dead-pid filtering.
- `readelf --wide -d` for `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and
  `DT_RUNPATH`, parsed once per file and memoized per run.
- `ldconfig -p` for system soname resolution, overridden by the running
  process's actual mapped paths so virtualenv and container copies win.
- `libpython*.so` detection for processes that embed CPython without a
  `python` executable name.
- `libtorch` detection to skip gdb injection on PyTorch targets, which
  corrupts the glibc heap when a thread is stopped inside `malloc`.

### Safety

- gdb injection uses `Popen` + `communicate(timeout=)` and kills gdb on
  hang. Empty or invalid output is treated as failure, not success.
- The injected `sys.modules` dump iterates a snapshot to tolerate
  modules with PEP 562 `__getattr__` that mutate `sys.modules`.
- The `sitecustomize` hook reports whether the `ctypes.dlopen` audit
  hook was installed, so the caller can distinguish full attribution
  from path-derived fallback.
- `run_spawn` terminates the child with SIGTERM, then SIGINT, then
  SIGKILL, and forwards user signals.

### Logging

- `loguru` integration when installed, with a `print`-backed
  `_FallbackLogger` that exposes the same method surface
  (`trace`/`debug`/`info`/`success`/`warning`/`error`/`critical`) when
  it is not.

### Packaging

- Installable via `pip install tracso`.
- Optional dependency groups: `tracso[tui]` for the Textual picker,
  `tracso[log]` for loguru, `tracso[all]` for both.
- Type annotations on all public functions; passes `mypy`.
- Linted with `ruff`; formatted with `ruff format`.
- `pyproject.toml` uses PEP 621 metadata with `project.urls`,
  `project.classifiers`, and `tool.*` sections for `ruff`, `mypy`,
  and `pytest`.

### Known limitations

- Linux only. macOS and Windows are not supported; `/proc` is required.
- gdb-based `sys.modules` injection fails on statically linked or frozen
  Python (PyInstaller, PyOxidizer, musl). The path-derived fallback runs
  in that case and produces attribution without import edges.
- `io_uring` submissions after the initial `io_uring_enter` are not
  traced; neither are memory-mapped file reads, which bypass the syscall
  layer.
- `DT_NEEDED` closure reflects what is declared on disk. Libraries
  loaded via `dlopen` are included when found in `/proc/<pid>/maps` but
  not when only present on the filesystem.

### Notes
- The attribution model is documented in the README under
  "Attribution model". It is the differentiator versus
  `pldd`, and `ldd`.

[1.0.0]: https://github.com/lof310/tracso/releases/tag/v1.0.0
