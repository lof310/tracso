# tracso

Trace shared-object origins of a running process.

tracso reads /proc/<pid>/maps, walks the ELF DT_NEEDED graph of every
shared library the process has loaded, and produces a report mapping
each library back to the module or package that caused it to be loaded.

Supported runtimes: Python 3.8 and later.

## Usage
tracso [-h] [-o OUTPUT] [--run ...] [--why SONAME] [--pick] [--pick-py] [--pick-mode {textual,curses,plain}] [--tree] [--json] [--csv]
              [--depth DEPTH] [--name-depth N] [--color {auto,always,never}] [-v] [--version]
              [target]

**positional arguments:**
  target                PID or library path

**options:**
  -h, --help            show this help message and exit
  -o, --output OUTPUT   output dot graph
  --run ...             run command and trace it
  --why SONAME          trace origin of a library
  --pick                interactively pick a process to trace
  --pick-py             Pick only python processes
  --pick-mode {textual,curses,plain} force a picker backend
  --tree                tree output
  --json                JSON output
  --csv                 CSV output
  --depth DEPTH         max .so depth (default 8)
  --name-depth N        python module name depth; 0=full (default 2)
  --color {auto,always,never}
  -v, --verbose         log injection decisions to stderr
  --version             show program's version number and exit

## Requirements
- Linux
- Python 3.8 or later
- readelf              (binutils, present on all Linux systems)
- ldconfig             (glibc)
- gdb                  (optional, enables Python module attribution)

No Python packages are required bessides stdlib. Optional dependencies:
- textual>=0.40  for interactive process picker
- loguru>=0.7    for structured logging


## Installation
```bash
git clone --depth 1 https://github.com/lof310/tracso
cd tracso
pip install .
```

## Output
The default output is a report with four sections:

Notable
    Up to four observations derived from the graph. Examples: a library
    loaded directly by more than one source module; a package whose
    transitive footprint exceeds 30% of the total; orphan libraries with
    no source and no parent.

Heaviest packages
    Source modules ranked by total bytes of reachable shared libraries.
    Each row shows the package name, aggregate size, a bar scaled to the
    total, the percentage of total bytes, and the number of libraries
    attributed to the package.

Most depended-on libraries
    Shared libraries ranked by in-degree, then by size. Each row shows
    the library name, size, a bar scaled to the maximum in-degree in the
    table, the in-degree, and the number of source modules that load it.

Orphans
    Shared libraries with no source origin and no shared-library parent.
    These are libraries loaded at runtime by a mechanism the tracer
    cannot see (dlopen from C code, for example) or libraries whose
    loader has already exited.

## How it works

1. Read /proc/<pid>/maps to obtain the set of shared objects currently
   mapped by the process.

2. For each shared object, run `readelf -d` to extract its DT_NEEDED,
   DT_SONAME, DT_RPATH, and DT_RUNPATH entries. Resolve each DT_NEEDED
   entry to an absolute path using, in order: the parent's DT_RUNPATH
   with $ORIGIN expanded, the parent's DT_RPATH with $ORIGIN expanded,
   then the ldconfig cache. Recurse.

3. If the process is a Python interpreter, attach with gdb, acquire the
   GIL via PyGILState_Ensure, execute a script that serialises
   sys.modules to JSON, release the GIL, detach. This yields the
   mapping from Python module name to file path.

4. Join the two graphs: Python module -> shared object from step 3,
   shared object -> shared object from step 2. Shared objects that have
   no Python parent are attributed to the nearest shared-object ancestor
   that does.

5. Render according to the requested format.


## Attribution model

A shared object is attributed to its nearest source module. If a shared
object is loaded by two source modules (for example, libssl.so.3 loaded
by both _ssl and _hashlib), its size is divided equally between them for
the purpose of the "Heaviest packages" table. Transitive imports through
Python are not attributed: if module A imports module B and B owns a
shared object, that shared object is attributed to B, not to A.


## Limitations

Linux only. Uses /proc, readelf, and ldconfig.

Requires gdb for accurate Python attribution. Without gdb, or when gdb
is unavailable for the target, tracso falls back to deriving package
names from the shared object's filesystem path (site-packages,
dist-packages, lib/python, .egg). The fallback misses standard library
extension modules and extensions installed outside those directories.

Statically linked binaries and musl-linked Python have no shared-object
files to walk. tracso reports what it can see and stops.

## Development
```bash
git clone https://github.com/lof310/tracso
cd tracso
pip install -r requirements-dev.txt
```

Formatting
```bash
black ./tracso
isort ./tracso
```

## License

MIT. See [LICENSE](LICENSE.md).
