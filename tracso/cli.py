"""Command-Line Interface (CLI)"""

import os
import sys

from . import __version__, logger
from .config import Options
from .tracer import (analyze, render_why, run_spawn, trace_pid, walk_so,
                     write_output)
from .utils import ldconfig_map


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="tracso",
        description="Trace shared-object origins of a running process.",
    )
    parser.add_argument("target", nargs="?", help="PID or library path")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument(
        "--run",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="run command and trace it",
    )
    parser.add_argument("--why", metavar="SONAME", help="trace origin of a library")
    parser.add_argument(
        "--pick", action="store_true", help="interactively pick a process to trace"
    )
    parser.add_argument(
        "--pick-py", action="store_true", help="Pick only python processes"
    )
    parser.add_argument(
        "--pick-mode",
        choices=["textual", "curses", "plain"],
        help="force a picker backend",
    )
    parser.add_argument("--tree", action="store_true", help="tree output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--csv", action="store_true", help="CSV output")
    parser.add_argument(
        "--depth", type=int, default=8, help="max .so depth (default 8)"
    )
    parser.add_argument(
        "--name-depth",
        type=int,
        default=2,
        metavar="N",
        help="python module name depth; 0=full (default 2)",
    )
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="log injection decisions to stderr"
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _trace_lib(path, opts):
    opts.target_label = os.path.basename(path)
    edges, dashed, cycles, seen = set(), set(), set(), set()
    walk_so(path, opts, seen, edges, dashed, cycles, set(), 0)
    return edges, dashed, cycles


def _trace_pid(pid, opts):
    edges, dashed, cycles, seen = set(), set(), set(), set()
    trace_pid(pid, opts, seen, edges, dashed, cycles)
    return edges, dashed, cycles


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.pick_py:
        args.pick = True
    if args.pick_mode:
        args.pick = True

    if args.depth < 0:
        parser.error("--depth must be >= 0")
    if args.name_depth < 0:
        parser.error("--name-depth must be >= 0")

    if args.why and (args.json or args.csv or args.tree):
        parser.error("--why cannot be combined with --json, --csv, or --tree")

    opts = Options(
        depth=args.depth,
        color=args.color,
        name_depth=args.name_depth,
        verbose=args.verbose,
    )
    opts.ldmap = ldconfig_map()

    try:
        if args.run is not None:
            cmd = list(args.run)
            if cmd and cmd[0] == "--":
                cmd = cmd[1:]
            if not cmd:
                parser.error("--run requires a command")
            edges, dashed, cycles = run_spawn(cmd, opts)
        elif args.pick:
            from .picker import list_processes, pick_process

            procs = list_processes(only_python=args.pick_py)
            if not procs:
                return logger.error("no matching processes")
            pid = pick_process(procs, force=args.pick_mode)
            if pid is None:
                return 130
            edges, dashed, cycles = _trace_pid(str(pid), opts)
        elif args.target:
            if args.target.isdecimal():
                if not os.path.exists(f"/proc/{args.target}"):
                    logger.error("no such process")
                    return 1
                edges, dashed, cycles = _trace_pid(args.target, opts)
            else:
                path = os.path.realpath(args.target)
                if os.path.isdir(path):
                    logger.error(f"{path}: is a directory")
                    return 1
                if not os.path.isfile(path):
                    logger.error(f"{path}: not found")
                    return 1
                edges, dashed, cycles = _trace_lib(path, opts)
        else:
            parser.error("target required (or can use --pick/--run)")

    except FileNotFoundError as exc:
        name = exc.filename or (args.run[0] if args.run else args.target or "?")
        logger.error(f"command not found: {name}")
        return 1
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        logger.exception("Unexpected Error: ", exc)
        return 1

    metrics = analyze(edges, opts)

    if args.why:
        try:
            stream = (
                sys.stdout
                if not args.output or args.output == "-"
                else open(args.output, "w")
            )
        except OSError as exc:
            logger.error(str(exc))
            return 1
        try:
            return render_why(args.why, edges, metrics, opts, stream)
        finally:
            if stream is not sys.stdout:
                stream.close()

    return write_output(args, opts, edges, dashed, cycles, metrics)
