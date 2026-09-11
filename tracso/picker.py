"""Interactive process picker

Modes, in order of preference:
    textual - full TUI, requires the `textual` package
    curses  - stdlib fallback
    plain   - numbered list, works under pipes and in CI
"""

import os
import sys
from dataclasses import dataclass

from .utils import fmt_size

# |---------------------------------|
# |======> /proc enumeration <======|
# |---------------------------------|


@dataclass
class ProcInfo:
    pid: int
    name: str
    cmdline: str
    rss_kb: int
    is_python: bool


def _read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        if not raw:
            return ""
        return " ".join(p.decode(errors="replace") for p in raw.split(b"\0") if p)
    except OSError:
        return ""


def _read_status(pid):
    name = ""
    rss = 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Name:"):
                    name = line[5:].strip()
                elif line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            rss = int(parts[1])
                        except ValueError:
                            pass
    except OSError:
        pass
    return name, rss


def _exe_basename(pid):
    try:
        return os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        return ""


def _looks_python(cmdline, exe):
    b = exe.lower()
    if (
        b == "python"
        or b.startswith("python3")
        or b.startswith("python2")
        or "pypy" in b
    ):
        return True
    c = cmdline.lower()
    return "python" in c or "pypy" in c


def list_processes(only_python=True):
    """Enumerate /proc and return ProcInfo list sorted by RSS descending."""
    procs = []
    me = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return procs

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        cmdline = _read_cmdline(pid)
        name, rss = _read_status(pid)
        exe = _exe_basename(pid)
        py = _looks_python(cmdline, exe)
        if only_python and not py:
            continue
        display = cmdline or name or exe or f"pid {pid}"
        procs.append(ProcInfo(pid, name or exe or "?", display, rss, py))

    procs.sort(key=lambda p: (-p.rss_kb, p.pid))
    return procs


# |------------------------------|
# |======> Textual picker <======|
# |------------------------------|


def _pick_textual(procs, prompt):
    from textual.app import App
    from textual.binding import Binding
    from textual.widgets import DataTable, Footer, Input, Static

    class PickerApp(App):
        CSS = """
        Screen { layout: vertical; }
        #prompt { padding: 0 1; height: 1; }
        #filter { height: 3; }
        DataTable { height: 1fr; }
        """

        BINDINGS = [
            Binding("slash", "focus_filter", "Filter", show=True),
            Binding("escape", "cancel", "Cancel", show=True, priority=True),
        ]

        def __init__(self, procs, prompt):
            super().__init__()
            self._procs = procs
            self._prompt = prompt
            self.picked = None

        def compose(self):
            yield Static(self._prompt, id="prompt")
            yield Input(placeholder="Filter by pid, name, or command…", id="filter")
            yield DataTable(id="table")
            yield Footer()

        def on_mount(self):
            table = self.query_one(DataTable)
            table.cursor_type = "row"
            self._rebuild("")
            table.focus()

        def action_focus_filter(self):
            self.query_one(Input).focus()

        def action_cancel(self):
            self.picked = None
            self.exit()

        def on_input_changed(self, event):
            self._rebuild(event.value)

        def on_input_submitted(self, event):
            self.query_one(DataTable).focus()

        def _rebuild(self, filt):
            table = self.query_one(DataTable)
            table.clear(columns=True)
            table.add_columns("PID", "NAME", "RSS", "CMD")
            f = (filt or "").strip().lower()
            for p in self._procs:
                hay = f"{p.pid} {p.name} {p.cmdline}".lower()
                if f and f not in hay:
                    continue
                table.add_row(
                    str(p.pid),
                    p.name,
                    fmt_size(p.rss_kb * 1024),
                    p.cmdline,
                    key=str(p.pid),
                )

        def on_data_table_row_selected(self, event):
            key = getattr(event.row_key, "value", event.row_key)
            try:
                self.picked = int(key)
            except (TypeError, ValueError):
                self.picked = None
            self.exit()

    app = PickerApp(procs, prompt)
    app.run()
    return app.picked


# |-----------------------------|
# |======> curses picker <======|
# |-----------------------------|


def _pick_curses(procs, prompt):
    import curses

    def _run(stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        cursor = 0
        filt = ""

        while True:
            f = filt.lower()
            matches = [
                p
                for p in procs
                if not f or f in f"{p.pid} {p.name} {p.cmdline}".lower()
            ]
            if cursor >= len(matches):
                cursor = max(0, len(matches) - 1)

            h, w = stdscr.getmaxyx()
            stdscr.erase()
            stdscr.addnstr(0, 0, prompt, w - 1, curses.A_BOLD)
            stdscr.addnstr(
                1,
                0,
                f"filter: {filt}   (Enter=select  Esc=cancel  ^U=clear)",
                w - 1,
                curses.A_DIM,
            )

            visible = matches[cursor : cursor + max(1, h - 3)]
            for i, p in enumerate(visible):
                line = (
                    f"{p.pid:>7}  {p.name:<16}  "
                    f"{fmt_size(p.rss_kb * 1024):>9}  {p.cmdline}"
                )
                attr = curses.A_REVERSE if i == 0 else curses.A_NORMAL
                stdscr.addnstr(3 + i, 0, line, w - 1, attr)
            stdscr.refresh()

            c = stdscr.getch()
            if c in (27, ord("q")):
                return None
            if c in (curses.KEY_ENTER, 10, 13):
                return matches[cursor].pid if matches else None
            if c == curses.KEY_UP:
                if cursor > 0:
                    cursor -= 1
            elif c == curses.KEY_DOWN:
                if cursor + 1 < len(matches):
                    cursor += 1
            elif c == 21:  # Ctrl-U
                filt = ""
                cursor = 0
            elif c in (curses.KEY_BACKSPACE, 127, 8):
                filt = filt[:-1]
                cursor = 0
            elif 32 <= c < 127:
                filt += chr(c)
                cursor = 0

    return curses.wrapper(_run)


# |----------------------------|
# |======> plain picker <======|
# |----------------------------|


def _pick_plain(procs, prompt):
    if not procs:
        return None
    sys.stderr.write(f"{prompt}\n")
    for i, p in enumerate(procs):
        sys.stderr.write(
            f"  {i:>3}  {p.pid:>7}  {p.name:<16}  "
            f"{fmt_size(p.rss_kb * 1024):>9}  {p.cmdline}\n"
        )
    sys.stderr.write("Pick a pid or list index: ")
    sys.stderr.flush()
    try:
        raw = sys.stdin.readline().strip()
    except KeyboardInterrupt:
        return None
    if not raw:
        return None
    if raw.isdigit():
        n = int(raw)
        for p in procs:
            if p.pid == n:
                return p.pid
        if 0 <= n < len(procs):
            return procs[n].pid
    return None


# |--------------------------|
# |======> dispatcher <======|
# |--------------------------|


def _detect_mode(force=None):
    if force:
        return force
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "plain"
    try:
        import textual  # noqa: F401

        return "textual"
    except ImportError:
        pass
    try:
        import curses  # noqa: F401

        return "curses"
    except ImportError:
        return "plain"


def pick_process(procs=None, prompt="Select a process to trace", force=None):
    """Return a pid chosen by the user, or None on cancel."""
    if procs is None:
        procs = list_processes(only_python=False)
    if not procs:
        return None

    mode = _detect_mode(force)

    if mode == "textual":
        try:
            return _pick_textual(procs, prompt)
        except Exception:
            # textual raised at import or during run; fall through.
            pass

    if mode in ("textual", "curses"):
        try:
            return _pick_curses(procs, prompt)
        except Exception:
            pass

    return _pick_plain(procs, prompt)
