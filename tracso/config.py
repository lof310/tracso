"""Options and constants"""

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Options:
    """Runtime options collected from CLI arguments."""

    depth: int = 8
    color: str = "auto"
    name_depth: int = 2
    verbose: bool = False

    ldmap: dict = field(default_factory=dict)
    path_by_name: dict = field(default_factory=dict)
    elf_cache: dict = field(default_factory=dict)

    target_label: str = ""
    interp: dict = field(default_factory=dict)

    py_imports: dict = field(default_factory=lambda: defaultdict(set))
    all_py_names: set = field(default_factory=set)
    baseline: set = field(default_factory=set)


ELF_TIMEOUT = 10
GDB_TIMEOUT = 15
PROC_POLLS = 15
PROC_POLL_INTERVAL = 0.05
