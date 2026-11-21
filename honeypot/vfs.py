import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from honeypot.auth import ConfigurationError


@dataclass
class Node:
    name: str
    kind: str
    mode: int
    owner: str
    group: str
    mtime: datetime
    content: str = ""
    size: int | None = None
    children: dict[str, "Node"] = field(default_factory=dict)


def normalize_path(cwd: str, path: str) -> str:
    stack = []

    if path.startswith("/"):
        full = path
    else:
        full = cwd + "/" + path

    parts = full.split("/")

    for part in parts:
        if part == "" or part == ".":
            continue
        elif part == "..":
            if stack:
                stack.pop()
        else:
            stack.append(part)

    return "/" + "/".join(stack)


class VirtualFS:
    def __init__(self, root: Node) -> None:
        self.root = root

    def resolve(self, cwd: str, path: str) -> Node | None:
        normalized = normalize_path(cwd, path)
        if normalized == "/":
            return self.root

        current = self.root
        for name in normalized[1:].split("/"):
            if current.kind != "dir":
                return None
            child = current.children.get(name)
            if child is None:
                return None
            current = child
        return current


def load_template(path: Path) -> Node:
    with path.open("rb") as f:
        data = tomllib.load(f)

    root = Node("", "dir", 0o755, "root", "root", datetime(2024, 1, 1, tzinfo=UTC))
    vfs = VirtualFS(root)
    root_seen = False

    for entry in sorted(data["node"], key=lambda node: node.get("path", "").count("/")):
        try:
            node_path = entry["path"]
            if normalize_path("/", node_path) != node_path:
                raise ConfigurationError(f"Invalid template path: {node_path}")

            kind = entry["type"]
            if kind not in ("file", "dir"):
                raise ConfigurationError(f"Invalid node type: {kind}")

            mode = int(entry["mode"], 8)
            if not 0 <= mode <= 0o7777:
                raise ConfigurationError(f"Mode out of range for: {node_path}")

            mtime = datetime.fromisoformat(entry["mtime"])
            if mtime.tzinfo is None:
                raise ConfigurationError(f"Timezone missing for: {node_path}")

            owner = entry["owner"]
            group = entry["group"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Invalid template entry {entry.get('path', '<unknown>')}: {exc}"
            ) from None

        # The "/" entry describes the root itself: update it instead of attaching.
        if node_path == "/":
            if root_seen:
                raise ConfigurationError("Duplicate path: /")
            if kind != "dir":
                raise ConfigurationError("Root must be a directory")
            root.mode, root.owner, root.group, root.mtime = mode, owner, group, mtime
            root_seen = True
            continue

        parent_path, _, name = node_path.rpartition("/")
        parent = vfs.resolve("/", parent_path or "/")
        if parent is None or parent.kind != "dir":
            raise ConfigurationError(f"Missing or invalid parent: {parent_path or '/'}")
        if name in parent.children:
            raise ConfigurationError(f"Duplicate path: {node_path}")

        parent.children[name] = Node(
            name,
            kind,
            mode,
            owner,
            group,
            mtime,
            content=entry.get("content", ""),
            size=entry.get("size"),
        )

    return root
