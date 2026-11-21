from dataclasses import dataclass, field
from datetime import datetime


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
