"""Tests for honeypot/vfs.py: normalize_path, Node, VirtualFS.resolve (R2.12)."""

import copy
import tomllib
from datetime import datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from honeypot.auth import ConfigurationError
from honeypot.vfs import Node, VirtualFS, load_template, normalize_path

SEGMENTS = st.one_of(
    st.sampled_from(["..", ".", "", "root", "a b", "\\", "a\\b", "é", "日本語", "👻"]),
    st.text(max_size=8).filter(lambda s: "/" not in s),
)
SEPARATORS = st.sampled_from(["/", "//"])


@st.composite
def paths(draw: st.DrawFn) -> str:
    segs = draw(st.lists(SEGMENTS, max_size=12))
    out = draw(st.sampled_from(["", "/"]))
    for seg in segs:
        out += seg + draw(SEPARATORS)
    return out


cwds = paths()


def _segments(result: str) -> list[str]:
    return [] if result == "/" else result[1:].split("/")


# --- R2.12 [PBT] ---------------------------------------------------------


@given(cwd=cwds, path=paths())
def test_r2_12_result_starts_with_slash(cwd: str, path: str) -> None:
    assert normalize_path(cwd, path).startswith("/")


@given(cwd=cwds, path=paths())
def test_r2_12_result_has_no_double_slash(cwd: str, path: str) -> None:
    assert "//" not in normalize_path(cwd, path)


@given(cwd=cwds, path=paths())
def test_r2_12_paths_never_escape_vfs(cwd: str, path: str) -> None:
    result = normalize_path(cwd, path)
    segs = _segments(result)
    assert "." not in segs
    assert ".." not in segs
    assert "" not in segs


@given(cwd=cwds, path=paths())
def test_r2_12_normalize_is_idempotent(cwd: str, path: str) -> None:
    once = normalize_path(cwd, path)
    assert normalize_path("/", once) == once
    assert normalize_path(cwd, once) == once


@given(
    cwd=cwds,
    ups=st.integers(min_value=1, max_value=30),
    rest=st.lists(st.sampled_from(["etc", "a b", "é", "\\"]), max_size=4),
)
def test_r2_12_leading_dotdot_never_above_root(cwd: str, ups: int, rest: list[str]) -> None:
    # Enough leading ".." from root-anchored cwd: result is just the rest.
    path = "/".join([".."] * ups + rest)
    result = normalize_path("/", path)
    assert result == "/" + "/".join(rest)
    # With any cwd, an absolute path prefixed by ".." stays at or below root.
    abs_result = normalize_path(cwd, "/" + path)
    assert abs_result == "/" + "/".join(rest)


@given(cwd=cwds, path=paths())
def test_r2_12_dotdot_prefix_from_any_cwd_stays_in_root(cwd: str, path: str) -> None:
    result = normalize_path(cwd, "/".join([".."] * 100) + "/" + path)
    assert result.startswith("/")
    assert ".." not in _segments(result)


# --- Example table -------------------------------------------------------


@pytest.mark.parametrize(
    ("cwd", "path", "expected"),
    [
        ("/root", "notes.txt", "/root/notes.txt"),
        ("/root", "../etc//passwd", "/etc/passwd"),
        ("/", "../../../etc", "/etc"),
        ("/home/deploy", "./.ssh/./", "/home/deploy/.ssh"),
        ("/etc", "/", "/"),
        ("/", "..", "/"),
    ],
)
def test_r2_12_normalize_examples(cwd: str, path: str, expected: str) -> None:
    assert normalize_path(cwd, path) == expected


def test_r2_12_backslash_is_ordinary_character() -> None:
    assert normalize_path("/", "a\\b") == "/a\\b"
    assert normalize_path("/", "..\\etc") == "/..\\etc"
    assert normalize_path("/root", "a\\..\\b") == "/root/a\\..\\b"
    assert normalize_path("/", "\\") == "/\\"


# --- Node ----------------------------------------------------------------


def _node(name: str, kind: str, **kw: object) -> Node:
    return Node(
        name=name,
        kind=kind,
        mode=0o755 if kind == "dir" else 0o644,
        owner="root",
        group="root",
        mtime=datetime(2026, 1, 1),
        **kw,  # type: ignore[arg-type]
    )


def test_node_children_not_shared_between_instances() -> None:
    a = _node("a", "dir")
    b = _node("b", "dir")
    assert a.children is not b.children
    a.children["x"] = _node("x", "file")
    assert b.children == {}


# --- VirtualFS.resolve ---------------------------------------------------


@pytest.fixture
def fs() -> VirtualFS:
    root = _node("", "dir")
    etc = _node("etc", "dir")
    passwd = _node("passwd", "file", content="root:x:0:0\n")
    home = _node("home", "dir")
    deploy = _node("deploy", "dir")
    notes = _node("notes.txt", "file", content="hi")
    etc.children["passwd"] = passwd
    deploy.children["notes.txt"] = notes
    home.children["deploy"] = deploy
    root.children["etc"] = etc
    root.children["home"] = home
    return VirtualFS(root)


def test_resolve_root(fs: VirtualFS) -> None:
    assert fs.resolve("/", "/") is fs.root
    assert fs.resolve("/etc", "/") is fs.root
    assert fs.resolve("/home/deploy", "../..") is fs.root


def test_resolve_absolute(fs: VirtualFS) -> None:
    node = fs.resolve("/home", "/etc/passwd")
    assert node is not None
    assert node.name == "passwd"


def test_resolve_relative(fs: VirtualFS) -> None:
    node = fs.resolve("/home/deploy", "notes.txt")
    assert node is not None
    assert node.name == "notes.txt"
    node = fs.resolve("/home/deploy", "../../etc/./passwd")
    assert node is not None
    assert node.name == "passwd"


def test_resolve_dir_with_trailing_slash(fs: VirtualFS) -> None:
    node = fs.resolve("/", "etc//")
    assert node is not None
    assert node.name == "etc"


def test_resolve_dotdot_above_root(fs: VirtualFS) -> None:
    node = fs.resolve("/", "../../../etc")
    assert node is not None
    assert node.name == "etc"
    assert fs.resolve("/", "../../..") is fs.root


def test_resolve_through_file_is_none(fs: VirtualFS) -> None:
    assert fs.resolve("/", "/etc/passwd/x") is None
    assert fs.resolve("/etc", "passwd/..x/y") is None


def test_resolve_missing_is_none(fs: VirtualFS) -> None:
    assert fs.resolve("/", "/nope") is None
    assert fs.resolve("/etc", "shadow") is None
    assert fs.resolve("/", "/home/nobody/notes.txt") is None


def test_resolve_backslash_is_not_separator(fs: VirtualFS) -> None:
    assert fs.resolve("/", "etc\\passwd") is None


# --- load_template -------------------------------------------------------

REAL_TEMPLATE = Path(__file__).resolve().parent.parent / "config" / "fs_template.toml"

ROOT_ENTRY = (
    '[[node]]\npath = "/"\ntype = "dir"\nmode = "0755"\n'
    'owner = "root"\ngroup = "root"\nmtime = "2026-03-12T09:41:07Z"\n'
)


def _entry(
    path: str = "/etc",
    type_: str = "dir",
    mode: str = '"0755"',
    mtime: str = '"2026-03-12T09:41:07Z"',
    owner: str | None = '"root"',
) -> str:
    """One [[node]] table; values are raw TOML so tests can pass bad types."""
    lines = ["[[node]]", f'path = "{path}"', f'type = "{type_}"']
    if mode is not None:
        lines.append(f"mode = {mode}")
    lines.append(f"mtime = {mtime}")
    if owner is not None:
        lines.append(f"owner = {owner}")
    lines.append('group = "root"')
    return "\n".join(lines) + "\n"


def _write(tmp_path: Path, *entries: str) -> Path:
    f = tmp_path / "t.toml"
    f.write_text("\n".join(entries), encoding="utf-8")
    return f


def _count(node: Node) -> int:
    return 1 + sum(_count(c) for c in node.children.values())


def test_load_template_real_file_loads_and_counts_match() -> None:
    with REAL_TEMPLATE.open("rb") as f:
        expected = len(tomllib.load(f)["node"])
    root = load_template(REAL_TEMPLATE)
    assert root.kind == "dir"
    assert _count(root) == expected


def test_load_template_small_tree_resolves(tmp_path: Path) -> None:
    f = _write(
        tmp_path,
        _entry("/etc"),
        _entry("/etc/passwd", "file"),
    )
    root = load_template(f)
    node = VirtualFS(root).resolve("/", "/etc/passwd")
    assert node is not None
    assert node.kind == "file"
    assert _count(root) == 3


def test_load_template_root_entry_updates_root_metadata(tmp_path: Path) -> None:
    f = _write(
        tmp_path,
        '[[node]]\npath = "/"\ntype = "dir"\nmode = "0700"\n'
        'owner = "ghost"\ngroup = "wheel"\nmtime = "2020-05-06T07:08:09Z"\n',
        _entry("/etc"),
    )
    root = load_template(f)
    assert root.mode == 0o700
    assert root.owner == "ghost"
    assert root.group == "wheel"
    assert root.mtime == datetime.fromisoformat("2020-05-06T07:08:09+00:00")
    assert list(root.children) == ["etc"]


def test_load_template_second_root_entry_rejected(tmp_path: Path) -> None:
    f = _write(tmp_path, ROOT_ENTRY, ROOT_ENTRY)
    with pytest.raises(ConfigurationError):
        load_template(f)


BAD_TEMPLATES = {
    "missing_parent": [_entry("/a/b")],
    "parent_is_file": [_entry("/f", "file"), _entry("/f/x", "file")],
    "duplicate_path": [_entry("/etc"), _entry("/etc")],
    "dotdot_path": [_entry("/etc"), _entry("/etc/../x")],
    "relative_path": [_entry("etc/x")],
    "trailing_slash": [_entry("/etc/")],
    "unknown_type": [_entry("/etc", "symlink")],
    "non_octal_mode": [_entry("/etc", mode='"0899"')],
    "numeric_mode": [_entry("/etc", mode="644")],
    "negative_mode": [_entry("/etc", mode='"-644"')],
    "mode_above_7777": [_entry("/etc", mode='"10000"')],
    "mtime_without_tz": [_entry("/etc", mtime='"2026-03-12T09:41:07"')],
    "invalid_mtime": [_entry("/etc", mtime='"not a date"')],
    "missing_owner": [_entry("/etc", owner=None)],
}


@pytest.mark.parametrize("entries", BAD_TEMPLATES.values(), ids=BAD_TEMPLATES.keys())
def test_load_template_rejects_bad_entry(tmp_path: Path, entries: list[str]) -> None:
    with pytest.raises(ConfigurationError):
        load_template(_write(tmp_path, *entries))


def test_r2_10_deepcopies_of_loaded_root_share_no_nodes() -> None:
    root = load_template(REAL_TEMPLATE)
    a = copy.deepcopy(root)
    b = copy.deepcopy(root)

    def ids(n: Node) -> set[int]:
        out = {id(n)}
        for c in n.children.values():
            out |= ids(c)
        return out

    assert ids(a).isdisjoint(ids(b))
    assert ids(a).isdisjoint(ids(root))

    before = copy.deepcopy(b)
    a.mode = 0o000
    a.children["etc"].children.clear()
    a.children["tmp"].children["new"] = Node("new", "file", 0o644, "root", "root", a.mtime)
    assert b == before
    assert root.mode != 0o000
    assert "new" not in root.children["tmp"].children
