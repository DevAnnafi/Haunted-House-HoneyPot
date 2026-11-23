from collections.abc import Callable
from dataclasses import dataclass

from honeypot.commands.parser import ParseError, parse
from honeypot.vfs import Node, VirtualFS, normalize_path


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


@dataclass
class Context:
    vfs: VirtualFS
    cwd: str
    username: str
    hostname: str


Handler = Callable[[Context, list[str], str], CommandResult]


def home_dir(username: str) -> str:
    return "/root" if username == "root" else f"/home/{username}"


def cmd_pwd(ctx: Context, _args: list[str], _stdin: str) -> CommandResult:
    return CommandResult(stdout=f"{ctx.cwd}\n")


def cmd_whoami(ctx: Context, _args: list[str], _stdin: str) -> CommandResult:
    return CommandResult(stdout=f"{ctx.username}\n")


def cmd_echo(_ctx: Context, args: list[str], _stdin: str) -> CommandResult:
    return CommandResult(stdout=" ".join(args) + "\n")


def cmd_cd(ctx: Context, args: list[str], _stdin: str) -> CommandResult:
    target = args[0] if args else home_dir(ctx.username)

    node = ctx.vfs.resolve(ctx.cwd, target)
    if node is None:
        return CommandResult(
            stderr=f"-bash: cd: {target}: No such file or directory\n", exit_status=1
        )
    if node.kind != "dir":
        return CommandResult(stderr=f"-bash: cd: {target}: Not a directory\n", exit_status=1)

    ctx.cwd = normalize_path(ctx.cwd, target)
    return CommandResult()


KERNEL_RELEASE = "6.8.0-48-generic"
KERNEL_VERSION = "#48-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 14:04:52 UTC 2024"
MACHINE = "x86_64"


def _split_options(args: list[str]) -> tuple[set[str], list[str]]:
    # "-la" -> {"l", "a"}; everything else is an operand. "--" ends options.
    flags: set[str] = set()
    operands: list[str] = []
    options_done = False
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
        elif not options_done and arg.startswith("-") and len(arg) > 1:
            flags.update(arg[1:])
        else:
            operands.append(arg)
    return flags, operands


def cmd_hostname(ctx: Context, _args: list[str], _stdin: str) -> CommandResult:
    return CommandResult(stdout=f"{ctx.hostname}\n")


def cmd_cat(ctx: Context, args: list[str], stdin: str) -> CommandResult:
    if not args:
        return CommandResult(stdout=stdin)

    out: list[str] = []
    err: list[str] = []
    for arg in args:
        node = ctx.vfs.resolve(ctx.cwd, arg)
        if node is None:
            err.append(f"cat: {arg}: No such file or directory\n")
        elif node.kind == "dir":
            err.append(f"cat: {arg}: Is a directory\n")
        else:
            out.append(node.content)
    return CommandResult(stdout="".join(out), stderr="".join(err), exit_status=1 if err else 0)


def _lookup_ids(ctx: Context) -> tuple[int, int]:
    # Read uid and gid from the fake /etc/passwd, so id matches what cat shows.
    passwd = ctx.vfs.resolve("/", "/etc/passwd")
    if passwd is not None and passwd.kind == "file":
        for line in passwd.content.splitlines():
            fields = line.split(":")
            if len(fields) >= 4 and fields[0] == ctx.username:
                try:
                    return int(fields[2]), int(fields[3])
                except ValueError:
                    break
    return (0, 0) if ctx.username == "root" else (1001, 1001)


def cmd_id(ctx: Context, _args: list[str], _stdin: str) -> CommandResult:
    uid, gid = _lookup_ids(ctx)
    name = ctx.username
    group = "root" if gid == 0 else name
    return CommandResult(stdout=f"uid={uid}({name}) gid={gid}({group}) groups={gid}({group})\n")


def cmd_uname(ctx: Context, args: list[str], _stdin: str) -> CommandResult:
    flags, _ = _split_options(args)
    for flag in sorted(flags):
        if flag not in "asnrvm":
            return CommandResult(
                stderr=f"uname: invalid option -- '{flag}'\n"
                "Try 'uname --help' for more information.\n",
                exit_status=1,
            )
    values = {
        "s": "Linux",
        "n": ctx.hostname,
        "r": KERNEL_RELEASE,
        "v": KERNEL_VERSION,
        "m": MACHINE,
    }
    if "a" in flags:
        # -a also prints processor, hardware platform and operating system.
        parts = [values[key] for key in "snrvm"] + [MACHINE, MACHINE, "GNU/Linux"]
    else:
        # uname prints fields in this fixed order, whatever order the flags came in.
        parts = [values[key] for key in "snrvm" if key in flags] or ["Linux"]
    return CommandResult(stdout=" ".join(parts) + "\n")


def _mode_string(node: Node) -> str:
    # 0o755 on a directory -> "drwxr-xr-x"
    chars = ["d" if node.kind == "dir" else "-"]
    for shift in (6, 3, 0):
        bits = (node.mode >> shift) & 0o7
        chars.append("r" if bits & 4 else "-")
        chars.append("w" if bits & 2 else "-")
        chars.append("x" if bits & 1 else "-")
    return "".join(chars)


def _display_size(node: Node) -> int:
    if node.kind == "dir":
        return 4096
    if node.size is not None:
        return node.size
    return len(node.content.encode("utf-8", "surrogatepass"))


def _long_line(node: Node, name: str) -> str:
    links = 2 if node.kind == "dir" else 1
    t = node.mtime
    date = f"{t:%b} {t.day:>2} {t:%H:%M}"
    return (
        f"{_mode_string(node)} {links} {node.owner} {node.group} "
        f"{_display_size(node):>6} {date} {name}"
    )


def _list_dir(node: Node, flags: set[str]) -> list[tuple[str, Node]]:
    entries = [
        (name, child)
        for name, child in node.children.items()
        if "a" in flags or not name.startswith(".")
    ]
    # ls sorts ignoring a leading dot and letter case.
    entries.sort(key=lambda entry: entry[0].lstrip(".").lower())
    if "a" in flags:
        entries = [(".", node), ("..", node), *entries]
    return entries


def _format_entries(entries: list[tuple[str, Node]], flags: set[str], total: bool) -> str:
    if "l" in flags:
        lines = [_long_line(child, name) for name, child in entries]
        if total:
            blocks = sum(-(-_display_size(child) // 4096) * 4 for _, child in entries)
            lines.insert(0, f"total {blocks}")
        return "".join(line + "\n" for line in lines)
    if not entries:
        return ""
    return "  ".join(name for name, _ in entries) + "\n"


def cmd_ls(ctx: Context, args: list[str], _stdin: str) -> CommandResult:
    flags, operands = _split_options(args)
    for flag in sorted(flags):
        if flag not in "al":
            return CommandResult(
                stderr=f"ls: invalid option -- '{flag}'\nTry 'ls --help' for more information.\n",
                exit_status=2,
            )
    targets = operands or ["."]

    out: list[str] = []
    err: list[str] = []
    dirs: list[tuple[str, Node]] = []
    files: list[tuple[str, Node]] = []
    for target in targets:
        node = ctx.vfs.resolve(ctx.cwd, target)
        if node is None:
            err.append(f"ls: cannot access '{target}': No such file or directory\n")
        elif node.kind == "dir":
            dirs.append((target, node))
        else:
            files.append((target, node))

    # Like real ls: files named on the command line first, then each directory.
    if files:
        out.append(_format_entries(files, flags, total=False))
    for i, (target, node) in enumerate(dirs):
        if len(targets) > 1:
            if files or i > 0:
                out.append("\n")
            out.append(f"{target}:\n")
        out.append(_format_entries(_list_dir(node, flags), flags, total=True))

    return CommandResult(stdout="".join(out), stderr="".join(err), exit_status=2 if err else 0)


REGISTRY: dict[str, Handler] = {
    "pwd": cmd_pwd,
    "whoami": cmd_whoami,
    "echo": cmd_echo,
    "cd": cmd_cd,
    "cat": cmd_cat,
    "ls": cmd_ls,
    "id": cmd_id,
    "uname": cmd_uname,
    "hostname": cmd_hostname,
}


def execute(ctx: Context, line: str) -> CommandResult:
    result = parse(line)
    if isinstance(result, ParseError):
        return CommandResult(stderr=result.message + "\n", exit_status=2)

    # Until T2.2 adds VFS writes, every redirection fails like a read-only target.
    if result.redirect is not None:
        return CommandResult(
            stderr=f"-bash: {result.redirect.target}: Permission denied\n",
            exit_status=1,
        )

    stdin = ""
    last = CommandResult()
    for stage in result.stages:
        handler = REGISTRY.get(stage.name)
        if handler is None:
            last = CommandResult(
                stderr=f"-bash: {stage.name}: command not found\n", exit_status=127
            )
        else:
            last = handler(ctx, stage.args, stdin)
        stdin = last.stdout  # this stage's output feeds the next stage

    return last
