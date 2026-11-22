from collections.abc import Callable
from dataclasses import dataclass

from honeypot.commands.parser import ParseError, parse
from honeypot.vfs import VirtualFS, normalize_path


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


def cmd_pwd(ctx: Context, args: list[str], stdin: str) -> CommandResult:
    return CommandResult(stdout=f"{ctx.cwd}\n")


def cmd_whoami(ctx: Context, args: list[str], stdin: str) -> CommandResult:
    return CommandResult(stdout=f"{ctx.username}\n")


def cmd_echo(ctx: Context, args: list[str], stdin: str) -> CommandResult:
    return CommandResult(stdout=" ".join(args) + "\n")


def cmd_cd(ctx: Context, args: list[str], _stdin: str) -> CommandResult:
    home = "/root" if ctx.username == "root" else f"/home/{ctx.username}"
    target = args[0] if args else home

    node = ctx.vfs.resolve(ctx.cwd, target)
    if node is None:
        return CommandResult(
            stderr=f"-bash: cd: {target}: No such file or directory\n", exit_status=1
        )
    if node.kind != "dir":
        return CommandResult(stderr=f"-bash: cd: {target}: Not a directory\n", exit_status=1)

    ctx.cwd = normalize_path(ctx.cwd, target)
    return CommandResult()


REGISTRY: dict[str, Handler] = {
    "pwd": cmd_pwd,
    "whoami": cmd_whoami,
    "echo": cmd_echo,
    "cd": cmd_cd,
}


def execute(ctx: Context, line: str) -> CommandResult:
    result = parse(line)

    if isinstance(result, ParseError):
        return CommandResult(stderr=result.message + "\n", exit_status=2)

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
