"""Tests for the cat, ls, id, uname and hostname commands in honeypot/commands/engine.py.

R2.1 (supported commands) and R2.5 (Linux-compatible errors). Every test runs against the real
fake-filesystem template, config/fs_template.toml, so the expected strings below are the
contents of that template. Commands are run through execute(), the same entry point the shell
uses, with a fresh Context per call.
"""

from pathlib import Path

import pytest

from honeypot.commands.engine import CommandResult, Context, execute
from honeypot.vfs import VirtualFS, load_template

HOSTNAME = "web-prod-01"
BASE_ROOT = load_template(Path("config/fs_template.toml"))

HOSTNAME_FILE = "web-prod-01\n"  # /etc/hostname
ISSUE_FILE = "Ubuntu 24.04.1 LTS \\n \\l\n\n"  # /etc/issue
UNAME_RELEASE = "6.8.0-48-generic"
UNAME_VERSION = "#48-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 14:04:52 UTC 2024"
UNAME_ALL = f"Linux {HOSTNAME} {UNAME_RELEASE} {UNAME_VERSION} x86_64 x86_64 x86_64 GNU/Linux\n"


def run(line: str, user: str = "root", cwd: str | None = None) -> CommandResult:
    """Run one command line in a fresh session. cwd defaults to the user's home."""
    if cwd is None:
        cwd = "/root" if user == "root" else f"/home/{user}"
    ctx = Context(vfs=VirtualFS(BASE_ROOT), cwd=cwd, username=user, hostname=HOSTNAME)
    return execute(ctx, line)


def ok(stdout: str) -> CommandResult:
    return CommandResult(stdout=stdout, stderr="", exit_status=0)


def fail(stderr: str, exit_status: int, stdout: str = "") -> CommandResult:
    return CommandResult(stdout=stdout, stderr=stderr, exit_status=exit_status)


# ---------------------------------------------------------------------------
# cat
# ---------------------------------------------------------------------------


def test_r2_1_cat_one_file() -> None:
    assert run("cat /etc/hostname") == ok(HOSTNAME_FILE)


def test_r2_1_cat_several_files_concatenates_in_order() -> None:
    assert run("cat /etc/hostname /etc/issue") == ok(HOSTNAME_FILE + ISSUE_FILE)
    assert run("cat /etc/issue /etc/hostname") == ok(ISSUE_FILE + HOSTNAME_FILE)


def test_r2_1_cat_relative_path_uses_cwd() -> None:
    assert run("cat hostname", cwd="/etc") == ok(HOSTNAME_FILE)
    assert run("cat ../etc/hostname", cwd="/home") == ok(HOSTNAME_FILE)


def test_r2_5_cat_missing_file() -> None:
    assert run("cat /nope") == fail("cat: /nope: No such file or directory\n", 1)


def test_r2_5_cat_missing_relative_file_names_the_argument_as_typed() -> None:
    assert run("cat missing.txt", cwd="/etc") == fail(
        "cat: missing.txt: No such file or directory\n", 1
    )


def test_r2_5_cat_directory() -> None:
    assert run("cat /etc") == fail("cat: /etc: Is a directory\n", 1)


def test_r2_5_cat_error_in_the_middle_does_not_stop_the_rest() -> None:
    result = run("cat /etc/hostname /nope /etc/issue")
    assert result == fail(
        "cat: /nope: No such file or directory\n",
        1,
        stdout=HOSTNAME_FILE + ISSUE_FILE,
    )


def test_r2_5_cat_reports_every_error_in_argument_order() -> None:
    result = run("cat /nope /etc /etc/hostname /nope2")
    assert result == fail(
        "cat: /nope: No such file or directory\n"
        "cat: /etc: Is a directory\n"
        "cat: /nope2: No such file or directory\n",
        1,
        stdout=HOSTNAME_FILE,
    )


def test_r2_6_cat_without_arguments_copies_stdin() -> None:
    assert run("echo hi | cat") == ok("hi\n")
    assert run("cat /etc/hostname | cat") == ok(HOSTNAME_FILE)


def test_r2_6_cat_with_arguments_ignores_stdin() -> None:
    assert run("echo hi | cat /etc/hostname") == ok(HOSTNAME_FILE)


def test_r2_6_cat_without_arguments_and_without_stdin_prints_nothing() -> None:
    assert run("cat") == ok("")


def test_r2_6_cat_dash_alone_copies_piped_input() -> None:
    assert run("echo hi | cat -") == ok("hi\n")


def test_r2_6_cat_dash_without_piped_input_prints_nothing() -> None:
    assert run("cat -") == ok("")


def test_r2_6_cat_dash_between_files_inserts_stdin_at_that_position() -> None:
    assert run("echo hi | cat /etc/hostname - /etc/issue") == ok(
        HOSTNAME_FILE + "hi\n" + ISSUE_FILE
    )


def test_r2_6_cat_dash_first_and_last() -> None:
    assert run("echo hi | cat - /etc/hostname") == ok("hi\n" + HOSTNAME_FILE)
    assert run("echo hi | cat /etc/hostname -") == ok(HOSTNAME_FILE + "hi\n")


def test_r2_6_cat_dash_without_piped_input_between_files_adds_nothing() -> None:
    assert run("cat /etc/hostname - /etc/issue") == ok(HOSTNAME_FILE + ISSUE_FILE)


def test_r2_5_cat_dash_does_not_hide_errors_in_other_arguments() -> None:
    assert run("echo hi | cat /nope - /etc") == fail(
        "cat: /nope: No such file or directory\ncat: /etc: Is a directory\n",
        1,
        stdout="hi\n",
    )


# ---------------------------------------------------------------------------
# ls: plain listing and hidden files
# ---------------------------------------------------------------------------


def test_r2_1_ls_hides_dotfiles_by_default() -> None:
    assert run("ls", user="deploy") == ok("app  notes.txt\n")


def test_r2_1_ls_of_a_directory_with_only_hidden_files_prints_nothing() -> None:
    assert run("ls", user="root") == ok("")


def test_r2_1_ls_a_shows_dotfiles_dot_and_dotdot_sorted_ignoring_leading_dot() -> None:
    assert run("ls -a", user="deploy") == ok(
        ".  ..  app  .bash_history  .bash_logout  .bashrc  notes.txt  .profile  .ssh\n"
    )
    assert run("ls -a", user="root") == ok(".  ..  .bash_history  .bashrc  .profile  .ssh\n")


def test_r2_1_ls_lists_the_named_directory() -> None:
    assert run("ls /etc/ssh") == ok("sshd_config  sshd_config.d\n")
    assert run("ls ssh", cwd="/etc") == ok("sshd_config  sshd_config.d\n")


def test_r2_1_ls_a_on_a_named_directory() -> None:
    assert run("ls -a /home") == ok(".  ..  deploy\n")


def test_r2_6_ls_output_can_be_piped() -> None:
    assert run("ls /home | cat") == ok("deploy\n")


# ---------------------------------------------------------------------------
# ls -l, -la, -al
# ---------------------------------------------------------------------------


def test_r2_1_ls_l_has_total_line_and_one_line_per_entry() -> None:
    assert run("ls -l", user="deploy") == ok(
        "total 8\n"
        "drwxr-xr-x 2 deploy deploy   4096 Oct 21 13:09 app\n"
        "-rw-r--r-- 1 deploy deploy    268 Oct 28 09:47 notes.txt\n"
    )


def test_r2_1_ls_l_of_a_directory_with_only_hidden_files_is_total_zero() -> None:
    assert run("ls -l", user="root") == ok("total 0\n")


def test_r2_1_ls_l_on_a_named_directory() -> None:
    assert run("ls -l /home") == ok(
        "total 4\ndrwxr-x--- 2 deploy deploy   4096 Nov 14 17:36 deploy\n"
    )


DEPLOY_LA_ENTRIES = [
    "drwxr-xr-x 2 deploy deploy   4096 Oct 21 13:09 app",
    "-rw------- 1 deploy deploy    146 Nov 14 17:36 .bash_history",
    "-rw-r--r-- 1 deploy deploy    220 Mar 12 09:58 .bash_logout",
    "-rw-r--r-- 1 deploy deploy    307 Mar 12 09:58 .bashrc",
    "-rw-r--r-- 1 deploy deploy    268 Oct 28 09:47 notes.txt",
    "-rw-r--r-- 1 deploy deploy    233 Mar 12 09:58 .profile",
    "drwx------ 2 deploy deploy   4096 May  7 10:12 .ssh",
]


@pytest.mark.parametrize("line", ["ls -la", "ls -al", "ls -l -a", "ls -a -l", "ls -lal"])
def test_r2_1_ls_la_and_al_are_the_same_listing(line: str) -> None:
    result = run(line, user="deploy")
    assert result.stderr == ""
    assert result.exit_status == 0
    lines = result.stdout.splitlines()
    # 9 entries (".", "..", and 7 files) at 4 blocks each.
    assert lines[0] == "total 36"
    assert lines[1] == "drwxr-x--- 2 deploy deploy   4096 Nov 14 17:36 ."
    assert lines[2].startswith("d")
    assert lines[2].endswith(" ..")
    assert lines[3:] == DEPLOY_LA_ENTRIES
    assert result.stdout.endswith("\n")


def test_r2_1_ls_la_and_al_give_identical_output() -> None:
    assert run("ls -la", user="deploy") == run("ls -al", user="deploy")
    assert run("ls -la /home") == run("ls -al /home")


def test_r2_1_ls_la_on_a_named_directory() -> None:
    result = run("ls -la /home")
    lines = result.stdout.splitlines()
    assert lines[0] == "total 12"
    assert lines[1] == "drwxr-xr-x 2 root root   4096 Mar 12 09:58 ."
    assert lines[2].endswith(" ..")
    assert lines[3] == "drwxr-x--- 2 deploy deploy   4096 Nov 14 17:36 deploy"
    assert len(lines) == 4


# ---------------------------------------------------------------------------
# ls: file arguments, several arguments, headers
# ---------------------------------------------------------------------------


def test_r2_1_ls_file_argument_prints_the_name_as_typed() -> None:
    assert run("ls /etc/hostname") == ok("/etc/hostname\n")
    assert run("ls hostname", cwd="/etc") == ok("hostname\n")


def test_r2_1_ls_l_file_argument_has_no_total_line() -> None:
    assert run("ls -l /etc/hostname") == ok(
        "-rw-r--r-- 1 root root     12 Mar 12 09:44 /etc/hostname\n"
    )


def test_r2_1_ls_several_directories_get_headers_and_blank_line_between() -> None:
    assert run("ls /home /etc/ssh") == ok(
        "/home:\ndeploy\n\n/etc/ssh:\nsshd_config  sshd_config.d\n"
    )


def test_r2_1_ls_l_several_directories_each_have_header_and_total() -> None:
    assert run("ls -l /home /etc/ssh") == ok(
        "/home:\n"
        "total 4\n"
        "drwxr-x--- 2 deploy deploy   4096 Nov 14 17:36 deploy\n"
        "\n"
        "/etc/ssh:\n"
        "total 8\n"
        "-rw-r--r-- 1 root root    627 Mar 12 09:52 sshd_config\n"
        "drwxr-xr-x 2 root root   4096 Mar 12 09:41 sshd_config.d\n"
    )


def test_r2_1_ls_files_come_before_directories() -> None:
    assert run("ls /home /etc/hostname") == ok("/etc/hostname\n\n/home:\ndeploy\n")


def test_r2_1_ls_a_single_directory_argument_has_no_header() -> None:
    assert run("ls /home") == ok("deploy\n")


# ---------------------------------------------------------------------------
# ls: errors
# ---------------------------------------------------------------------------


def test_r2_5_ls_missing_path_exits_2() -> None:
    assert run("ls /nope") == fail("ls: cannot access '/nope': No such file or directory\n", 2)


def test_r2_5_ls_every_missing_path_is_reported_in_order() -> None:
    assert run("ls /nope /nope2") == fail(
        "ls: cannot access '/nope': No such file or directory\n"
        "ls: cannot access '/nope2': No such file or directory\n",
        2,
    )


def test_r2_5_ls_missing_path_does_not_stop_the_valid_ones() -> None:
    assert run("ls /nope /home") == fail(
        "ls: cannot access '/nope': No such file or directory\n",
        2,
        stdout="/home:\ndeploy\n",
    )


def test_r2_5_ls_invalid_option_exits_2() -> None:
    assert run("ls -x") == fail(
        "ls: invalid option -- 'x'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_invalid_option_among_valid_ones_prints_no_listing() -> None:
    assert run("ls -lx /etc") == fail(
        "ls: invalid option -- 'x'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_invalid_option_is_reported_even_with_a_missing_path() -> None:
    assert run("ls -x /nope") == fail(
        "ls: invalid option -- 'x'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_long_invalid_option_names_the_option() -> None:
    assert run("ls --invalid-option") == fail(
        "ls: unrecognized option '--invalid-option'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_short_invalid_options_report_the_first_one_typed() -> None:
    assert run("ls -z -y") == fail(
        "ls: invalid option -- 'z'\nTry 'ls --help' for more information.\n", 2
    )
    assert run("ls -yz") == fail(
        "ls: invalid option -- 'y'\nTry 'ls --help' for more information.\n", 2
    )
    assert run("ls -a -y -l -z") == fail(
        "ls: invalid option -- 'y'\nTry 'ls --help' for more information.\n", 2
    )


@pytest.mark.parametrize("line", ["ls -x --y", "ls --y -x", "ls -lx --y /nope"])
def test_r2_5_ls_long_invalid_option_is_reported_over_short_ones(line: str) -> None:
    assert run(line) == fail(
        "ls: unrecognized option '--y'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_first_long_invalid_option_is_reported() -> None:
    assert run("ls --x --y") == fail(
        "ls: unrecognized option '--x'\nTry 'ls --help' for more information.\n", 2
    )


def test_r2_5_ls_double_dash_ends_option_parsing() -> None:
    assert run("ls -- /home") == ok("deploy\n")


def test_r2_5_ls_after_double_dash_a_dash_word_is_a_path() -> None:
    assert run("ls -- -l") == fail("ls: cannot access '-l': No such file or directory\n", 2)


def test_r2_5_ls_after_double_dash_an_invalid_looking_option_is_a_path() -> None:
    assert run("ls -a -- -x") == fail("ls: cannot access '-x': No such file or directory\n", 2)


# ---------------------------------------------------------------------------
# id
# ---------------------------------------------------------------------------


def test_r2_1_id_root() -> None:
    assert run("id", user="root") == ok("uid=0(root) gid=0(root) groups=0(root)\n")


def test_r2_1_id_deploy_reads_uid_1000_from_etc_passwd() -> None:
    assert run("id", user="deploy") == ok("uid=1000(deploy) gid=1000(deploy) groups=1000(deploy)\n")


def test_r2_1_id_user_not_in_passwd_gets_uid_1001() -> None:
    assert run("id", user="mallory") == ok(
        "uid=1001(mallory) gid=1001(mallory) groups=1001(mallory)\n"
    )


def test_r2_1_id_matches_the_passwd_file_cat_shows() -> None:
    passwd_lines = run("cat /etc/passwd").stdout.splitlines()
    assert passwd_lines[-1].startswith("deploy:x:1000:1000:")


# ---------------------------------------------------------------------------
# uname
# ---------------------------------------------------------------------------


def test_r2_1_uname_without_flags_prints_the_kernel_name() -> None:
    assert run("uname") == ok("Linux\n")


def test_r2_1_uname_a_prints_everything() -> None:
    assert run("uname -a") == ok(UNAME_ALL)


def test_r2_1_uname_a_wins_over_other_flags() -> None:
    assert run("uname -a -s") == ok(UNAME_ALL)


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("-s", "Linux\n"),
        ("-n", f"{HOSTNAME}\n"),
        ("-r", f"{UNAME_RELEASE}\n"),
        ("-v", f"{UNAME_VERSION}\n"),
        ("-m", "x86_64\n"),
    ],
)
def test_r2_1_uname_single_flags(flag: str, expected: str) -> None:
    assert run(f"uname {flag}") == ok(expected)


def test_r2_1_uname_sr_and_rs_print_in_the_same_fixed_order() -> None:
    assert run("uname -sr") == ok(f"Linux {UNAME_RELEASE}\n")
    assert run("uname -rs") == ok(f"Linux {UNAME_RELEASE}\n")
    assert run("uname -r -s") == ok(f"Linux {UNAME_RELEASE}\n")


def test_r2_1_uname_uses_the_session_hostname() -> None:
    ctx = Context(vfs=VirtualFS(BASE_ROOT), cwd="/", username="root", hostname="other-host")
    assert execute(ctx, "uname -n") == ok("other-host\n")


def test_r2_5_uname_invalid_option_exits_1() -> None:
    assert run("uname -x") == fail(
        "uname: invalid option -- 'x'\nTry 'uname --help' for more information.\n", 1
    )


def test_r2_5_uname_long_invalid_option_exits_1() -> None:
    assert run("uname --x") == fail(
        "uname: unrecognized option '--x'\nTry 'uname --help' for more information.\n", 1
    )


def test_r2_5_uname_help_is_an_unrecognized_option() -> None:
    assert run("uname --help") == fail(
        "uname: unrecognized option '--help'\nTry 'uname --help' for more information.\n", 1
    )


def test_r2_5_uname_short_invalid_options_report_the_first_one_typed() -> None:
    assert run("uname -z -y") == fail(
        "uname: invalid option -- 'z'\nTry 'uname --help' for more information.\n", 1
    )
    assert run("uname -yz") == fail(
        "uname: invalid option -- 'y'\nTry 'uname --help' for more information.\n", 1
    )


@pytest.mark.parametrize("line", ["uname -x --y", "uname --y -x", "uname -sx --y"])
def test_r2_5_uname_long_invalid_option_is_reported_over_short_ones(line: str) -> None:
    assert run(line) == fail(
        "uname: unrecognized option '--y'\nTry 'uname --help' for more information.\n", 1
    )


def test_r2_5_uname_invalid_option_among_valid_ones_prints_nothing_else() -> None:
    assert run("uname -sx") == fail(
        "uname: invalid option -- 'x'\nTry 'uname --help' for more information.\n", 1
    )


def test_r2_5_uname_double_dash_ends_options() -> None:
    assert run("uname --") == ok("Linux\n")


# ---------------------------------------------------------------------------
# hostname
# ---------------------------------------------------------------------------


def test_r2_1_hostname_prints_the_session_hostname() -> None:
    assert run("hostname") == ok(f"{HOSTNAME}\n")


def test_r2_1_hostname_matches_etc_hostname() -> None:
    assert run("hostname").stdout == run("cat /etc/hostname").stdout


def test_r2_1_hostname_uses_the_context_value() -> None:
    ctx = Context(vfs=VirtualFS(BASE_ROOT), cwd="/", username="root", hostname="other-host")
    assert execute(ctx, "hostname") == ok("other-host\n")
