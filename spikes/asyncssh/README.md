# AsyncSSH Spike

Throwaway spike to validate [ADR-0001](../../docs/adr/0001-language-and-ssh-library.md)
before marking it Accepted. Not production code.

- **Library:** asyncssh 2.24.1
- **Python:** 3.12+
- **Platform tested:** Windows (PowerShell), OpenSSH client
- **Listen address:** 127.0.0.1:2222 (local only)

## How to run

```bash
python spikes/asyncssh/spike_server.py
# in a second terminal:
ssh -p 2222 ghost@localhost
```

## Results

| # | Check | Result | Date |
|---|---|---|---|
| 1 | OpenSSH client connects | Pass | 2026-11-05 |
| 2 | Auth attempts logged, accepted/rejected by app | Pass |2026-11-05 |
| 3 | Custom banner advertised | Pass| 2026-11-06|
| 4 | Agent, port (-L/-R/-D), X11 forwarding and SFTP rejected |  Pass |2026-11-06 |
| 5 | Host key stable across restarts | Pass |2026-11-05 |
| 6 | Hypothesis test runs alongside asyncio | Pass | |

## Check details

### 1. OpenSSH client connects 
- **Test:** `ssh -p 2222 ghost@localhost` with the correct password, then with a wrong password.
- **Result:** The correct password received `hello` and the connection closed. Wrong passwords
  were rejected with `Permission denied`.
  
### 2. Auth attempts logged 
- **Test:** One connection with the correct password, one with wrong passwords.
- **Result:** Each attempt logged as `AUTH SUCCESS|FAILED ip=<ip> username=<repr>`.
  Passwords are never logged. 6 `FAILED` lines for 6 wrong guesses.

### 3. Custom banner advertised 
- **Test:** `ssh -v -p 2222 ghost@localhost` before and after setting `server_version`.
- **Before:** `remote software version AsyncSSH_2.24.1`
- **After:** `remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`

### 4. Forwarding and SFTP rejected 
| Feature | Client saw | Server logged |
|---|---|---|
| `-L` | `open failed: connect failed` | `FORWARD DENIED type=local dest='example.com':80` |
| `-D` | `open failed: connect failed` | `FORWARD DENIED type=local dest='104.20.23.154':80` |
| `-R` | `remote port forwarding failed for listen port 9090` | `FORWARD DENIED type=remote listen='localhost':9090` |
| SFTP | `subsystem request failed on channel 0` | (refused by `sftp_factory=None`) |
| Agent / X11 | Not sent by the Windows client | Verified by configuration (see Findings) |

### 5. Host key stable across restarts 
- **Test:** Restarted the server and reconnected with the same client.
- **Result:** No "host identification has changed" warning; the key loaded from file persisted.

### 6. Hypothesis test runs alongside asyncio 
- **Tests:** `pytest spikes/asyncssh/test_spike.py -v` → 2 passed.
  - `test_auth_log_is_single_safe_line` (Hypothesis): for any generated username and
    success flag, the auth log line contains no `\n`, `\r`, or raw `\x1b`, and starts
    with `AUTH <SUCCESS|FAILED> `.
  - `test_exec_request_end_to_end` (pytest-asyncio): starts the server on port 0,
    connects with the asyncssh client, runs `uname -a` via exec, and asserts output
    and exit status 0.
- **Finding:** The first test run caught a bug: the extracted formatter still referenced
  `self.client_ip`. Hypothesis shrank the failure to `username=''`.

### Extra: interactive shell and exec requests 
- **Test:** Interactive session (echo loop, `exit`, Ctrl+D, terminal resize) and
  `ssh -p 2222 ghost@localhost "uname -a"`.
- **Result:** All four behaved correctly. Exec requests are distinguished by
  `process.command` being a string rather than `None`.

## Findings
- asyncssh offers both **keyboard-interactive** and **password** auth, and routes both into
  `validate_password`. The OpenSSH client tried 3 times with each, so one connection got
  6 password attempts. The real build must count failures per connection across both methods
  (R8.7) and record the method used (R1.5).
- Resizing the client terminal (Windows OpenSSH) raises `asyncssh.TerminalSizeChanged` while reading stdin. The handler must catch it inside the read loop and continue; catching it outside the loop ends the session on every resize. The real shell needs the same pattern.
- Agent / X11: Verified by configuration (`agent_forwarding=False`, `x11_forwarding=False`). The Windows client could not issue the requests (no ssh-agent running; DISPLAY not set). Re-test from a Linux client before production (tracked in requirements verification).
- **Exit realism:** Typing `exit` closed the session without a newline, so the client's
  next output ran onto the prompt line (`exitdebug1: ...`). Fixed by writing `logout\n`
  before closing, matching real bash.
- **Banner is not the only fingerprint:** With `server_version` set, the advertised
  version reads `OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`, but `ssh -v` still exposes asyncssh:
  - an unrecognised `global-requests-ok` extension
  - a `server-sig-algs` list containing algorithms real OpenSSH 9.6 does not advertise
    (`@ssh.com` variants, `ssh-ed448`, `ssh-dss`, `ecdsa-sha2-1.3.132.0.10`)
  - auth methods `keyboard-interactive,password` instead of Ubuntu's typical
    `publickey,password`
  Tools like ssh-audit could use these to identify the honeypot. Candidate v1.0
  **Should** item: restrict advertised algorithms to match OpenSSH 9.6 and offer
  public-key auth that always fails.
- **Forwarding refusal message:** Denied `-L`/`-D` requests return
  `connect failed: Connection refused`. Real OpenSSH with forwarding disabled typically
  returns "administratively prohibited." Minor believability gap to review in v1.0.
- **IPv6:** The client tries `::1` first and is refused because the spike listens on
  `127.0.0.1` only. The production design must decide whether the honeypot also
  listens on IPv6.