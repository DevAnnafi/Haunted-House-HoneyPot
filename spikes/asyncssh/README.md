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
| 2 | Auth attempts logged, accepted/rejected by app | Pass | |
| 3 | Custom banner advertised | Pass | |
| 4 | Agent, port (-L/-R/-D), X11 forwarding and SFTP rejected |  Pass | |
| 5 | Host key stable across restarts | Pass | |
| 6 | Hypothesis test runs alongside asyncio | Pending | |

## Check details

### 1. OpenSSH client connects 
- **Test:** `ssh -p 2222 ghost@localhost` with the correct password, then with a wrong password.
- **Result:** The correct password received `hello` and the connection closed. Wrong passwords
  were rejected with `Permission denied`.
  
### 2. Auth attempts logged ✅
- **Test:** One connection with the correct password, one with wrong passwords.
- **Result:** Each attempt logged as `AUTH SUCCESS|FAILED ip=<ip> username=<repr>`.
  Passwords are never logged. 6 `FAILED` lines for 6 wrong guesses.

### 5. Host key stable across restarts ✅
- **Test:** Restarted the server and reconnected with the same client.
- **Result:** No "host identification has changed" warning; the key loaded from file persisted.

### Extra: interactive shell and exec requests ✅
- **Test:** Interactive session (echo loop, `exit`, Ctrl+D, terminal resize) and
  `ssh -p 2222 ghost@localhost "uname -a"`.
- **Result:** All four behaved correctly. Exec requests are distinguished by
  `process.command` being a string rather than `None`.

## Findings

- asyncssh offers both **keyboard-interactive** and **password** auth, and routes both into
  `validate_password`. The OpenSSH client tried 3 times with each, so one connection got
  6 password attempts. The real build must count failures per connection across both methods
  (R8.7) and record the method used (R1.5).
- Resizing the client terminal (Windows OpenSSH) raises asyncssh.TerminalSizeChanged while reading stdin. The handler must catch it inside the read loop and continue; catching it outside the loop ends the session on every resize. The real shell needs the same pattern.
- Agent / X11: Verified by configuration (agent_forwarding=False, x11_forwarding=False). The Windows client could not issue the requests (no ssh-agent running; DISPLAY not set). Re-test from a Linux client before production (tracked in requirements verification).