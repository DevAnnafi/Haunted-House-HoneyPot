# Product: Haunted House Honeypot

## What it is

An SSH honeypot that traps attackers in a fake, haunted Linux box. It looks like a real server at first. The longer an attacker stays, the stranger it gets: files change, output turns unsettling, and the system seems to notice them. Every action is recorded and mapped to MITRE ATT&CK techniques, shown live on a dashboard.

## Why it exists

- Most honeypots passively log attackers. This one actively wastes their time, which is a defensive goal in deception security.
- Built for the Kiroween 2026 hackathon (Frankenstein category): it stitches together an SSH server, a filesystem emulator, an LLM, and a threat-intel dashboard.

## Users

- **Attackers** (unwitting): bots and humans who find port 22.
- **Defender** (admin): watches sessions live and reviews tactics.
- **Judges**: can SSH in themselves to experience it.

## The demo moment

Someone types `ssh` into the box, starts poking around, and gets creeped out, while the dashboard lights up with their ATT&CK techniques in real time.

Every feature must serve this moment. Anything that doesn't waits until after the deadline.

## Goals

1. **SSH login:** Accept SSH connections and authenticate attackers into a simulated environment.
2. **Fake shell and filesystem:** Provide a believable Linux shell and filesystem, isolated per attacker. Each new session starts fresh in the MVP; attacker-specific state persistence is reserved for goal 7.
3. **Escalating haunting:** Increase the intensity of supernatural events based on session duration and attacker behavior.
4. **LLM fallback:** Generate believable, in-character responses for unsupported commands without executing them on the host.
5. **Session recording and ATT&CK mapping:** Record every session, including commands, timestamps, and outputs, and tag relevant behavior using rule-based MITRE ATT&CK mappings.
6. **Live dashboard:** Display active sessions, detected techniques, haunting levels, and recorded session replay.
7. **Persistent attacker sessions (stretch):** Recognize returning attackers by matching SSH username/password credentials, using source IP only as a secondary signal; preserve their simulated files, haunt level, and command history for 7 days after their last activity, with automatic expiration and strict isolation between attacker environments.

## Non-goals

- **No real shell:** No attacker command ever executes on the host.
- **No unrestricted outbound network access:** Only the configured LLM API may receive outbound requests.
- **No real file downloads:** When an attacker runs `wget` or `curl`, record the requested URL and simulate the output without fetching the resource.
- **No full Bash compatibility:** No scripting, loops, job control, or command substitution. Support basic commands and simple pipes only.
- **SSH only:** No Telnet, HTTP, FTP, or additional honeypot protocols.
- **No ML-based ATT&CK classifier:** Use explainable, testable rules for technique mapping. Machine learning may be considered after the hackathon.
- **No distributed deployment:** Support a single honeypot server, without multi-region infrastructure or distributed sensors.

## Hard constraints

- **Deadline:** December 4, 2026, 2:00 PM PT.
- All code must be written within the hackathon window.
- All attacker input is hostile and untrusted, including input passed to the LLM.
- Attacker commands must never execute on the host operating system.
- The simulated filesystem must remain separate from the host filesystem.
- Attacker-controlled content must never override system instructions, security constraints, or LLM behavior rules.
- The LLM API must receive only the minimum sanitized session context needed to generate a response.
- Outbound network access must be restricted to the configured LLM API.

## Tone of the haunting

**Slow-burn creepy:** The environment initially behaves like an ordinary Linux server. Subtle anomalies gradually appear: unexpected file changes, strange log entries, and messages that seem slightly out of place. As the attacker continues interacting, the system becomes increasingly aware of their presence and responds directly to their actions.

**Playful horror:** Use eerie humor, unsettling terminal messages, mysterious files, and supernatural behavior to create tension. The experience should feel like a haunted computer with a personality, avoiding gore, graphic violence, and excessive jump scares.

**Safety guardrail:** The haunting must never threaten attackers in real-world terms, claim to hack back, report them, expose their identity, or retaliate. Never use an attacker's real IP address or personal information to imply surveillance or physical danger. All frightening messages must remain clearly within the fictional haunted-server environment.