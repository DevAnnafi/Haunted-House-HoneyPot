# Development Log — Haunted House Honeypot

## November 4, 2026 — Project Setup

### Completed
- Created the GitHub repository for Haunted House Honeypot.
- Selected the project concept for the Kiroween 2026 hackathon.
- Created the initial architecture diagram showing the SSH server, simulated shell, haunting engine, LLM fallback, session recording, MITRE ATT&CK mapping, and live dashboard.
- Began organizing the project around Kiro's specification-driven development workflow.

### Status
Project initialized and initial architecture diagram created. Implementation not yet started.

---

## November 5, 2026 — Product Requirements and Security Planning

### Completed
- Defined the product vision, target users, demo experience, and seven product goals.
- Established the MVP boundary around SSH emulation, escalating haunting, LLM fallback, session recording, MITRE ATT&CK mapping, and the live dashboard.
- Moved persistent attacker environments into a stretch goal.
- Established security constraints for command execution, filesystem isolation, outbound traffic, and untrusted LLM input.
- Defined the haunting's slow-burn progression, playful horror style, and prohibition on real-world threats or retaliation.
- Created the Kiro steering documentation, including `.kiro/steering/product.md`.
- Finalized `requirements.md`, covering R1–R8 with EARS acceptance criteria, MoSCoW priorities, and verification checklists.
- Identified property-based testing candidates for filesystem limits, path traversal, haunting progression, and output sanitization.
- Added requirements for read-only judge access, session recording, SSH abuse prevention, and resource limits.
- Reviewed and corrected the requirements before beginning the detailed engineering design.

### Design decisions
- Fresh simulated environments for each session in the MVP.
- Seven-day attacker state retention proposed for the persistence stretch goal.
- Attacker identity matching remains unresolved. Common SSH credentials cannot safely identify a unique attacker.
- SSH forwarding, SFTP, SCP, and other potentially dangerous SSH features will be rejected.
- Passwords will not be stored in plaintext; keyed HMAC fingerprints will be used for correlation.
- The honeypot will run without root privileges and will never execute attacker commands on the host.
- The MVP will prioritize Must requirements. Optional features will be implemented only if time permits.
- Kiro will assist with specifications, implementation, and tests, while architectural and security decisions remain subject to human review.

### Challenges / Open questions
- **Attacker identity:** Bots frequently reuse the same default SSH credentials. Using credentials alone to identify returning attackers could incorrectly merge unrelated sessions.
- **Realistic shell behavior:** The simulated environment needs believable Linux commands and error messages without allowing actual host execution.
- **Project scope:** The original feature set was too large for the hackathon timeline, requiring clear Must, Should, and Could priorities.
- **Persistent environments:** A reliable identity-matching strategy must be documented before implementing the stretch goal.

### Lessons / surprises
- **Credential collisions:** Multiple attackers can use identical usernames and passwords. I learned that credentials are useful telemetry but are not reliable proof of identity.
- **SSH forwarding:** Allowing forwarding could turn the honeypot into an open proxy. I had to consider SSH features beyond interactive command execution.
- **Stored XSS:** Attackers control the text recorded by the honeypot. That text could target the administrator's browser if the dashboard renders it unsafely.
- **Kiro workflow:** The hackathon evaluates how Kiro contributes to development. I need to document where Kiro helped and where I made, reviewed, or changed decisions myself.

### Next steps
1. Write **ADR-0001** to select the programming language and SSH server library.
2. Write **ADR-0002** to document the password HMAC strategy and credential-handling tradeoffs.
3. Create `design.md`, defining component responsibilities, interfaces, data models, security boundaries, and deployment architecture.
4. Create `tasks.md` from the approved requirements and design, prioritizing Must requirements.
5. Begin implementing the SSH honeypot MVP, starting with simulated authentication, shell interaction, and session recording.

### Status
Product requirements and engineering acceptance criteria finalized. Initial architecture diagram completed. Detailed system design and implementation are next. No functional implementation or tests completed yet.