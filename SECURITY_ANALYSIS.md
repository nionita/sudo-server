# sudo-server Security Analysis

This document lists the currently unresolved security findings in the repo.
Issues already fixed in the codebase were removed from the previous list.

## 1. Response Files Leak Output Across Agents

**Severity:** High

Response files are stored under `/run/sudo-server/responses`, with the directory
owned by `root:sudo-agents` and mode `02750`. Individual response files are
written with mode `0640`.

Impact:
- Any user in the `sudo-agents` group can list response files in that directory.
- Any user in the `sudo-agents` group can read another agent's command output.
- Approved command output may contain secrets, credentials, package manager
  tokens, or other sensitive data that should only be visible to the requesting
  agent and the administrator.

Recommended fix:
- Stop using a group-readable shared response directory.
- Create response files with mode `0600` and transfer ownership to the
  requesting UID.
- Prefer a design that returns results over a per-request socket or another
  per-agent channel instead of filesystem polling.

## 2. Command Policy Is Too Coarse

**Severity:** Medium to High

The current policy model only allowlists executable names. That is a meaningful
improvement over unrestricted execution, but several allowed tools remain too
powerful to treat as single safe operations.

Examples:
- `pip` and `pip3` can execute arbitrary setup hooks or install attacker-chosen
  code.
- `npm` and `npx` can execute lifecycle scripts or fetch and run arbitrary code.
- `docker` and `docker-compose` can mount host paths, start privileged
  containers, or bypass intended host controls.
- `systemctl` grants a wide range of service-management actions rather than a
  narrow approved subset.

Impact:
- A compromised agent can submit a command that technically matches the binary
  allowlist but still performs broad root-level actions once approved.
- Human approval becomes the only meaningful control for these tools, which
  weakens the value of the allowlist.

Recommended fix:
- Replace raw executable allowlisting with operation-level policies.
- Implement server-owned wrappers or explicit schemas for sensitive operations,
  such as package install/update or service restart, with argument validation and
  allowlists for package names or service names.
- Remove interpreter-like and orchestration tools from example configs unless a
  narrower wrapper exists.

## 3. Telegram Output Mirroring Can Leak Sensitive Data

**Severity:** Medium

After command execution, the server posts a shortened copy of command output
back into Telegram. This can expose sensitive command results in the review chat.

Impact:
- Secrets printed by the approved command may be copied into Telegram.
- In group chats, every member can see the mirrored output even if only one
  approver is authorized to press buttons.
- Telegram message history becomes an additional storage location for privileged
  command output.

Recommended fix:
- Default to Telegram summaries that include only approval status and exit code.
- Make output mirroring opt-in, ideally per policy or per approved request.
- Avoid mirroring output for commands that can reasonably expose credentials,
  tokens, private file contents, or environment details.
