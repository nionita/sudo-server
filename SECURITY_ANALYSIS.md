# sudo-server — Security & Code Quality Analysis

## Architecture Summary

The system has two components:
1. **sudo-server.py** — a root daemon that listens on a Unix socket, forwards execution requests to Telegram for human approval, and executes approved commands.
2. **sudoreq** — an unprivileged client that sends requests via the Unix socket and polls a response file for the result.

Communication flow: `agent → Unix socket → server → Telegram → human → server → execute → response file → agent`

---

## 🔴 Critical Security Issues

### 1. Arbitrary File Write via `response_path` (RCE potential)

**Severity: CRITICAL** — The attacker-controlled `response_path` field is passed to `_write_response()` which writes arbitrary JSON to any file the root process can access.

The server **trusts the client** to provide `response_path` and writes to it as root without any validation:

```python
# sudo-server.py line 317-326
def _write_response(path: str, data: dict):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)
```

A malicious agent user (any member of `sudo-agents` group) can set `response_path` to:
- `/etc/crontab` — overwrite cron with JSON that cron will error on, causing DoS
- `/etc/passwd` — destroy authentication
- `/root/.ssh/authorized_keys` — while the JSON payload isn't valid SSH key format, the `.tmp` write + rename is still a destructive overwrite
- Any file on the system — the server runs as root with `ReadWritePaths=/`

Even for a **denied** or **expired** request, the server still writes to `response_path`. **No approval is needed for the file write — only for command execution.**

**Fix:** Validate `response_path` is under a designated temp directory (e.g., `/tmp/sudo-server-responses/`), and that the filename matches an expected pattern. Better yet, have the server create the response file itself.

---

### 2. Response File Race Condition (TOCTOU — Symlink Attack)

**Severity: CRITICAL** — The response temp directory is world-writable with sticky bit (`0o1777`), but the response file itself is created by the client and then written to by root.

In `sudoreq` (line 131-137):
```python
tmp_dir = Path(tempfile.gettempdir()) / "sudo-server-responses"
tmp_dir.mkdir(mode=0o1777, exist_ok=True)  # world-writable
resp_file = str(tmp_dir / f"resp-{os.getpid()}-{int(time.time())}.json")
Path(resp_file).touch(mode=0o600)
os.chmod(resp_file, 0o622)
```

Attack: Between the client creating the file and the server writing to it, a local attacker (another member of `sudo-agents` or even the agent itself) can:
1. Delete the response file
2. Create a **symlink** at the same path → pointing to `/etc/shadow`, `/etc/sudoers`, etc.
3. Root's `_write_response()` follows the symlink and overwrites the target

This is a classic TOCTOU symlink race. The `0o1777` sticky bit on the directory only prevents deletion of files by *other* users, but the *same* user (the agent who created the file) can freely replace their own file with a symlink.

**Fix:** Use `O_NOFOLLOW` when opening for write, or write to a directory only root can access (e.g., `/run/sudo-server/responses/`) and let the client read from there.

---

### 3. Allowlist Bypass via Path Manipulation

**Severity: HIGH** — The allowlist checks `os.path.basename(argv[0])` but the server executes the **full** `argv[0]`.

```python
base_cmd = os.path.basename(argv[0])  # line 248
# ... check base_cmd against allowlist ...

# But execution uses the full argv:
actual_argv = req.argv  # line 285
```

An agent can bypass the allowlist by:
- `argv = ["/home/evil/my-script-named-apt-get", "--malicious-flag"]`
- `basename` → `"apt-get"` → passes allowlist
- Executes `/home/evil/my-script-named-apt-get` as root

Even simpler: `argv = ["./apt-get"]` resolves relative to `cwd`, which is also client-controlled.

**Fix:** Resolve `argv[0]` to its canonical absolute path using `shutil.which()` or `os.path.realpath()` and check the basename of the *resolved* path. Better yet, check against full canonical paths in the allowlist.

---

### 4. No Authentication of the Agent User Identity

**Severity: HIGH** — The `agent_user` field is **self-reported** by the client. The server never verifies it.

Any user in the `sudo-agents` group can claim to be any other agent user:
```python
# sudoreq line 141
agent_user = getpass.getuser()    # client-side only

# sudo-server.py trusts this blindly:
agent_user = payload["agent_user"]   # line 247
```

This defeats per-agent allowlists entirely. Agent A (allowed only `apt-get`) can forge `agent_user` as Agent B (allowed `systemctl`) to escape their restrictions.

**Fix:** Use `SO_PEERCRED` on the Unix socket to obtain the client's actual UID from the kernel, then resolve the username server-side. This is un-forgeable.

---

## 🟠 Medium Security Issues

### 5. No Telegram User Authorization

The server verifies the callback comes from the correct **chat** but not from an authorized **user**:

```python
# line 490-496: checks chat ID only
cq_chat = str(cq.get("message", {}).get("chat", {}).get("id", ""))
if cq_chat != chat_id:
    continue
```

If the Telegram bot is in a **group chat**, any member of that group can approve/deny commands. There's no allowlist of Telegram user IDs authorized to make approval decisions.

**Fix:** Add an `authorized_telegram_users` config field (list of Telegram user IDs) and check `cq["from"]["id"]` against it.

---

### 6. HTML Injection in Telegram Messages

The command `argv`, `agent_user`, `cwd`, `run_as`, and command output are embedded directly into HTML Telegram messages without escaping:

```python
# line 425-433
cmd_display = " ".join(req.argv)
text = (
    f"<b>Sudo request</b>\n"
    f"Agent: <code>{req.agent_user}</code>\n"
    ...
    f"Command:\n<pre>{cmd_display}</pre>\n"
```

A malicious agent can craft `argv` containing HTML tags (e.g., `<b>Approve immediately</b>` or inject misleading display text like making a dangerous command look benign). While Telegram's HTML parser is limited, it can still break formatting and create social engineering opportunities.

**Fix:** Escape `<`, `>`, `&` in all user-controlled strings before embedding in HTML messages. Use `html.escape()`.

---

### 7. Unbounded Request Accumulation (DoS)

The `RequestStore` has no maximum size. An attacker with socket access can flood the server with thousands of requests, each consuming memory and generating a Telegram message.

**Fix:** Add a per-user limit on concurrent pending requests and a global cap.

---

### 8. `run_as` Not Validated

The `run_as` field is client-controlled and never validated on the server side. An agent can request `run_as: "root"` regardless of what makes sense for their use case. While this goes through Telegram approval, the approval prompt might not make the significance clear enough.

---

### 9. `cwd` Not Validated

The server falls back to `/` if `cwd` is not a directory (line 295), but doesn't check for path traversal or whether the agent should have access to that directory. Combined with the allowlist bypass (issue 3), a crafted `cwd` can be used to resolve relative command paths to attacker-controlled directories.

---

## 🟡 Low Security Issues

### 10. Token Entropy Is Adequate but Short

`secrets.token_hex(8)` = 16 hex chars = 64 bits of entropy. This is sufficient for short-lived tokens (300s TTL), but given the system's sensitivity, 128-bit tokens (`token_hex(16)`) would be more standard and cost-free.

### 11. Log Files Lack Integrity Protection

Audit logs are plain append-only text files. A compromised system could have its audit trail tampered with. Consider writing to syslog as well (which is already partially done via journald) or using append-only file attributes.

### 12. No Rate Limiting on Socket Connections

No throttling on incoming Unix socket connections. A local user in `sudo-agents` could saturate the server's event loop.

### 13. Telegram Bot Token in Memory

The bot token persists in process memory. If `/proc/<pid>/environ` is readable (it is to root), the token is exposed. This is inherent to the architecture and not easily fixable.

---

## ⚪ Non-Security Bugs and Code Quality Issues

### 14. **Systemd Hardening Contradiction**

```ini
ProtectSystem=strict
ReadWritePaths=/var/log/sudo-server /run/sudo-server /tmp/sudo-server-responses
ReadWritePaths=/          # ← THIS OVERRIDES EVERYTHING ABOVE
```

The second `ReadWritePaths=/` completely negates `ProtectSystem=strict`, making it as if the hardening doesn't exist. The comment says "Allow executing system commands" but `ReadWritePaths` controls write access, not execute access. Execution is controlled by `NoExecPaths` / file permissions.

**Fix:** Remove `ReadWritePaths=/`. If commands need write access to specific paths, enumerate them explicitly. The first `ReadWritePaths` line plus paths needed by specific commands should be sufficient.

---

### 15. **Lambda Late-Binding Bug in Loops**

Multiple lambdas in the poller loop capture variables by reference (`cq_id`, `req`, `from_user`, `req_token`). In some execution paths within the `for update in data["result"]` loop, if the loop iterates fast enough before executors run, lambdas may see the wrong values. In practice this is mitigated by `await` on each executor call, but it's a latent bug.

**Fix:** Use `functools.partial` instead of lambdas, or capture values explicitly: `lambda cq_id=cq_id: ...`.

---

### 16. **Inconsistent argv Display**

Line 542 uses double-space join: `'  '.join(req.argv)` while line 425 and 573 use single-space `' '.join(req.argv)`. This is cosmetic but inconsistent.

### 17. **Config File Permissions Not Checked**

The server doesn't verify that `/etc/sudo-server/config.json` has restrictive permissions. If it contains the Telegram token (possible per the config example), a world-readable config leaks the bot token.

### 18. **No Graceful Shutdown of Pending Requests**

When the server shuts down (SIGTERM), pending requests are abandoned — their response files are never written to. The clients will time out after `--wait` seconds, but a graceful shutdown should write `{"status": "error", "message": "Server shutting down"}` to all pending response files.

### 19. **`reader.read(4096)` May Truncate**

Line 342: `reader.read(4096)` — if a request payload is larger than 4096 bytes (e.g., very long `argv`), it gets silently truncated, potentially producing invalid JSON. This is unlikely but possible.

**Fix:** Read in a loop until EOF or use `reader.readuntil()` with a max size.

---

## Summary Severity Matrix

| # | Issue | Severity | Exploitable Without Approval? |
|---|-------|----------|-------------------------------|
| 1 | Arbitrary file write via `response_path` | 🔴 CRITICAL | ✅ Yes |
| 2 | Symlink race on response file | 🔴 CRITICAL | ✅ Yes |
| 3 | Allowlist bypass via path manipulation | 🔴 HIGH → CRITICAL with #4 | Needs approval but misleading |
| 4 | Agent user identity not verified | 🔴 HIGH | ✅ Yes (forge identity) |
| 5 | No Telegram user authorization | 🟠 MEDIUM | Group member can approve |
| 6 | HTML injection in Telegram | 🟠 MEDIUM | ✅ Yes (social engineering) |
| 7 | Unbounded request accumulation | 🟠 MEDIUM | ✅ Yes (DoS) |
| 8 | `run_as` not validated | 🟠 MEDIUM | Needs approval |
| 9 | `cwd` not validated | 🟠 MEDIUM | Enables #3 |
| 14 | systemd hardening negated | ⚪ CONFIG BUG | N/A |
| 15 | Lambda late-binding | ⚪ CODE BUG | N/A |

**Issues #1 and #2 are exploitable by any user in `sudo-agents` without needing Telegram approval.** They can write arbitrary data to arbitrary files as root, just by connecting to the socket. This is the most urgent thing to fix.
