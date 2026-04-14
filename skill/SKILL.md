---
name: sudo-request
description: Use when an agent running as an unprivileged Linux user needs to install a package, write a system file, change file ownership, restart a service, or execute any other command that requires root privileges. Explains how to use the sudoreq tool to request approval from the system owner via Telegram, wait for the response, and handle all outcomes (approved, denied, expired, error).
---

# Sudo Request Skill

## Overview

This server runs a **sudo-server** daemon. When you need to execute a command that requires root privileges, you cannot run it directly — instead you submit a request via the `sudoreq` tool. The system owner receives a Telegram message with Approve/Deny buttons. If approved, the command runs as root and its output is returned to you.

You do **not** have sudo rights. You **do** have access to `/usr/local/bin/sudoreq`.

---

## When to Use This Skill

Load this skill whenever you need to:

- Install a Linux package (`apt-get install ...`)
- Write or modify a system file owned by root
- Change ownership or permissions on system paths (`chown`, `chmod`)
- Restart or enable a systemd service (`systemctl restart ...`)
- Execute any command that fails with "Permission denied" due to missing privileges

---

## Basic Usage

```bash
sudoreq -- COMMAND [ARGS...]
```

The `--` separator is recommended to avoid argument ambiguity when the command has options of its own.

### Examples

```bash
# Install a package
sudoreq -- apt-get install -y ffmpeg

# Restart a service
sudoreq -- systemctl restart nginx

# Change ownership of a directory
sudoreq -- chown -R myuser:myuser /var/lib/myapp

# Read a root-owned config file
sudoreq -- cat /etc/some-protected-config

# Run command as a specific user (not root)
sudoreq --as www-data -- mkdir /var/www/html/uploads
```

---

## Options

| Option | Default | Description |
|---|---|---|
| `--as USER` | `root` | Run the command as this user instead of root |
| `--cwd DIR` | current directory | Working directory for the command |
| `--wait SECS` | 300 | How long to wait for the owner's approval |
| `--` | | Separates sudoreq options from the command |

---

## Workflow

1. `sudoreq` sends your request to the sudo-server daemon via a local Unix socket.
2. The daemon sends a Telegram message to the system owner with the command details and Approve/Deny buttons.
3. `sudoreq` blocks, polling for the result.
4. When the owner taps a button:
   - **Approved**: the command runs and stdout/stderr is printed to your terminal. Exit code mirrors the command's actual exit code.
   - **Denied**: `sudoreq` exits with code 1 and prints a denial message.
5. If the owner does not respond within `--wait` seconds (default 300), `sudoreq` exits with code 1 with a timeout message.

---

## Checking the Exit Code

Always check the exit code to know if the request succeeded:

```bash
sudoreq -- apt-get install -y curl
if [ $? -eq 0 ]; then
  echo "Installation succeeded"
else
  echo "Failed — was it denied or did apt-get return an error?"
fi
```

Or in Python:

```python
import subprocess
result = subprocess.run(["sudoreq", "--", "apt-get", "install", "-y", "curl"])
if result.returncode != 0:
    raise RuntimeError("sudoreq failed — command denied, expired, or errored")
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Approved and command succeeded (exit code 0) |
| Non-zero | Command approved but returned non-zero exit code |
| 1 | Denied, expired, timed out, or server error |

---

## What You Can Request

Only commands in the server's allowlist can be approved. Attempting a disallowed command results in an immediate rejection (before the Telegram message is sent).

Common allowed commands (check with the system owner if unsure):
- Package management: `apt-get`, `apt`, `dpkg`, `pip3`, `npm`
- Services: `systemctl`
- File operations: `cp`, `mv`, `mkdir`, `chown`, `chmod`, `install`, `tee`
- Containers: `docker`, `docker-compose`

If your request is rejected immediately with "not in allowlist", ask the system owner to add your required command to the config.

---

## Important Rules

- **Use bare command names** — The server resolves commands securely via its system PATH. Do not provide full paths (e.g., use `apt-get`, not `/usr/bin/apt-get`), as paths will be rejected.
- **Never construct shell strings** — always pass commands as separate arguments. Correct: `sudoreq -- apt-get install -y curl`. Wrong: `sudoreq -- "apt-get install -y curl"` (that tries to run a binary literally named `apt-get install -y curl`).
- **One command per request** — chain commands across multiple `sudoreq` calls, not in a single shell string.
- **No pipes or redirects** — `sudoreq -- cat /etc/file | grep pattern` will not work. Instead: `sudoreq -- cat /etc/file` and then filter the output yourself.
- **Target Users & Paths** — When using `--as`, the requested user must be explicitly allowed by the server's configuration (which typically defaults to only `root`). When using `--cwd`, the path must be absolute and cannot contain traversals (e.g., `..`).
- **Be specific** — the owner sees exactly what you are asking. Vague or overly broad commands (like `bash`) will likely be denied.

---

## Troubleshooting

**"Socket not found"** — the sudo-server daemon is not running. Notify the system owner.

**"Permission denied" on socket** — your user is not in the `sudo-agents` group. Ask the owner: `sudo usermod -aG sudo-agents YOUR_USER`.

**Request expired before approval** — the owner did not respond in time. Retry with a longer `--wait` if the task is expected to take a while to review.

**Command rejected immediately** — the command is not in the allowlist. Request the owner to add it to `/etc/sudo-server/config.json`.
