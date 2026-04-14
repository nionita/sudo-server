# sudo-server

`sudo-server` is a privileged command execution gateway designed specifically for unprivileged agents and bots. It operates by launching a secure UNIX daemon (`sudo-server.py`) running as `root` and a lightweight client utility (`sudoreq`) that submits requests to it over a strictly controlled socket.

When an agent requests a command, `sudo-server` sends an interactive inline prompt to a configured Telegram chat. If an authorized human user presses "Approve", the command executes securely, and the output is propagated back to the waiting agent.

---

## What It's About

Many environments require AI agents or automated bots to run commands extending beyond their privilege boundaries. Granting these agents native `sudo` access or adding them to `wheel` exposes the underlying system to catastrophic risk in cases of hallucination, prompting injection, or supply-chain compromise. 

`sudo-server` mitigates this by providing a complete **Human-In-The-Loop (HITL) approval gateway**. 

- The agent requests a command.
- An interactive prompt containing the request details is securely piped to the Human's phone via Telegram.
- Execute only on explicit cryptographic Telegram approval by an authorized user.
- Read-only response telemetry is fed back to the client.

## Features & Hardened Security Architecture

`sudo-server` is built with a zero-trust perspective regarding its clients:
- **SO_PEERCRED Authentication:** Agent identities are cryptographically sourced via Kernel syscalls over the UNIX socket, blocking forgery attempts.
- **Bare Names & Secured PATH Execution:** Full paths provided by the agent are discarded to prevent symlink manipulation and traversal bypasses. Only bare commands found strictly in secure system paths (`/bin`, `/sbin`, etc.) are resolved and executed.
- **Arbitrary File Overwrite Protection:** All transient response files are strictly managed and allocated by the `root` server side; clients are blocked from executing symlink race-conditions.
- **DOS Queuing Capping:** Active queries queued for the Human's review are capped (e.g. 50 parallel requests), and socket payloads safely error dynamically if overloaded (>1MB buffers).
- **Target Sub-user Privileges:** Config limits exactly what users can be transitioned onto (typically only defaulting to `root`).

---

## Installation

### Prerequisites
- A Linux-based environment utilizing `systemd`.
- Active Telegram Account + Telegram Bot credentials. (Obtain an API token via `@BotFather` and fetch your Personal ID via `@userinfobot`).

### Deployment

Run the included install script as `root`:

```bash
git clone https://github.com/your-org/sudo-server.git
cd sudo-server
sudo bash install.sh
```

### Configuration

Follow the post-installation tasks:
1. **Credentials:** Set `SUDO_SERVER_TG_TOKEN` and `SUDO_SERVER_TG_CHAT_ID` within `/etc/sudo-server/env`.
2. **Access Control:** Modify `/etc/sudo-server/config.json`. Configure your `command_allowlist` carefully to restrict precisely what commands agents are authorized to submit. Add your Telegram ID to `authorized_telegram_users` to strictly authorize specific reviewers.
3. **Agent User Inclusion:** Assign appropriate users to the secure access group:
   ```bash
   sudo usermod -aG sudo-agents agent_username
   ```
4. **Boot:**
   ```bash
   sudo systemctl enable --now sudo-server
   sudo journalctl -u sudo-server -f
   ```

---

## Security Best Practices

1. **Keep Configs Locked Down**: Configuration keys often contain secrets or critical logic paths. Ensure all paths matching `/etc/sudo-server/*` evaluate rigidly to `600` access nodes strictly scoped by `root`. `sudo-server` dynamically protects your node actively warning if your `config.json` exposes secrets.
2. **Never Whitelist Abusable Binaries**: Avoid allowlisting broad shells or interpreters (`bash`, `sh`, `python3`, `ruby`) inside `config.json`. A compromised agent given `bash` can pipe inline commands destroying isolation boundaries. Authorize explicitly focused tools appropriately (`systemctl`, `apt-get`, `mkdir`).
3. **Restrict Agent Target Scopes**: Restrict the `allowed_run_as` list purely to the functional IDs needed. 
