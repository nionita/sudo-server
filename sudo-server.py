#!/usr/bin/env python3
"""
sudo-server — privilege-escalation approval daemon
Receives command requests from unprivileged agent users over a Unix socket,
forwards them to the owner via Telegram inline buttons, and executes approved
commands as root (or as a specified user via sudo).

No third-party dependencies — stdlib only.
Runs as root under systemd.
"""

import asyncio
import json
import logging
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration — loaded from /etc/sudo-server/config.json
# All values can be overridden by environment variables (see load_config).
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "socket_path":    "/run/sudo-server/request.sock",
    "socket_group":   "sudo-agents",
    "log_file":       "/var/log/sudo-server/sudo-server.log",
    "audit_log":      "/var/log/sudo-server/audit.log",
    "token_ttl":      300,          # seconds a pending approval token stays valid
    "max_output_len": 3000,         # chars of command output sent back via Telegram
    "poll_timeout":   30,           # Telegram long-poll timeout (seconds)
    # Allowlist: if non-empty, only these base command names are accepted.
    # Example: ["apt-get", "apt", "dpkg", "systemctl", "cp", "chown", "cat"]
    "command_allowlist": [],
    # Per-agent allowlist: maps UNIX username → list of allowed base commands.
    # Overrides command_allowlist for that user if set.
    # Example: {"agent_web": ["apt-get", "apt"], "agent_dev": ["systemctl"]}
    "agent_allowlist": {},
    # Telegram — MUST be set (env vars preferred over config file for secrets)
    "telegram_bot_token": "",       # or env SUDO_SERVER_TG_TOKEN
    "telegram_chat_id":  "",        # or env SUDO_SERVER_TG_CHAT_ID
}

CONFIG_FILE = os.environ.get("SUDO_SERVER_CONFIG", "/etc/sudo-server/config.json")


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg.update(json.load(f))
    # Environment variable overrides (secrets should live here, not in the file)
    if os.environ.get("SUDO_SERVER_TG_TOKEN"):
        cfg["telegram_bot_token"] = os.environ["SUDO_SERVER_TG_TOKEN"]
    if os.environ.get("SUDO_SERVER_TG_CHAT_ID"):
        cfg["telegram_chat_id"] = os.environ["SUDO_SERVER_TG_CHAT_ID"]
    if os.environ.get("SUDO_SERVER_SOCKET"):
        cfg["socket_path"] = os.environ["SUDO_SERVER_SOCKET"]
    if os.environ.get("SUDO_SERVER_SOCKET_GROUP"):
        cfg["socket_group"] = os.environ["SUDO_SERVER_SOCKET_GROUP"]
    if os.environ.get("SUDO_SERVER_TOKEN_TTL"):
        cfg["token_ttl"] = int(os.environ["SUDO_SERVER_TOKEN_TTL"])
    return cfg


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(cfg: dict):
    log_path = Path(cfg["log_file"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path),
    ]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def audit(cfg: dict, entry: dict):
    """Append a JSON audit record (one per line) to the audit log."""
    audit_path = Path(cfg["audit_log"])
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Telegram helpers (urllib only, no third-party libs)
# ---------------------------------------------------------------------------

class TelegramError(Exception):
    pass


def tg_call(token: str, method: str, payload: dict, timeout: int = 10) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise TelegramError(f"HTTP {e.code}: {body}") from e


def tg_send(token: str, chat_id: str, text: str,
            keyboard: Optional[list] = None) -> dict:
    """Send a message, optionally with an inline keyboard."""
    payload: dict = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    return tg_call(token, "sendMessage", payload)


def tg_edit(token: str, chat_id: str, message_id: int, text: str) -> None:
    """Edit an existing message (used to update approval prompt after decision)."""
    try:
        tg_call(token, "editMessageText", {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
        })
    except TelegramError:
        pass  # message may already be deleted — not fatal


def tg_answer_callback(token: str, callback_query_id: str, text: str = "") -> None:
    """Dismiss the spinner on an inline button press."""
    try:
        tg_call(token, "answerCallbackQuery", {
            "callback_query_id": callback_query_id,
            "text": text,
        })
    except TelegramError:
        pass


def tg_get_updates(token: str, offset: int, poll_timeout: int) -> dict:
    """Long-poll for updates. Uses a longer urllib timeout = poll_timeout + 5."""
    url = (
        f"https://api.telegram.org/bot{token}/getUpdates"
        f"?offset={offset}&timeout={poll_timeout}&allowed_updates=callback_query"
    )
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=poll_timeout + 5) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError):
        return {"ok": True, "result": []}


# ---------------------------------------------------------------------------
# Pending request store
# ---------------------------------------------------------------------------

class PendingRequest:
    __slots__ = ("token", "agent_user", "argv", "cwd", "run_as",
                 "created_at", "message_id", "response_path")

    def __init__(self, token: str, agent_user: str, argv: list[str],
                 cwd: str, run_as: str, response_path: str):
        self.token = token
        self.agent_user = agent_user
        self.argv = argv
        self.cwd = cwd
        self.run_as = run_as
        self.created_at = time.monotonic()
        self.message_id: Optional[int] = None
        self.response_path = response_path


class RequestStore:
    def __init__(self, ttl: int):
        self._store: dict[str, PendingRequest] = {}
        self._ttl = ttl

    def add(self, req: PendingRequest):
        self._store[req.token] = req

    def get(self, token: str) -> Optional[PendingRequest]:
        req = self._store.get(token)
        if req and (time.monotonic() - req.created_at) > self._ttl:
            del self._store[token]
            return None
        return req

    def remove(self, token: str) -> Optional[PendingRequest]:
        return self._store.pop(token, None)

    def expire_all(self):
        now = time.monotonic()
        expired = [t for t, r in self._store.items()
                   if (now - r.created_at) > self._ttl]
        for t in expired:
            req = self._store.pop(t)
            _write_response(req.response_path, {
                "status": "expired",
                "message": "Approval timed out.",
            })
            logging.info("Request %s expired (user=%s cmd=%s)",
                         t[:8], req.agent_user, req.argv[0])


# ---------------------------------------------------------------------------
# Command validation
# ---------------------------------------------------------------------------

def validate_request(payload: dict, cfg: dict) -> tuple[bool, str]:
    """Return (ok, error_message). Checks structure + allowlist."""
    required = {"agent_user", "argv", "cwd", "run_as", "response_path"}
    missing = required - payload.keys()
    if missing:
        return False, f"Missing fields: {missing}"

    argv = payload["argv"]
    if not isinstance(argv, list) or not argv:
        return False, "argv must be a non-empty list"
    for a in argv:
        if not isinstance(a, str):
            return False, "argv elements must be strings"

    agent_user = payload["agent_user"]
    base_cmd = os.path.basename(argv[0])

    # Per-agent allowlist takes precedence
    agent_al = cfg.get("agent_allowlist", {}).get(agent_user)
    if agent_al is not None:
        if base_cmd not in agent_al:
            return False, (
                f"Command '{base_cmd}' not in per-agent allowlist for {agent_user}. "
                f"Allowed: {agent_al}"
            )
        return True, ""

    # Global allowlist
    global_al = cfg.get("command_allowlist", [])
    if global_al and base_cmd not in global_al:
        return False, (
            f"Command '{base_cmd}' not in global allowlist. "
            f"Allowed: {global_al}"
        )

    return True, ""


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def execute_command(req: PendingRequest, cfg: dict) -> dict:
    """Run the command and return a result dict."""
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": f"/home/{req.run_as}" if req.run_as != "root" else "/root",
        "USER": req.run_as,
        "LOGNAME": req.run_as,
    }
    # Build the actual argv: if run_as != root, use sudo -u <user>
    if req.run_as == "root":
        actual_argv = req.argv
    else:
        actual_argv = ["sudo", "-u", req.run_as, "--"] + req.argv

    try:
        result = subprocess.run(
            actual_argv,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=req.cwd if os.path.isdir(req.cwd) else "/",
            env=env,
        )
        combined = (result.stdout + result.stderr).strip()
        max_len = cfg.get("max_output_len", 3000)
        if len(combined) > max_len:
            combined = combined[:max_len] + "\n[...truncated]"
        return {
            "status": "approved",
            "returncode": result.returncode,
            "output": combined,
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Command timed out (120s)."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Response file helpers
# ---------------------------------------------------------------------------

def _write_response(path: str, data: dict):
    """Write JSON result to the response file the agent is waiting on."""
    try:
        # Write to a temp file then rename for atomicity
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception as e:
        logging.error("Failed to write response to %s: %s", path, e)


# ---------------------------------------------------------------------------
# Unix socket server
# ---------------------------------------------------------------------------

async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: dict,
    store: RequestStore,
    send_queue: asyncio.Queue,
):
    peer = writer.get_extra_info("peername")
    try:
        raw = await asyncio.wait_for(reader.read(4096), timeout=5)
        payload = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.warning("Bad request from %s: %s", peer, e)
        writer.write(json.dumps({"status": "error", "message": "Bad request"}).encode())
        await writer.drain()
        writer.close()
        return

    ok, err = validate_request(payload, cfg)
    if not ok:
        logging.warning("Rejected request from %s: %s", peer, err)
        writer.write(json.dumps({"status": "rejected", "message": err}).encode())
        await writer.drain()
        writer.close()
        return

    token = secrets.token_hex(8)  # 16 hex chars — short enough to type if needed
    req = PendingRequest(
        token=token,
        agent_user=payload["agent_user"],
        argv=payload["argv"],
        cwd=payload["cwd"],
        run_as=payload.get("run_as", "root"),
        response_path=payload["response_path"],
    )
    store.add(req)

    # Acknowledge immediately so the client can start polling its response file
    writer.write(json.dumps({
        "status": "pending",
        "token": token,
        "message": "Request queued, waiting for approval.",
    }).encode())
    await writer.drain()
    writer.close()

    # Hand off to Telegram sender
    await send_queue.put(req)
    logging.info("Queued request %s from %s: %s",
                 token[:8], req.agent_user, req.argv)


async def run_socket_server(cfg: dict, store: RequestStore, send_queue: asyncio.Queue):
    sock_path = cfg["socket_path"]
    Path(sock_path).parent.mkdir(parents=True, exist_ok=True)

    # Remove stale socket
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    server = await asyncio.start_unix_server(
        lambda r, w: handle_client(r, w, cfg, store, send_queue),
        path=sock_path,
    )

    # Set group ownership and permissions (0660)
    try:
        import grp
        gid = grp.getgrnam(cfg["socket_group"]).gr_gid
        os.chown(sock_path, 0, gid)
    except (KeyError, PermissionError) as e:
        logging.warning("Could not set socket group '%s': %s", cfg["socket_group"], e)
    os.chmod(sock_path, 0o660)

    logging.info("Unix socket listening at %s", sock_path)
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# Telegram sender (reads from queue, sends messages)
# ---------------------------------------------------------------------------

async def telegram_sender(cfg: dict, store: RequestStore, send_queue: asyncio.Queue):
    token = cfg["telegram_bot_token"]
    chat_id = cfg["telegram_chat_id"]
    loop = asyncio.get_event_loop()

    while True:
        req: PendingRequest = await send_queue.get()
        cmd_display = " ".join(req.argv)
        text = (
            f"<b>Sudo request</b>\n"
            f"Agent: <code>{req.agent_user}</code>\n"
            f"Run as: <code>{req.run_as}</code>\n"
            f"CWD: <code>{req.cwd}</code>\n"
            f"Command:\n<pre>{cmd_display}</pre>\n"
            f"Token: <code>{req.token}</code>\n"
            f"Expires in {cfg['token_ttl']}s"
        )
        keyboard = [[
            {"text": "✅ Approve", "callback_data": f"approve:{req.token}"},
            {"text": "❌ Deny",    "callback_data": f"deny:{req.token}"},
        ]]
        try:
            resp = await loop.run_in_executor(
                None, lambda: tg_send(token, chat_id, text, keyboard)
            )
            if resp.get("ok"):
                req.message_id = resp["result"]["message_id"]
        except TelegramError as e:
            logging.error("Telegram send failed: %s", e)
            _write_response(req.response_path, {
                "status": "error",
                "message": f"Telegram notification failed: {e}",
            })
            store.remove(req.token)


# ---------------------------------------------------------------------------
# Telegram poller (long-polls getUpdates, handles callback_query)
# ---------------------------------------------------------------------------

async def telegram_poller(cfg: dict, store: RequestStore):
    token = cfg["telegram_bot_token"]
    chat_id = str(cfg["telegram_chat_id"])
    poll_timeout = cfg["poll_timeout"]
    loop = asyncio.get_event_loop()
    offset = 0

    logging.info("Telegram poller started")
    while True:
        try:
            data = await loop.run_in_executor(
                None, lambda: tg_get_updates(token, offset, poll_timeout)
            )
        except Exception as e:
            logging.warning("getUpdates error: %s", e)
            await asyncio.sleep(5)
            continue

        # Expire stale requests periodically
        store.expire_all()

        if not data.get("ok"):
            await asyncio.sleep(5)
            continue

        for update in data.get("result", []):
            offset = max(offset, update["update_id"] + 1)
            cq = update.get("callback_query")
            if not cq:
                continue

            # Security: only accept callbacks from the expected chat
            cq_chat = str(
                cq.get("message", {}).get("chat", {}).get("id", "")
            )
            if cq_chat != chat_id:
                logging.warning("Ignoring callback from chat %s (expected %s)",
                                cq_chat, chat_id)
                continue

            cq_id = cq["id"]
            data_str = cq.get("data", "")
            from_user = cq.get("from", {}).get("username", "unknown")

            if ":" not in data_str:
                continue
            action, req_token = data_str.split(":", 1)
            req = store.get(req_token)

            if req is None:
                await loop.run_in_executor(
                    None,
                    lambda: tg_answer_callback(token, cq_id, "Request not found or expired.")
                )
                continue

            if action == "approve":
                await loop.run_in_executor(
                    None,
                    lambda: tg_answer_callback(token, cq_id, "Executing...")
                )
                logging.info("Request %s APPROVED by @%s", req_token[:8], from_user)
                audit(cfg, {
                    "event": "approved",
                    "token": req_token[:8],
                    "agent_user": req.agent_user,
                    "argv": req.argv,
                    "run_as": req.run_as,
                    "approved_by": from_user,
                })
                store.remove(req_token)

                # Execute in a thread so we don't block the event loop
                result = await loop.run_in_executor(
                    None, lambda: execute_command(req, cfg)
                )
                _write_response(req.response_path, result)

                # Update the Telegram message
                rc = result.get("returncode", "?")
                out = result.get("output", result.get("message", ""))
                out_display = out[:400] + ("..." if len(out) > 400 else "")
                summary = (
                    f"<b>✅ Executed</b> (approved by @{from_user})\n"
                    f"<code>{'  '.join(req.argv)}</code>\n"
                    f"Exit: <code>{rc}</code>\n"
                    f"<pre>{out_display}</pre>"
                )
                if req.message_id:
                    await loop.run_in_executor(
                        None,
                        lambda: tg_edit(token, chat_id, req.message_id, summary)
                    )

            elif action == "deny":
                await loop.run_in_executor(
                    None,
                    lambda: tg_answer_callback(token, cq_id, "Denied.")
                )
                logging.info("Request %s DENIED by @%s", req_token[:8], from_user)
                audit(cfg, {
                    "event": "denied",
                    "token": req_token[:8],
                    "agent_user": req.agent_user,
                    "argv": req.argv,
                    "denied_by": from_user,
                })
                store.remove(req_token)
                _write_response(req.response_path, {
                    "status": "denied",
                    "message": f"Denied by @{from_user}.",
                })
                if req.message_id:
                    summary = (
                        f"<b>❌ Denied</b> by @{from_user}\n"
                        f"<code>{' '.join(req.argv)}</code>"
                    )
                    await loop.run_in_executor(
                        None,
                        lambda: tg_edit(token, chat_id, req.message_id, summary)
                    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    cfg = load_config()

    if not cfg["telegram_bot_token"]:
        print("ERROR: telegram_bot_token not set. "
              "Use SUDO_SERVER_TG_TOKEN env var or config file.", file=sys.stderr)
        sys.exit(1)
    if not cfg["telegram_chat_id"]:
        print("ERROR: telegram_chat_id not set. "
              "Use SUDO_SERVER_TG_CHAT_ID env var or config file.", file=sys.stderr)
        sys.exit(1)

    setup_logging(cfg)
    logging.info("sudo-server starting")

    store = RequestStore(ttl=cfg["token_ttl"])
    send_queue: asyncio.Queue = asyncio.Queue()

    loop = asyncio.get_event_loop()

    def _shutdown():
        logging.info("sudo-server shutting down")
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _shutdown)

    await asyncio.gather(
        run_socket_server(cfg, store, send_queue),
        telegram_sender(cfg, store, send_queue),
        telegram_poller(cfg, store),
    )


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("sudo-server must run as root", file=sys.stderr)
        sys.exit(1)
    asyncio.run(main())
