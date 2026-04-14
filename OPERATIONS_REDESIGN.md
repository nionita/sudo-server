# sudo-server Operations Redesign

This note captures the intended redesign direction after the current command-based
model showed its limits, especially around sandboxing and high-power tools such
as `apt`, `systemctl`, `npm`, `pip`, and `docker`.

## Why This Redesign Is Needed

The current model allowlists commands by executable name and then runs them
inside the sandbox of `sudo-server.service`.

That creates two problems:

1. It is too coarse from a security perspective.
   - Allowing a binary like `apt`, `systemctl`, `pip`, `npm`, or `docker` still
     allows a very large action space.
   - Human approval becomes the only real control for dangerous tools.

2. It is too rigid from a sandbox perspective.
   - Different privileged actions need different writable paths, network rules,
     timeouts, and execution constraints.
   - Example: `apt update` needs write access to APT state directories, but the
     main service sandbox only allows writes to `/var/log/sudo-server` and
     `/run/sudo-server`.

So the next step should not be “allow more commands”, but “define explicit
operations”.

## Target Model

The system should move from:

- requesting raw commands with arbitrary arguments

to:

- requesting named operations with validated arguments

Examples:

- `apt_update`
- `apt_install(package_names)`
- `systemctl_restart(service_name)`
- `systemctl_status(service_name)`
- `install_package_file(path, owner, mode)`
- `chown_path(path, user, group)` with path restrictions

Each operation should define:

- operation name
- argument schema and validation rules
- command template or executor implementation
- allowed `run_as`
- timeout
- output policy
- sandbox policy
- Telegram approval presentation

## Plugin-Like Operation Architecture

Operations should be designed like installable server-side plugins, but with a
very strict trust model.

### Core principles

- The basic `sudo-server` daemon remains the control plane.
- Operations are provided by system-wide installed definitions or modules.
- Agents can only request operations that are explicitly configured and assigned.
- The server never executes an arbitrary binary directly from the request.

### Proposed structure

Each operation should be installed system-wide, for example under a dedicated
directory such as:

- `/usr/lib/sudo-server/operations/`
- `/etc/sudo-server/operations.d/`

An operation package should provide:

- an operation ID
- a machine-readable schema
- an executor definition
- a sandbox profile
- display metadata for Telegram

The executor can be one of:

- a fixed command template with placeholders
- a root-owned wrapper script
- a Python module loaded by the daemon
- a transient systemd unit template

The preferred direction is to keep executors root-owned and system-installed,
not editable by agent users.

## Configuration Model

Global config should stop being a command allowlist and become an operation
assignment policy.

Configuration should answer:

- which operations are enabled on this machine
- which agents may request which operations
- which Telegram chat/channel handles approvals for which operations
- any per-operation limits or defaults

### Likely config layers

1. System-installed operation definitions
   - shipped with the software or installed separately
   - not controlled by unprivileged agents

2. Local server config
   - enables or disables operations
   - assigns operations to agent users or agent groups
   - maps operations to Telegram approval targets

3. Operation-local config
   - allowed package names
   - allowed service names
   - allowed path prefixes
   - timeout overrides
   - output redaction rules

## Telegram Approval Model

Approval should move from “approve this command line” to “approve this
operation invocation”.

Approval messages should show:

- operation name
- requesting agent
- validated arguments
- target run-as identity
- target sandbox profile
- timeout
- optional human-readable risk summary

Example:

- Operation: `apt_install`
- Agent: `agent_browser`
- Args: `packages=[ffmpeg]`
- Sandbox: `apt-write`
- Timeout: `300s`

Telegram approval must remain tied to:

- the destination chat/channel for the request
- the authorized approver IDs for that chat/channel

The routing model should support different approval channels for different
operations or agent groups.

Examples:

- package operations -> infra-maintenance channel
- service restarts -> ops-oncall channel
- file ownership fixes -> local-admin channel

## Sandbox Model

Per-operation sandboxing is a core requirement of the redesign.

The current daemon-wide sandbox is too blunt. Different operations need
different filesystem and runtime permissions.

That means operation execution should likely move to a separate execution layer,
preferably via transient `systemd-run` units or another equivalent isolated
runtime.

Each operation should declare at least:

- writable paths
- whether network is allowed
- working directory policy
- runtime timeout
- environment policy
- whether privilege drop or user switching is needed

Examples:

- `apt_update`
  - writable: `/var/lib/apt/lists`, `/var/cache/apt`
  - network: yes
  - run as: root

- `systemctl_restart(service_name)`
  - writable: minimal systemd/runtime paths only
  - network: no special requirement
  - argument: service must be in an allowlist

## Request Flow

High-level future flow:

1. Agent requests an operation ID plus structured arguments.
2. Server authenticates the agent by peer credentials.
3. Server loads the operation definition.
4. Server validates arguments against the operation schema.
5. Server checks whether the agent is allowed to use that operation.
6. Server resolves the Telegram approval target for that operation.
7. Server sends a structured approval request to Telegram.
8. Human approves or denies the operation invocation.
9. Server launches the executor in the operation-specific sandbox.
10. Result is returned to the agent and summarized back to Telegram according to
    the operation's output policy.

## Security Requirements

The redesign should preserve or improve the current security posture:

- no raw executable paths from agents
- no raw shell commands from agents
- strict schema validation for every operation argument
- operation definitions must be root-owned and system-installed
- operation execution context must be isolated from the main daemon
- approvals must be bound to exact validated arguments
- logs and audit records should include operation ID and normalized arguments
- output handling should be operation-specific and redact or suppress secrets by default

## Migration Direction

This is a major design change, not an incremental patch.

Suggested migration path:

1. Keep the current daemon running as the base transport and approval layer.
2. Add support for requesting operations alongside the current command mode.
3. Implement a small first set of built-in operations:
   - `apt_update`
   - `apt_install`
   - `systemctl_restart`
   - `systemctl_status`
4. Route these operations through per-operation execution profiles.
5. Deprecate broad command allowlisting once the required operations exist.

## Non-Goals for the First Redesign Pass

- fully generic plugin loading from untrusted locations
- user-provided scripts as operations
- arbitrary shell execution wrapped as an “operation”
- per-agent custom code execution

The operation model should stay explicit, root-controlled, and auditable.
