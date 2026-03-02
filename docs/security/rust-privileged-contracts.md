# Privileged Rust Contract Freeze (v1)

This document freezes the compatibility contracts for privileged components migrated to Rust.

## 1. PAM Reset Helper Socket Protocol

Transport:
- UNIX domain socket only
- Socket perms/ownership: `root:mailclient`, mode `0660`

Frame format:
- `4-byte` big-endian payload length
- JSON payload body
- Maximum frame size: `8192` bytes

Request schema (`deny_unknown_fields`):
- `request_id: string` (required, non-empty)
- `username: string` (required, <= `128` bytes)
- `new_password: string` (required, <= `4096` bytes)

Response schema (`deny_unknown_fields`):
- `request_id: string`
- `ok: bool`
- `code: string`

Well-known helper response codes:
- `ok`
- `helper_failed`
- `invalid_frame`
- `invalid_request`
- `unauthorized_peer`

Authorization:
- Linux `SO_PEERCRED` UID/GID checks are mandatory

Execution:
- Helper invokes `/usr/sbin/chpasswd` directly (no shell)
- Password is passed via stdin in `username:password\n` form only

Logging:
- Helper logs only `{request_id, username, result_code}`
- No plaintext password logging

## 2. Updater Worker File Contract

Paths (under `UPDATE_BASE_DIR`):
- request: `request/update-request.json`
- status: `status/update-status.json`
- lock: `lock/update.lock`
- backups: `backups/`

Request JSON schema:
- `request_id: string`
- `requested_at: RFC3339 string`
- `requested_by: string`
- `target_version: string` (optional)

Status JSON schema:
- `state: idle|queued|in_progress|completed|failed|rolled_back`
- `request_id, requested_at, started_at, finished_at`
- `target_version, from_version, to_version`
- `rolled_back: bool`
- `error: string`

Operational rules:
- Request/status files remain JSON and pretty-printed
- Lock file remains exclusive-create guarded
- Worker maintains staged swap + rollback semantics

## 3. Golden Fixtures

Frozen fixture files are in:
- `rust/contracts/tests/fixtures/pam/`
- `rust/contracts/tests/fixtures/updater/`

Contract tests must pass before release packaging.
