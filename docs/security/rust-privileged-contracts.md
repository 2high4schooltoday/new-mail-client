# Privileged Rust Contract Freeze (v1)

This document freezes the compatibility contracts for privileged components migrated to Rust.

## 1. PAM Reset Helper Socket Protocol

Transport:
- UNIX domain socket only
- Socket perms/ownership: `root:despatch`, mode `0660`

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
- request queue: `request/update-request-*.json`
- legacy request path accepted during transition: `request/update-request.json`
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
- Workers consume the oldest pending request file and continue accepting the legacy fixed request filename during transition
- Lock file remains exclusive-create guarded
- Worker maintains staged swap + rollback semantics
- Worker rejects symlinked request/status paths before reads/writes

Ownership/mode contract:
- `/opt/despatch` runtime payload is `root:root`
- `/opt/despatch/.env` is `root:despatch` `0640`
- `request/` and `status/` are `root:despatch` `0770` with files `0660`
- `lock/`, `work/`, and `backups/` are `root:root` `0750`

## 3. Updater Authenticity Contract

Required config when updates are enabled:
- `UPDATE_REQUIRE_SIGNATURE=true` (default)
- `UPDATE_SIGNATURE_ASSET=checksums.txt.sig` (default)
- `UPDATE_SIGNING_PUBLIC_KEYS` as comma-separated base64 Ed25519 public keys

Verification order (fail-closed):
1. Download archive, `checksums.txt`, and detached signature asset
2. Verify detached Ed25519 signature over raw `checksums.txt` bytes using pinned key set
3. Parse checksums and verify archive hash

Failure policy:
- Missing signature asset, invalid signature, invalid key material, or checksum mismatch aborts update
- No privileged artifact ownership is handed to `despatch` during/after apply

## 4. Golden Fixtures

Frozen fixture files are in:
- `rust/contracts/tests/fixtures/pam/`
- `rust/contracts/tests/fixtures/updater/`

Contract tests must pass before release packaging.
