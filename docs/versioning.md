# Versioning Design

## Purpose
This document defines the stable release numbering model for Despatch so tags, release titles, and patch hotfixes stay consistent.

## Canonical Model
- Base version shape: `v<phase>.<major>.<minor>`
- Optional hotfix patch suffix: `_<patch>`
- Human release title shape: `Alpha <phase>.<major>.<minor>[_<patch>]`

### Field meanings
- `phase`: release track ordinal (`1` currently maps to Alpha)
- `major`: breaking-generation number inside the phase
- `minor`: feature/revision number inside the phase/major
- `patch`: bug-fix hotfix index for that exact base version, zero-padded to 2 digits (`_01`, `_02`, ...)

## Repository Tag Convention (established)
Git tags include the prerelease marker between base version and patch:
- `v<phase>.<major>.<minor>-alpha.1`
- `v<phase>.<major>.<minor>-alpha.1_<patch>`

This preserves existing published tags and must not be changed retroactively.

## Example
- Human: `Alpha 1.0.5_03`
- Tag: `v1.0.5-alpha.1_03`
- Meaning: third bug-fix patch for base `1.0.5` on the Alpha track.

## Increment Rules
1. Feature release: increment `<minor>`, reset patch suffix (no `_NN`).
2. Bug-fix on same base: keep `<phase>.<major>.<minor>`, increment `_NN` sequentially.
3. Never rewrite an existing published version number to point at different code.
4. Never mix patch counters across different base versions (for example `_03` on `1.0.5` is independent from `_03` on `1.0.4`).
