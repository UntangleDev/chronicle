# Changelog

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0, a minor version may change anything: names, options, struct fields,
database columns, and the signed content format. No compatibility layers are
kept during that period.

## Unreleased

## 0.1.1

### Added

- A closed historical-verifier registry keyed by the algorithm and canonical
  version stored on each ledger entry. The current writer and retained
  verification schemes are separate, so a future writer can be added without
  removing the implementation needed to verify older evidence.
- Authenticated erasable values backed by `Chronicle.ErasureKeyring`.
  `Chronicle.erasable/2` and per-schema `erasable` policies store AES-256-GCM
  ciphertext; `Chronicle.Erasure.destroy/1` removes plaintext access while the
  ledger continues to verify.

### Changed

- Deleted the raw-key low-level verifier and added
  `Chronicle.Integrity.verify_entry/5`. Verification now resolves the entry's
  key identifier through its configured sequence epoch internally; no
  compatibility path accepts raw key material.
- Canonical version 1 now enforces its existing aggregate byte limit as a
  running budget and flattens accepted iodata once. Accepted encodings and the
  published integrity vector are unchanged.
- Key-resolver and keyring exceptions now expose only the exception module;
  exception messages, fields, and stacktraces do not cross the secret-manager
  boundary in ordinary error terms.

## 0.1.0

First release.

Chronicle records application facts and Ecto record versions in one append-only,
hash-chained ledger authenticated with HMAC-SHA-256. Both go through the same
model, so an authorization denial and a database update occupy the same ordered
history and are verified by the same walk.

### Recording

- `Chronicle.insert/2`, `update/2` and `delete/2` mirror the `Ecto.Repo` write
  surface. The audit record commits in the same transaction as the change it
  describes, and a write that cannot be signed fails the operation. There is no
  unsigned mode.
- `Chronicle.record/3` for facts that are not database mutations — a denied
  authorization, an export, a payment provider's response.
- `Chronicle.transaction/3`, `group/3`, `span/3` and `run/3` gather related work
  into one signed unit carrying its own outcome, duration and child count. Each
  accepts a `do` block or an explicit zero-arity function.
- `Chronicle.Multi` adds audited steps to an ordinary `Ecto.Multi`, which stays
  an `Ecto.Multi`.
- Ambient actor, tenant, subject and correlation data through
  `Chronicle.Context`, with explicit capture for `Task` and Oban, and request
  context for Phoenix.

### Integrity

- A SHA-256 hash chain over a versioned canonical binary encoding, independent
  of Erlang's External Term Format, with fixed resource limits and rejection of
  terms that cannot survive a restart.
- HMAC-SHA-256 signatures over domain-separated digests for content, chain
  position and authentication, so a digest computed for one purpose can never
  verify as another.
- Total order established by a ledger-head row lock, so concurrent writers
  cannot fork the chain.
- Sequence-bounded key epochs, expressing rotation boundaries as ledger
  positions rather than timestamps, with dual-key transition proofs and
  pluggable keyrings for KMS, Vault or PKCS#11.
- `Chronicle.verify_all/2` recomputes every content digest, chain link and
  signature, and checks sequence gaps, the mutable ledger head, unsigned rows,
  duplicate entries and orphaned group children.
- `Chronicle.CheckpointStore` anchors verified positions outside the audit
  database, which is what makes a whole-ledger rewind detectable.
- `Chronicle.Verifier`, a supervised process that verifies on a schedule and
  advances a checkpoint only after a store verifies completely.

### Reading

- `Chronicle.history/2` returns record-local versions numbered in committed
  ledger order, computed in the same statement that returns the page.
- `Chronicle.at/2` reconstructs a past state from a single stored version rather
  than replaying deltas. `Chronicle.revert/2` returns a changeset without
  persisting it.
- `Chronicle.Query` timeline and group queries, paginated by immutable ledger
  position rather than by timestamp or offset.

### Protection

- Credential-shaped field names are protected by default, matched by substring,
  underscore-separated segment, and exact name. Configured fields extend the
  built-in list rather than replacing it.
- Per-schema `redact`, `hash` and `omit` policies, plus `Chronicle.secret/1`,
  `hash/1` and `omit/0` for values whose sensitivity is in their content rather
  than their name.
- A version containing a withheld field reports itself incomplete, and
  reconstruction fails rather than inventing a value.

### Operations

- `mix chronicle.install` generates the Ecto migration and a configuration
  example.
- `mix chronicle.doctor` checks configuration, storage, signing, protected
  fields per audited schema, and ledger integrity.
- `mix chronicle.keys.rotate` plans a rotation, without mutating by default.
- `Chronicle.health/2` performs bounded reads only, and reports healthy only
  when the next write could actually be signed.
- Structured `Chronicle.Error` values carrying a matchable reason alongside a
  human-readable message, and telemetry for verification runs.

### Supported

- Elixir 1.17 or later. That is the first release requiring Erlang/OTP 25, where
  `:crypto.hash_equals/2` is available.
- PostgreSQL and SQLite. SQLite cannot execute `SELECT ... FOR UPDATE`, so it
  does not exercise the lock that establishes total order.

Chronicle is tamper-evident and rollback-resistant, not tamper-proof, and it
records only what is written through it. The README states the boundaries in
full; read them before relying on this for anything that matters.
