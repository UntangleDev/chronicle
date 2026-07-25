# Chronicle

[![CI](https://github.com/UntangleDev/chronicle/actions/workflows/ci.yml/badge.svg)](https://github.com/UntangleDev/chronicle/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/chronicle.svg)](https://hex.pm/packages/chronicle)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/chronicle)

Chronicle records trustworthy application facts and Ecto record versions without
turning ordinary persistence into an audit-infrastructure exercise.

The common Ecto API mirrors `Ecto.Repo`:

```elixir
Chronicle.insert(changeset, actor: current_user)
Chronicle.update(changeset, actor: current_user)
Chronicle.delete(post, actor: current_user)
```

Each domain mutation and its audit version commit in the same database
transaction. Arbitrary non-database facts and larger grouped operations use the
same signed event model.

## Guarantees and threat model

The Ecto provider stores every standalone event or complete group in an
authenticated hash chain. Chronicle detects:

- modification, insertion, deletion, or reordering of signed content;
- sequence gaps and a forged mutable ledger head;
- unsigned audit rows;
- missing, extra, or reordered children in a group;
- use of the wrong signing key for a configured key epoch; and
- deletion or rollback past a checkpoint held outside the audit database.

Chronicle is tamper-evident and rollback-resistant, not magically tamper-proof.
An attacker controlling the application and an active signing key can create
valid new history until a checkpoint is published. An attacker controlling the
database can rewind both the chain and its local head; detecting that requires
an `Chronicle.CheckpointStore` in a separate trust boundary.

The Ecto provider has no unsigned mode.

## Installation

Add the dependency:

```elixir
def deps do
  [
    {:chronicle, "~> 0.1"}
  ]
end
```

Generate the migration and a runtime configuration example:

```console
mix chronicle.install --repo MyApp.Repo --phoenix
```

For the normal single-repository case, configuration is deliberately small:

```elixir
import Config

config :chronicle,
  repo: MyApp.Repo,
  signing_key: {:system, "CHRONICLE_SIGNING_KEY_BASE64", :base64}
```

The key must decode to at least 32 bytes. The install task prints a suitable
development key but never writes it to disk.

Run the generated migration, then check the installation:

```console
mix chronicle.doctor
```

## Auditing Ecto writes

Use the same result convention as `Ecto.Repo`:

```elixir
{:ok, post} =
  %Post{}
  |> Post.changeset(params)
  |> Chronicle.insert(actor: current_user)

{:ok, post} =
  post
  |> Post.changeset(%{title: "Revised"})
  |> Chronicle.update(actor: current_user)

{:ok, post} = Chronicle.delete(post, actor: current_user)
```

Invalid domain changes return `{:error, changeset}`. An audit failure returns
`{:error, %Chronicle.Error{}}` and rolls back the domain mutation.

Bang forms mirror Repo:

```elixir
Chronicle.insert!(changeset, actor: current_user)
Chronicle.update!(changeset, actor: current_user)
Chronicle.delete!(post, actor: current_user)
```

### Ordinary `Ecto.Multi`

`Chronicle.Multi` augments a normal `Ecto.Multi`; it is not a wrapper:

```elixir
multi =
  Ecto.Multi.new()
  |> Chronicle.Multi.insert(:post, post_changeset, actor: current_user)
  |> Chronicle.Multi.update(:account, account_changeset, actor: current_user)
  |> Chronicle.Multi.record(:notification, fn changes ->
    {"notification.requested", %{post_id: changes.post.id}}
  end)

Repo.transaction(multi)
```

Audit steps use internal names shaped as `{:chronicle, operation_name}`. Named
domain results remain available under their original names.

## Record history and time travel

Every audited Ecto insert and update stores the complete resulting persisted
state. A delete stores a signed tombstone and the preceding state. Diffs remain
available for display, but reconstruction never replays a chain of deltas.

```elixir
{:ok, versions} = Chronicle.history(post)
{:ok, versions} = Chronicle.history(Post, post_id)

latest = hd(versions)
latest.version       # record-local position, 1-based
latest.operation     # :insert | :update | :delete
latest.record        # the reconstructed struct, nil for a tombstone
latest.restorable?
```

A version holds only what describes the version. Everything describing the
event — actor, subject, changes, timestamp, correlation id, group id — lives on
`latest.event`, and only there. No value appears in two places:

```elixir
latest.event.actor
latest.event.occurred_at
latest.event.subject["id"]

Chronicle.Version.changes(latest)    # field transitions
Chronicle.Version.snapshot(latest)   # the stored snapshot
```

An event carries two free-form maps. `data` is what the event asserts, given at
the call site. `metadata` is ambient: it is inherited from `Chronicle.Context`
and merged into every event raised while that context is in scope, so a request
or job attaches its provenance once rather than at every call. Neither is
queried — filter on the indexed columns instead.

History is newest first and defaults to 50 entries:

```elixir
Chronicle.history(post, limit: 100, offset: 100)
```

Reconstruct a state by record-local version, audit event, or wall-clock time:

```elixir
{:ok, old_post} = Chronicle.at(post, version: 3)
{:ok, old_post} = Chronicle.at(Post, post_id, event: audit_event_id)
{:ok, old_post} = Chronicle.at(Post, post_id, at: ~U[2026-07-01 12:00:00Z])
```

Version numbers are one-based positions in immutable ledger order. Composite
primary keys use a map or keyword list:

```elixir
Chronicle.history(Membership, %{account_id: account_id, user_id: user_id})
```

Reversion is intentionally non-persisting. It returns a changeset against the
current record so current validation, authorization, and business rules can
still run:

```elixir
with {:ok, changeset} <- Chronicle.revert(post, version: 3),
     {:ok, reverted_post} <- Chronicle.update(changeset, actor: current_user) do
  {:ok, reverted_post}
end
```

Time travel covers one Ecto record, not its association graph. Restoring an
aggregate remains application logic.

### Snapshot safety

Chronicle snapshots persisted Ecto fields only. It excludes associations,
virtual fields, and runtime metadata. The snapshot contains a schema
fingerprint and fails closed if the current schema is incompatible.

No schema declaration is required. An optional policy controls capture:

```elixir
defmodule MyApp.Account do
  use Ecto.Schema
  use Chronicle.Schema,
    except: [:ephemeral_value],
    redact: [:password_hash],
    hash: [:email],
    omit: [:session_token]

  # ...
end
```

The two groups of options answer different questions:

- `only` and `except` select which field changes are worth reporting. An update
  touching only excluded fields records nothing — no event, no ledger sequence.
  This is how you keep a noisy `touched_at` or counter column out of the audit
  trail without generating an event that says nothing.
- `redact`, `hash`, and `omit` withhold a value from the audit store.

`hash` stores an unsalted SHA-256 fingerprint. It answers correlation
questions — did this field change, did it revert to an earlier value, does it
match another record — but it is **not** secrecy. A value drawn from a small or
guessable set, such as an email address, a phone number, or a short numeric
code, can be recovered by hashing candidates until one matches. Reach for
`redact` or `omit` when the value itself must not be recoverable, and treat
`hash` as a correlation tool rather than a protection level between the two.

Excluding a field from diffs does not withhold it. A version still captures
every persisted field, so time travel keeps working. Use `omit` to keep a value
out of the store entirely.

Chronicle never invents protected historical values: a version containing a
withheld field remains visible in history, but `at` and `revert` return an
explicit `:snapshot_incomplete` error.

Historical snapshots consume more storage than delta-only logs. That is an
intentional trade: historical reads are bounded to one version row and do not
depend on replaying every mutation since creation.

### Protected fields

Because a version stores the complete resulting record, and the ledger is
append-only, a value written in clear text cannot be removed later without
breaking the hash chain. Built-in protection is therefore deliberately
generous. A field is protected when its name

- contains `password`, `passwd`, `secret`, `token`, `credential`, `apikey`,
  `privkey`, or `passphrase`;
- has an underscore-separated segment equal to `pwd`, `ssn`, `cvv`, `cvc`,
  `iban`, `pin`, `salt`, or `jwt`; or
- exactly matches a known credential or financial identifier such as
  `api_key`, `card_number`, or `routing_number`.

This covers credentials, not general personal data. Classify
application-specific personal data explicitly.

Configured fields **extend** the built-in list, so adding one never silently
disables the rest:

```elixir
config :chronicle,
  redaction: [
    fields: [:internal_note],
    hash_fields: [:email],
    omit_fields: [:raw_response]
  ]
```

To take complete ownership of the policy, opt out explicitly with
`redaction: [builtin: false, fields: [...]]`.

Protection and reconstruction pull in opposite directions: a protected field
cannot be restored. `mix chronicle.doctor` reports every audited schema whose
versions are consequently not restorable, so that is a visible decision rather
than a surprise at the first `Chronicle.at/2` call.

## Larger audited operations

`Chronicle.transaction/3` opens the configured Repo transaction, establishes
actor and correlation context, and commits all nested facts as one signed
group. It takes a `do` block, so `use Chronicle` once per calling module — the
same arrangement as `Logger`:

```elixir
defmodule MyApp.Orders do
  use Chronicle

  def checkout(current_user, order_changeset, payment, request_id) do
    Chronicle.transaction "order.checkout",
      actor: current_user,
      correlation_id: request_id do
      {:ok, order} = Chronicle.update(order_changeset)
      Chronicle.record!("payment.captured", %{payment_id: payment.id})
      Chronicle.record!("notification.requested", %{template: "receipt"})
      order
    end
  end
end
```

Every construct that wraps a section of your code takes a block the same way:
`transaction/3`, `span/3`, `run/3`, `group/3`,
`Chronicle.Phoenix.with_context/3`, `Chronicle.Phoenix.run/4`, and
`Chronicle.Oban.with_context/2`. One `use Chronicle` covers all of them,
including the optional Phoenix and Oban integrations when those dependencies
are present. Each also accepts an explicit zero-arity function in the same
position, so function-form calls keep working.

Audited `Ecto.Multi` operations executed inside this callback automatically
join the group. Developers do not pass group identifiers.

A group is stored alongside its events rather than in its own table: it is a
row in `audit_events` with `kind: "group"` carrying the unit's type, outcome,
timing, and child count, and its children reference it by `group_id`. One
signed ledger entry covers the group and all of its children. Queries written
directly against `audit_events` should filter on `kind` if they want events
only.

By default an operation is recorded as a failure only when its callback
returns `:error` or `{:error, reason}`, and as a success otherwise. Pass
`:classify` for other conventions — see `Chronicle.Classifier`.

The lower-level `Chronicle.run/3` and `Chronicle.group/3` remain available for
non-Ecto providers and specialised outcome handling.

## Arbitrary audit facts

Not every fact is a database mutation. Data is a map and options are a keyword
list; unknown option keys raise rather than being dropped, so a keyword list
passed where data was intended is reported instead of producing an empty event:

```elixir
Chronicle.record(
  "authorization.denied",
  %{policy: "account-owner"},
  actor: current_user,
  subject: Chronicle.ref("account", account.id),
  correlation_id: request_id
)
```

References contain only stable identity:

```elixir
Chronicle.actor("user", user.id)
Chronicle.ref("account", account.id)
```

Explicit sensitive markers work in arbitrary nested event data:

```elixir
%{
  credential: Chronicle.secret(value),
  fingerprint: Chronicle.hash(value),
  payload: Chronicle.omit()
}
```

`hash/1` is for correlating a value across records, not for hiding it; see the
caveat under [Protected fields](#protected-fields).

## Phoenix context

Place the plug after authentication:

```elixir
plug Chronicle.Phoenix.Plug,
  actor_assign: :current_user,
  tenant_assign: :current_account
```

It establishes actor, tenant, and request correlation, and records request
provenance — method, path, remote IP, request id — under `metadata["http"]`. It
does not automatically audit every controller action. Application code records the
business fact where its meaning is known.

`Chronicle.Task` propagates context to awaited tasks. Detached work should carry
serializable context explicitly; `Chronicle.Oban` provides helpers for that.

## Verification and external checkpoints

Verify every ledger in the configured store:

```elixir
Chronicle.verify_all()
```

Verification performs fixed-size batches rather than one payload query per
ledger entry:

```elixir
Chronicle.verify_all(:primary, verification_batch_size: 1_000)
```

For rollback detection, implement `Chronicle.CheckpointStore` using a system
outside the audit database and supervise the verifier:

```elixir
children = [
  {Chronicle.Verifier,
   name: MyApp.AuditVerifier,
   store: :primary,
   checkpoint_store: MyApp.ExternalAuditCheckpoints}
]
```

`Chronicle.health/2` reports whether the next entry can be signed, whether any
key needed to verify existing history is unresolvable, cached verifier status,
and external checkpoint lag — without launching a full verification. It is
unhealthy if the store cannot be written to, even when there is no history yet
to verify.

## Key rotation

The short `signing_key` configuration is for an unrotated key. Before rotation,
declare all verification keys and their sequence epochs explicitly:

```elixir
config :chronicle,
  repo: MyApp.Repo,
  integrity: [
    ledger: "primary",
    keys: %{
      "audit-2026-07" => {:system, "AUDIT_KEY_2026_07_BASE64", :base64},
      "audit-2026-10" => {:system, "AUDIT_KEY_2026_10_BASE64", :base64}
    },
    key_epochs: %{
      "audit-2026-07" => [from: 1, through: 90_000],
      "audit-2026-10" => [from: 90_001]
    }
  ]
```

Inspect and prepare rotation with:

```console
mix chronicle.keys.rotate --key-id audit-2026-10
```

Appending a transition is explicit:

```console
mix chronicle.keys.rotate --key-id audit-2026-10 --append-transition
```

The transition is authenticated by both the active key and proof from the new
key. Historical keys remain necessary for full verification.

Chronicle uses OTP `:crypto` for SHA-256 and HMAC-SHA-256. Digestif is a
password-hashing library and is deliberately not used for ledger primitives;
password hashing and authenticated audit chaining solve different problems.

## Named stores and advanced configuration

Most applications should use one configured Repo. Applications with genuinely
different trust boundaries may configure named stores:

```elixir
config :chronicle,
  default_store: :primary,
  stores: [
    primary: [
      provider: Chronicle.Provider.Ecto,
      repo: MyApp.Repo,
      integrity: [key_id: "primary", key: {:system, "PRIMARY_AUDIT_KEY"}]
    ],
    security: [
      provider: Chronicle.Provider.Ecto,
      repo: MyApp.SecurityRepo,
      integrity: [key_id: "security", key: {:system, "SECURITY_AUDIT_KEY"}]
    ]
  ]
```

Custom table names, prefixes, keyrings, KMS resolution, checkpoint stores, and
provider selection are advanced options because each introduces an operational
decision and a larger test matrix.

## Performance

The hot path performs the domain mutation, audit event insert, ledger-entry
insert, and ledger-head advancement in one transaction. The single locked
ledger head establishes total order and is the concurrency boundary.

Writers take the ledger position before building the row, so every signed
record commits to its own place in the chain and stores that position. Reads
therefore never join the ledger-entry table to establish order: history,
timeline, and cursor pagination are index-only on the record tables, and a
record's version number is computed in the same statement that returns the
page.

`bench/postgres.exs` is a reproducible PostgreSQL benchmark:

```console
CHRONICLE_BENCH_DATABASE_URL=ecto://postgres:postgres@localhost/chronicle_bench \
CHRONICLE_BENCH_WRITES=1000 \
CHRONICLE_BENCH_CONCURRENCY=16 \
mix run bench/postgres.exs
```

On a local disposable PostgreSQL 17 container, 500 measured writes produced:

| Concurrency | Writes/s | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|
| 1 | 548 | 1.77 ms | 2.12 ms | 2.40 ms |
| 8 | 788 | 5.82 ms | 30.93 ms | 45.28 ms |
| 32 | 702 | 7.94 ms | 171.53 ms | 219.13 ms |

These numbers describe one development machine, not a product guarantee. They
show the actual trade-off: low single-write overhead and a simple total order,
followed by lock contention at high concurrency. Partitioned integrity streams
should be introduced only for a workload with an explicit latency or throughput
budget that this design misses.

## Running the test suite

SQLite covers the portable paths and needs no setup. PostgreSQL covers the one
the concurrency model depends on — the ledger-head row lock — which SQLite
cannot execute:

```console
mix test
CHRONICLE_TEST_DATABASE_URL=ecto://postgres:postgres@localhost/chronicle_test mix test
```

Without a reachable server the PostgreSQL-only tests are excluded and the run
says so. The suite includes an adversarial matrix that mutates every signed
column, removes and adds group children, tampers with each ledger-entry field,
reorders entries, and forges the head, asserting each is detected — and
asserting that a whole-ledger rewind is *not* detected without an external
checkpoint.

## Operational rules

- Keep signing keys outside the audit database.
- Publish checkpoints to a separate trust boundary.
- Restrict or revoke `UPDATE` and `DELETE` on audit tables for the application
  database role when operationally possible.
- Back up audit rows, ledger entries, key history, and external checkpoints.
- Treat `occurred_at` as signed application time; ledger sequence is the
  authoritative commit order.
- Run `mix chronicle.doctor` after deployment and key-configuration changes.

## License

MIT
