defmodule Chronicle.Integrity.Entry do
  @moduledoc """
  Cryptographic commitment to one append-only audit ledger unit.

  The digests and the material they were computed from travel together, which
  is what lets `Chronicle.Integrity.verify/5` recompute an entry from the
  original payload and compare, rather than take the stored digests on trust.

  `previous_digest` is the one field outside `@enforce_keys`. The first entry
  in a ledger has no predecessor, and being a genesis entry is the only
  legitimate reason for it to be `nil`.
  """

  @enforce_keys [
    :ledger,
    :sequence,
    :kind,
    :record_id,
    :content_digest,
    :digest,
    :signature,
    :key_id,
    :algorithm,
    :canonical_version
  ]
  defstruct [
    :ledger,
    :sequence,
    :kind,
    :record_id,
    :previous_digest,
    :content_digest,
    :digest,
    :signature,
    :key_id,
    :algorithm,
    :canonical_version
  ]

  @type t :: %__MODULE__{
          ledger: String.t(),
          sequence: pos_integer(),
          kind: :event | :group,
          record_id: String.t(),
          previous_digest: String.t() | nil,
          content_digest: String.t(),
          digest: String.t(),
          signature: String.t(),
          key_id: String.t(),
          algorithm: String.t(),
          canonical_version: non_neg_integer()
        }
end

defmodule Chronicle.Integrity.Checkpoint do
  @moduledoc """
  A ledger position suitable for anchoring outside the audit database.

  Persist this value in a system with a separate trust boundary—for example
  immutable object storage, a transparency service, or a monitoring account.

  This is the only defence the library has against wholesale rollback. A chain
  proves its own internal consistency, and an attacker who truncates the ledger
  at some sequence and rewrites forward from there satisfies that perfectly.
  Comparing the live head against a position recorded somewhere they do not
  control is what turns "consistent" into "complete". Stored inside the audit
  database, a checkpoint proves nothing, because it falls to the same attacker
  in the same breath.
  """

  @enforce_keys [:ledger, :sequence]
  defstruct [:ledger, :sequence, :digest]

  @type t :: %__MODULE__{
          ledger: String.t(),
          sequence: non_neg_integer(),
          digest: String.t() | nil
        }
end

defmodule Chronicle.Integrity do
  @moduledoc """
  Hash-chain and HMAC primitives for tamper-evident audit ledgers.

  Every entry carries three separate commitments, and keeping them separate is
  the design. One combined digest would detect tampering just as reliably; it
  would not tell anyone what kind of tampering happened.

    * `content_digest` commits to what the record says. Anyone holding the
      content can recompute it, so it proves the content is unmodified and
      nothing else.
    * `digest` — the chain digest — commits to where that content sits in
      history: the ledger, the sequence number, the preceding entry's digest,
      and the content digest itself. This is the link that makes a chain.
    * `signature` is an HMAC over the chain digest. It cannot be produced
      without the key, so it is the only one of the three that says *this
      application* wrote the entry, rather than someone holding a database
      connection.

  ## The digests nest, and verification exploits that

  Each digest is computed over the one before it, so a single act of tampering
  invalidates all three: editing a payload changes the content digest, which
  changes the chain digest containing it, which changes the signature over
  that. `verify/5` therefore checks them innermost first, so the mismatch it
  reports is the root cause rather than the outermost symptom. Checking the
  signature first would be equally sound cryptographically and would answer
  `:signature_mismatch` for every possible attack, which tells an operator
  nothing about what was done to their data.

  For the same reason the cheap structural checks — sequence number, previous
  digest — run ahead of the rebuild that recomputes all three.

  ## Every hashed tuple leads with a tag

  The values handed to SHA-256 and HMAC are tuples whose first element names
  what the digest is for. That tag is domain separation: it guarantees a digest
  computed for one purpose can never verify as a digest computed for another,
  even where the remaining fields would encode identically. Without it, an
  attacker who could get a content digest accepted where a chain digest is
  expected would hold a chain that verifies over a history that never happened.

  ## The algorithm is inside the hash, not beside it

  The algorithm string and the canonical encoding version are hashed into all
  three tuples as well as being stored on the entry. Because the digests cover
  them, an entry cannot be relabelled as using a weaker scheme and still
  verify. That is what makes it safe to change either one later: entries
  written under the old rules fail loudly with `:unsupported_algorithm` or
  `:unsupported_canonical_version` instead of being checked under rules they
  were never written for.
  """

  alias Chronicle.{Canonical, Digest, Integrity.Entry, Keyring}
  alias Chronicle.Value

  @algorithm "audit-binary-v1-hmac-sha256-v2"

  # HMAC-SHA-256 is only as strong as the smaller of its key and its output.
  # Below 32 bytes the key becomes the weakest part of the construction; above
  # 64 HMAC hashes the key down itself, so demanding more buys nothing.
  @minimum_key_bytes 32

  @type integrity_options :: keyword()

  @doc """
  Computes all three commitments for one entry at a known ledger position.

  The caller supplies the position — `sequence` and the preceding entry's
  `previous_digest` — because an entry is in no position to vouch for where it
  sits. Establishing that order is the ledger's job, under a lock; this
  function only commits to what it is told.

  The signing key is fetched through the keyring using `sequence`, so a key
  configured for one epoch cannot sign outside it. There is no path here that
  produces an entry without a key: if one cannot be resolved, this returns an
  error and the surrounding write is expected to fail with it, rather than
  proceeding unsigned.
  """
  @spec build(
          :event | :group,
          String.t(),
          term(),
          pos_integer(),
          String.t() | nil,
          integrity_options()
        ) :: {:ok, Entry.t()} | {:error, term()}
  def build(kind, record_id, payload, sequence, previous_digest, opts)
      when kind in [:event, :group] and is_binary(record_id) and is_integer(sequence) and
             sequence > 0 and is_list(opts) do
    with {:ok, ledger} <- non_empty_string(Keyword.get(opts, :ledger, "default"), :ledger),
         {:ok, key} <- Keyring.current(ledger, sequence, opts) do
      build_current(
        kind,
        record_id,
        payload,
        sequence,
        previous_digest,
        Keyword.merge(opts, ledger: ledger, key_id: key.id, key: key.source)
      )
    end
  end

  defp build_current(kind, record_id, payload, sequence, previous_digest, opts) do
    with {:ok, ledger} <- non_empty_string(Keyword.get(opts, :ledger, "default"), :ledger),
         {:ok, key_id} <- non_empty_string(Keyword.get(opts, :key_id), :key_id),
         {:ok, key} <- resolve_key(Keyword.get(opts, :key)) do
      canonical_version = Canonical.version()

      # Each digest is an input to the next: content, then position, then
      # authentication. Reordering these three blocks does not compile to a
      # weaker chain, it compiles to no chain at all.
      content_digest =
        {:audit_content_v2, @algorithm, canonical_version, kind, record_id,
         Value.canonical(payload)}
        |> canonical()
        |> sha256()

      digest =
        {:audit_chain_v2, @algorithm, canonical_version, ledger, sequence, previous_digest, kind,
         record_id, content_digest}
        |> canonical()
        |> sha256()

      signature =
        {:audit_signature_v2, @algorithm, canonical_version, ledger, sequence, digest, key_id}
        |> canonical()
        |> hmac(key)

      {:ok,
       %Entry{
         ledger: ledger,
         sequence: sequence,
         kind: kind,
         record_id: record_id,
         previous_digest: previous_digest,
         content_digest: content_digest,
         digest: digest,
         signature: signature,
         key_id: key_id,
         algorithm: @algorithm,
         canonical_version: canonical_version
       }}
    end
  end

  @doc """
  Verifies content, chain position, and HMAC for one entry.

  `expected_previous` and `expected_sequence` come from the caller walking the
  ledger in order, never from the entry itself. That is the whole point: an
  entry that supplied its own expectations would verify happily after being
  renumbered or moved, and a chain of such entries would agree with itself
  about a history nobody wrote.

  The checks run cheapest and innermost first, so the error names the specific
  layer that failed — `:content_digest_mismatch` for edited content,
  `:chain_digest_mismatch` for content that is intact but relocated,
  `:signature_mismatch` for a chain rebuilt without the key. See the module
  documentation for why that ordering is load-bearing rather than tidy.
  """
  @spec verify(Entry.t(), term(), String.t() | nil, pos_integer(), binary()) ::
          :ok | {:error, term()}
  def verify(%Entry{} = entry, payload, expected_previous, expected_sequence, key_source)
      when is_binary(key_source) do
    opts = [ledger: entry.ledger, key_id: entry.key_id, key: key_source]

    with {:ok, key} <- resolve_key(key_source),
         :ok <- check(entry.sequence == expected_sequence, {:unexpected_sequence, entry.sequence}),
         :ok <-
           check(
             secure_equal?(entry.previous_digest, expected_previous),
             {:previous_digest_mismatch, entry.sequence}
           ),
         {:ok, expected} <- rebuild(entry, payload, Keyword.put(opts, :key, key)),
         :ok <-
           check(
             secure_equal?(entry.content_digest, expected.content_digest),
             {:content_digest_mismatch, entry.sequence}
           ),
         :ok <-
           check(
             secure_equal?(entry.digest, expected.digest),
             {:chain_digest_mismatch, entry.sequence}
           ),
         :ok <-
           check(
             secure_equal?(entry.signature, expected.signature),
             {:signature_mismatch, entry.sequence}
           ) do
      :ok
    end
  end

  defp rebuild(%Entry{algorithm: @algorithm, canonical_version: version} = entry, payload, opts) do
    with :ok <-
           check(
             version == Canonical.version(),
             {:unsupported_canonical_version, version}
           ) do
      build_current(
        entry.kind,
        entry.record_id,
        payload,
        entry.sequence,
        entry.previous_digest,
        opts
      )
    end
  end

  defp rebuild(%Entry{algorithm: algorithm}, _payload, _opts),
    do: {:error, {:unsupported_algorithm, algorithm}}

  @doc """
  Resolves a verification key and enforces its configured sequence epoch.

  Every lookup goes through the keyring, so a key can never authenticate an
  entry outside its declared epoch. Configure a `:keys` map with `:key_epochs`,
  the single `:key_id` and `:key` pair, or a custom `:keyring`.

  There is deliberately no way to hand a key directly to verification. An
  entry names the key that signed it, and an attacker who can edit that column
  could otherwise nominate a key of their choosing; binding the lookup to the
  sequence number is what stops a compromised or retired key from being used
  to re-sign history it was never valid for.
  """
  @spec verification_key(String.t(), pos_integer() | nil, integrity_options()) ::
          {:ok, binary()} | {:error, term()}
  def verification_key(key_id, sequence \\ nil, opts) do
    with {:ok, key} <-
           Keyring.fetch(Keyword.get(opts, :ledger, "default"), key_id, sequence, opts) do
      resolve_key(key.source)
    end
  end

  @doc false
  @spec resolve_key(term()) :: {:ok, binary()} | {:error, term()}
  def resolve_key(source) do
    result =
      case source do
        key when is_binary(key) -> {:ok, key}
        function when is_function(function, 0) -> normalize_key_result(function.())
        {:base64, encoded} when is_binary(encoded) -> decode_base64(encoded, :inline)
        {:system, variable} when is_binary(variable) -> fetch_system(variable)
        {:system, variable, :base64} when is_binary(variable) -> decode_system_base64(variable)
        nil -> {:error, :integrity_key_not_configured}
        other -> {:error, {:invalid_integrity_key_source, other}}
      end

    with {:ok, key} <- result,
         :ok <-
           check(
             byte_size(key) >= @minimum_key_bytes,
             {:integrity_key_too_short, byte_size(key), @minimum_key_bytes}
           ) do
      {:ok, key}
    end
  rescue
    # A blanket rescue, against the usual rule, for one specific reason:
    # `source` may be a caller-supplied zero-arity function, so this is a trust
    # boundary and the exception raised behind it is arbitrary. A key that
    # cannot be resolved has to fail the surrounding write with a matchable
    # reason, not escape as an exception from inside a domain transaction.
    exception -> {:error, {:integrity_key_resolution_failed, exception}}
  end

  @doc """
  Flattens an entry into a map for insertion alongside the audit row.

  The `inserted_at` stamped here sits outside every digest, and that is worth
  knowing before anyone relies on it. It records when the row reached the
  database, which is useful to an operator and worthless as evidence — a clock
  is not a witness, and whoever can edit the row can edit the timestamp. Order
  is established by `sequence` and `previous_digest`, which are signed.
  """
  @spec entry_row(Entry.t()) :: map()
  def entry_row(%Entry{} = entry) do
    entry
    |> Map.from_struct()
    |> Map.update!(:kind, &to_string/1)
    |> Map.put(:inserted_at, DateTime.utc_now())
  end

  @doc """
  Rebuilds an entry from a stored row, accepting atom or string keys.

  Rows reach this function both from Ecto schemas and from raw queries, hence
  the tolerance for either key type. Nothing is validated beyond `kind`: a row
  written under an older algorithm or canonical version reconstructs quite
  happily here and is rejected by `verify/5`, which is the layer that knows
  what "supported" means. Keeping the judgement in one place is why this
  function looks credulous.
  """
  @spec entry_from_row(map()) :: Entry.t()
  def entry_from_row(row) do
    %Entry{
      ledger: fetch(row, :ledger),
      sequence: fetch(row, :sequence),
      kind: row |> fetch(:kind) |> parse_kind(),
      record_id: fetch(row, :record_id),
      previous_digest: fetch(row, :previous_digest),
      content_digest: fetch(row, :content_digest),
      digest: fetch(row, :digest),
      signature: fetch(row, :signature),
      key_id: fetch(row, :key_id),
      algorithm: fetch(row, :algorithm),
      canonical_version:
        Map.get(row, :canonical_version, Map.get(row, "canonical_version", 0)) || 0
    }
  end

  defp canonical(term), do: Canonical.encode(term)
  defp sha256(value), do: Digest.sha256(value)
  defp hmac(value, key), do: Digest.hmac_sha256(key, value)

  # A `nil` previous_digest means genesis, not a missing value, so two of them
  # agreeing is a match rather than an absence of evidence.
  defp secure_equal?(nil, nil), do: true
  defp secure_equal?(nil, _right), do: false
  defp secure_equal?(_left, nil), do: false

  # The size guard is a precondition rather than a shortcut: `hash_equals/2`
  # raises on operands of differing length, and unequal lengths here are an
  # ordinary failed comparison, not a programmer error. Nothing leaks by
  # checking it first — every value compared through this function is a
  # fixed-width hex digest, so the length was never the secret.
  defp secure_equal?(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)
  end

  defp secure_equal?(_left, _right), do: false

  defp non_empty_string(value, _field) when is_binary(value) and byte_size(value) > 0,
    do: {:ok, value}

  defp non_empty_string(value, field), do: {:error, {:invalid_integrity_option, field, value}}

  defp normalize_key_result({:ok, key}), do: {:ok, key}
  defp normalize_key_result({:error, reason}), do: {:error, reason}
  defp normalize_key_result(key), do: {:ok, key}

  defp decode_system_base64(variable) do
    with {:ok, encoded} <- fetch_system(variable) do
      decode_base64(encoded, variable)
    end
  end

  defp decode_base64(encoded, source) do
    case Base.decode64(encoded) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, {:invalid_base64_integrity_key, source}}
    end
  end

  defp fetch_system(variable) do
    case System.fetch_env(variable) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:environment_variable_not_set, variable}}
    end
  end

  defp check(true, _error), do: :ok
  defp check(false, error), do: {:error, error}

  defp parse_kind("event"), do: :event
  defp parse_kind("group"), do: :group

  defp parse_kind(kind),
    do: raise(ArgumentError, "invalid audit integrity kind: #{inspect(kind)}")

  defp fetch(row, key), do: Map.get(row, key, Map.get(row, to_string(key)))
end
