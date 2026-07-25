defmodule Chronicle.Value.Raw do
  @moduledoc false

  # Marks a subtree that has already been normalized and protected, so
  # `Chronicle.Value.normalize/2` passes it through untouched. Without this, a
  # payload whose map keys are themselves field names (an Ecto snapshot) would
  # be protected a second time, replacing values the snapshot had already
  # accounted for in `missing_fields`.

  @enforce_keys [:value]
  defstruct [:value]

  @type t :: %__MODULE__{value: term()}
end

defmodule Chronicle.Value do
  @moduledoc false

  # The boundary between "whatever term the caller passed" and "data that can
  # be stored, encoded, and hashed". Everything downstream assumes a value has
  # already been through here: `Chronicle.Canonical` raises on structs and on
  # runtime-bearing terms, and keeping it from ever seeing one is this module's
  # job.
  #
  # Normalization is lossy by design, and the specific losses are worth
  # knowing before trusting a reconstructed value:
  #
  #   * Tuples become lists, since none of the storage formats here have
  #     tuples. `{1, 2}` and `[1, 2]` therefore normalize identically. That is
  #     not a digest collision — the digest commits to the stored form, not to
  #     the term the caller held — but the original shape is unrecoverable,
  #     and what comes back out of a reconstruction is a list.
  #   * Date and time structs become ISO 8601 strings rather than being walked
  #     as maps, which would otherwise bind the digest to whichever calendar
  #     module happened to build them.
  #   * Anything still unmatched falls through to `inspect/1`. A pid or a
  #     function becomes a string: a lossy record, but a stable one, and
  #     stability is what the digest needs. Raising instead would fail a
  #     domain write over a value nobody intended to audit in the first place.
  #
  # Protection is applied per field name during the map walk, which means it
  # only reaches values sitting under a key. A sensitive value that never sits
  # under a matching name — a bare string in a list whose own key did not
  # match — is not protected by anything here. `Chronicle.Redaction` documents
  # the matching rules; this is the shape of what they cannot see.

  alias Chronicle.Redaction
  alias Chronicle.Redaction.Policy
  alias Chronicle.Value.Raw

  # Sentinel for "drop this key entirely", as distinct from replacing it with a
  # placeholder. It survives as a bare atom only because the `:omit` clause
  # returns it directly; a caller's own `:__audit_omit__` would have gone
  # through the atom clause and become a string first, so the two cannot be
  # confused. Containers strip it after normalizing, since the decision is
  # made per field and the removal has to happen a level up.
  @omit :__audit_omit__

  @doc """
  Normalizes a term for storage, applying the protection policy by field name.

  The policy is resolved once per call rather than once per key.
  """
  @spec normalize(term(), Policy.t() | keyword()) :: term()
  def normalize(value, policy \\ [])

  def normalize(value, %Policy{} = policy), do: do_normalize(value, policy)
  def normalize(value, opts) when is_list(opts), do: do_normalize(value, Redaction.compile(opts))

  @doc """
  Normalizes a term without applying any protection policy.

  Used for integrity input, where the payload has already been protected, and
  for comparing a value against its protected form.

  Reaching for `normalize/2` here instead would protect an already-protected
  payload a second time, writing a placeholder over a value the snapshot had
  already accounted for as withheld — a corrupted snapshot that still claims
  to be complete. `Chronicle.Value.Raw` guards the same boundary from the other
  side, for subtrees that must survive a policy-bearing pass untouched.
  """
  @spec canonical(term()) :: term()
  def canonical(value), do: do_normalize(value, nil)

  defp do_normalize(%Raw{value: value}, _policy), do: value

  defp do_normalize(%Chronicle.Sensitive{strategy: :redact}, _policy), do: "[REDACTED]"
  defp do_normalize(%Chronicle.Sensitive{strategy: :omit}, _policy), do: @omit

  defp do_normalize(%Chronicle.Sensitive{strategy: :hash, value: value}, policy) do
    digest =
      value
      |> do_normalize(policy)
      |> Chronicle.Canonical.encode()
      |> Chronicle.Digest.sha256()

    "sha256:" <> digest
  end

  defp do_normalize(nil, _policy), do: nil

  defp do_normalize(value, _policy) when is_boolean(value) or is_number(value), do: value

  # Every column normalization feeds is JSON, which cannot carry arbitrary
  # bytes. Tagging them here keeps a `:binary` field storable and, because the
  # signature covers what is actually stored, keeps the digest honest.
  defp do_normalize(value, _policy) when is_binary(value) do
    if String.valid?(value),
      do: value,
      else: %{"$audit_type" => "binary", "base64" => Base.encode64(value)}
  end

  defp do_normalize(value, _policy) when is_atom(value), do: Atom.to_string(value)
  defp do_normalize(%DateTime{} = value, _policy), do: DateTime.to_iso8601(value)
  defp do_normalize(%NaiveDateTime{} = value, _policy), do: NaiveDateTime.to_iso8601(value)
  defp do_normalize(%Date{} = value, _policy), do: Date.to_iso8601(value)
  defp do_normalize(%Time{} = value, _policy), do: Time.to_iso8601(value)

  defp do_normalize(%_{} = value, policy) do
    if decimal?(value) do
      to_string(value)
    else
      value
      |> Map.from_struct()
      |> do_normalize(policy)
    end
  end

  defp do_normalize(value, policy) when is_map(value) do
    Enum.reduce(value, %{}, fn {key, item}, normalized ->
      item = if policy, do: Redaction.protect_field(policy, key, item), else: item
      item = do_normalize(item, policy)

      if item == @omit do
        normalized
      else
        Map.put(normalized, normalize_key(key), item)
      end
    end)
  end

  defp do_normalize(value, policy) when is_list(value) do
    value
    |> Enum.map(&do_normalize(&1, policy))
    |> Enum.reject(&(&1 == @omit))
  end

  defp do_normalize(value, policy) when is_tuple(value),
    do: value |> Tuple.to_list() |> do_normalize(policy)

  defp do_normalize(value, _policy), do: inspect(value)

  defp normalize_key(key) when is_binary(key), do: key
  defp normalize_key(key) when is_atom(key), do: Atom.to_string(key)

  defp normalize_key(key) do
    to_string(key)
  rescue
    Protocol.UndefinedError -> inspect(key)
  end

  # `Decimal` is an alias resolved at compile time, so this is an atom
  # comparison and holds whether or not the library is loaded.
  defp decimal?(%{__struct__: module}), do: module == Decimal
end
