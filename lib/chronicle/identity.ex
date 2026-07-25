defprotocol Chronicle.Identity do
  @moduledoc """
  Converts domain values into small, stable audit references.

  A protocol rather than a behaviour because the thing that varies is the shape
  of the data, not a choice of implementation — actors and subjects arrive as
  schema structs, plain maps, and application types that share nothing but the
  need to be named.

  The `Any` fallback tries the shapes worth guessing at and then raises. It
  does not fall back to `inspect/1` or to a generated id: a reference that
  looks plausible but points at nothing is worse than a write that stops and
  tells you the value it could not name. `Chronicle.ref/2` is the explicit way
  through for values that genuinely have no derivable identity.

  Whatever this returns is reduced to exactly one shape, `{type, id}`, by
  `Chronicle.Reference` — so there is a single place where reference identity is
  decided, and a composite key is digested rather than stored two ways.
  """

  @fallback_to_any true

  @spec audit_identity(t()) :: map()
  def audit_identity(value)
end

defimpl Chronicle.Identity, for: Any do
  def audit_identity(%{__struct__: module, id: id}) do
    %{"type" => inspect(module), "id" => id}
  end

  def audit_identity(%{id: id} = value) do
    %{"type" => Map.get(value, :type, Map.get(value, "type", "entity")), "id" => id}
  end

  def audit_identity(%{"id" => id} = value) do
    %{"type" => Map.get(value, "type", "entity"), "id" => id}
  end

  def audit_identity(value) do
    raise ArgumentError,
          "cannot derive an audit identity from #{inspect(value)}; implement Chronicle.Identity or use Chronicle.ref/2"
  end
end

defmodule Chronicle.Reference do
  @moduledoc false

  # The single place a reference becomes storable, on both the write and the
  # read path. Whatever `Chronicle.Identity` produced is reduced here to exactly
  # a type and an id, so every actor, tenant, and subject in the ledger has one
  # shape and queries can compare them without knowing where they came from.
  #
  # A scalar id is stored as itself. A composite one is stored as a digest of
  # its type and key, because a reference column has to hold one comparable
  # value — storing the parts separately would mean two columns that can
  # disagree, and storing the whole term would mean an id nothing can index or
  # match on.

  alias Chronicle.{Canonical, Digest, Value}

  @doc """
  Normalizes any value into a reference of exactly `type` and `id`.

  A reference identifies; it does not describe. Extra keys from a custom
  `Chronicle.Identity` implementation are dropped here, at the boundary, so the
  event you get back is the reference that gets stored. Put anything else in
  the event's `data` or `metadata`.

  A composite identifier — as an Ecto record with a composite primary key
  produces — becomes its `digest/1`, so every reference is a single indexable
  pair. For an Ecto record version the key columns remain readable in the
  snapshot.
  """
  @spec resolve(term()) :: map() | nil
  def resolve(nil), do: nil

  def resolve(value) do
    # One path, so a plain map, a struct, and a custom implementation all reach
    # the same shape and the same default type.
    normalized = value |> Chronicle.Identity.audit_identity() |> Value.normalize()

    %{"type" => type(normalized), "id" => id(normalized)}
  end

  @doc """
  Returns the indexable type of a reference.
  """
  @spec type(map() | nil) :: String.t() | nil
  def type(nil), do: nil

  def type(reference) when is_map(reference) do
    case fetch(reference, "type") do
      nil -> nil
      value when is_binary(value) -> value
      value -> to_string(value)
    end
  end

  @doc """
  Returns the indexable identifier of a reference.

  A scalar identifier is stored as itself. A composite identifier — a map or
  list, as an Ecto record with a composite primary key produces — is stored as
  its `digest/1`, so every reference is matchable by one column regardless of
  the shape of its key. Writers and readers must both go through this function
  or they will disagree.
  """
  @spec id(map() | nil) :: String.t() | nil
  def id(nil), do: nil

  def id(reference) when is_map(reference) do
    case fetch(reference, "id") do
      nil -> nil
      value when is_binary(value) -> value
      value when is_integer(value) or is_atom(value) -> to_string(value)
      _composite -> digest(reference)
    end
  end

  @doc """
  Returns a deterministic fingerprint of a reference's type and identifier.

  The `sha256:` prefix keeps a composite key distinguishable from a scalar one
  stored in the same column.
  """
  @spec digest(map()) :: String.t()
  def digest(reference) when is_map(reference) do
    digest =
      {:audit_reference_v1, fetch(reference, "type"), Value.canonical(fetch(reference, "id"))}
      |> Canonical.encode()
      |> Digest.sha256()

    "sha256:" <> digest
  end

  defp fetch(reference, key), do: Map.get(reference, key, Map.get(reference, atom(key)))

  defp atom("type"), do: :type
  defp atom("id"), do: :id
end
