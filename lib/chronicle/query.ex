defmodule Chronicle.Query.Page do
  @moduledoc """
  One stable, cursor-addressed page of audit timeline items.
  """

  defstruct items: [], next_cursor: nil

  @type t :: %__MODULE__{items: [Chronicle.Query.Item.t()], next_cursor: String.t() | nil}
end

defmodule Chronicle.Query.Item do
  @moduledoc """
  A tagged event or group returned by `Chronicle.Query.timeline/2`.

  `ledger_sequence` is the immutable position of the signed ledger entry.
  Grouped events share their group's ledger position and use
  `child_sequence` to provide a stable order within that position.
  """

  @enforce_keys [:kind, :ledger, :ledger_sequence, :child_sequence, :occurred_at, :record]
  defstruct [:kind, :ledger, :ledger_sequence, :child_sequence, :occurred_at, :record]

  @type t :: %__MODULE__{
          kind: :event | :group,
          ledger: String.t(),
          ledger_sequence: pos_integer(),
          child_sequence: non_neg_integer(),
          occurred_at: DateTime.t(),
          record: Chronicle.Event.t() | Chronicle.Group.t()
        }
end

defmodule Chronicle.Query do
  @moduledoc """
  Read API for Ecto-backed audit timelines.

  Filters are a map or keyword list. Supported filters include `:actor`,
  `:tenant`, `:subject`, `:correlation_id`, `:type`, `:outcome`, `:from`,
  `:to`, and `:kinds`. Reference filters accept the same values as
  `Chronicle.record/3`.

      Chronicle.Query.timeline(actor: user, limit: 50)
      Chronicle.Query.for_subject(order, from: yesterday)
      Chronicle.Query.group(group_id)

  Pages use opaque cursors backed by immutable ledger positions rather than
  user-supplied event timestamps. Do not parse or rely on their representation.
  Queries do not verify the ledger; use `Chronicle.verify_all/2` for integrity
  assurance.
  """

  alias Chronicle.{Config, Error}

  @filter_keys [
    :actor,
    :tenant,
    :subject,
    :correlation_id,
    :type,
    :outcome,
    :from,
    :to,
    :kinds
  ]

  @spec timeline(map() | keyword(), keyword()) ::
          {:ok, Chronicle.Query.Page.t()} | {:error, Error.t()}
  def timeline(filters \\ [], opts \\ []) do
    {filters, opts} = split_query_options(filters, opts)
    filters = normalize_filters(filters)

    with :ok <- validate_filters(filters),
         {:ok, store} <- Config.fetch_store(opts[:store]),
         :ok <- ecto_store(store),
         {:ok, page} <- Chronicle.Query.Ecto.timeline(store, filters, opts) do
      {:ok, page}
    else
      {:error, reason} -> {:error, Error.wrap(:query, reason, store: opts[:store])}
    end
  rescue
    exception ->
      {:error,
       Error.new(:query, {:reader_exception, exception, __STACKTRACE__}, store: opts[:store])}
  end

  @spec for_actor(term(), keyword()) :: {:ok, Chronicle.Query.Page.t()} | {:error, Error.t()}
  def for_actor(actor, opts \\ []), do: timeline([actor: actor], opts)

  @spec for_tenant(term(), keyword()) :: {:ok, Chronicle.Query.Page.t()} | {:error, Error.t()}
  def for_tenant(tenant, opts \\ []), do: timeline([tenant: tenant], opts)

  @spec for_subject(term(), keyword()) :: {:ok, Chronicle.Query.Page.t()} | {:error, Error.t()}
  def for_subject(subject, opts \\ []), do: timeline([subject: subject], opts)

  @spec for_correlation(String.t(), keyword()) ::
          {:ok, Chronicle.Query.Page.t()} | {:error, Error.t()}
  def for_correlation(correlation_id, opts \\ []),
    do: timeline([correlation_id: correlation_id], opts)

  @spec group(String.t(), keyword()) ::
          {:ok, {Chronicle.Group.t(), [Chronicle.Event.t()]}} | {:error, Error.t()}
  def group(id, opts \\ []) when is_binary(id) do
    with {:ok, store} <- Config.fetch_store(opts[:store]),
         :ok <- ecto_store(store),
         {:ok, result} <- Chronicle.Query.Ecto.group(store, id, opts) do
      {:ok, result}
    else
      {:error, reason} -> {:error, Error.wrap(:query, reason, store: opts[:store])}
    end
  rescue
    exception ->
      {:error,
       Error.new(:query, {:reader_exception, exception, __STACKTRACE__}, store: opts[:store])}
  end

  @doc false
  def encode_cursor({ledger, ledger_sequence, child_sequence, kind, id}) do
    {1, ledger, ledger_sequence, child_sequence, kind, id}
    |> :erlang.term_to_binary()
    |> Base.url_encode64(padding: false)
  end

  @doc false
  def decode_cursor(nil), do: {:ok, nil}

  def decode_cursor(cursor) when is_binary(cursor) and byte_size(cursor) <= 512 do
    with {:ok, binary} <- Base.url_decode64(cursor, padding: false),
         {1, ledger, ledger_sequence, child_sequence, kind, id}
         when is_binary(ledger) and is_integer(ledger_sequence) and ledger_sequence > 0 and
                is_integer(child_sequence) and child_sequence >= 0 and
                kind in [:event, :group] and is_binary(id) <-
           :erlang.binary_to_term(binary, [:safe]) do
      {:ok, {ledger, ledger_sequence, child_sequence, kind, id}}
    else
      _ -> {:error, :invalid_audit_cursor}
    end
  rescue
    _ -> {:error, :invalid_audit_cursor}
  end

  def decode_cursor(_cursor), do: {:error, :invalid_audit_cursor}

  defp normalize_filters(filters) when is_list(filters),
    do: filters |> Map.new() |> normalize_filters()

  defp normalize_filters(filters) when is_map(filters) do
    Enum.reduce([:actor, :tenant, :subject], filters, fn key, normalized ->
      case Map.fetch(normalized, key) do
        {:ok, value} -> Map.put(normalized, key, normalize_reference(key, value))
        :error -> normalized
      end
    end)
  rescue
    # A value that cannot be turned into a reference is the caller's filter,
    # not a store failure. `validate_filters/1` reports it as such.
    ArgumentError -> filters
  end

  defp normalize_reference(:subject, %schema{} = value) do
    if function_exported?(schema, :__schema__, 1) and
         Code.ensure_loaded?(Chronicle.Ecto.Snapshot) do
      Chronicle.Ecto.Snapshot.subject(value)
    else
      Chronicle.Reference.resolve(value)
    end
  end

  defp normalize_reference(_key, value), do: Chronicle.Reference.resolve(value)

  defp validate_filters(filters) do
    with [] <- Map.keys(filters) -- @filter_keys,
         :ok <- validate_reference_filter(filters, :actor),
         :ok <- validate_reference_filter(filters, :tenant),
         :ok <- validate_reference_filter(filters, :subject),
         :ok <- validate_datetime_filter(filters, :from),
         :ok <- validate_datetime_filter(filters, :to) do
      :ok
    else
      [unknown | _] -> {:error, {:invalid_query_filter, unknown}}
      {:error, _reason} = error -> error
    end
  end

  defp validate_reference_filter(filters, key) do
    case Map.fetch(filters, key) do
      :error ->
        :ok

      {:ok, reference} when is_map(reference) ->
        if reference_value(reference, "type") && reference_value(reference, "id"),
          do: :ok,
          else: {:error, {:invalid_query_filter, key}}

      {:ok, _reference} ->
        {:error, {:invalid_query_filter, key}}
    end
  end

  defp validate_datetime_filter(filters, key) do
    case Map.fetch(filters, key) do
      :error -> :ok
      {:ok, %DateTime{}} -> :ok
      {:ok, _value} -> {:error, {:invalid_query_filter, key}}
    end
  end

  defp reference_value(reference, key),
    do: Map.get(reference, key, Map.get(reference, String.to_existing_atom(key)))

  defp ecto_store(%{provider: Chronicle.Provider.Ecto, name: name}) do
    if Code.ensure_loaded?(Chronicle.Query.Ecto),
      do: :ok,
      else: {:error, {:ecto_query_not_available, name}}
  end

  defp ecto_store(%{name: name}), do: {:error, {:ecto_query_not_supported, name}}

  defp split_query_options(filters, opts) when is_map(filters), do: {filters, opts}

  defp split_query_options(filters, opts) when is_list(filters) do
    query_option_keys = [:store, :limit, :cursor]
    {query_opts, actual_filters} = Keyword.split(filters, query_option_keys)
    {actual_filters, Keyword.merge(query_opts, opts)}
  end
end
