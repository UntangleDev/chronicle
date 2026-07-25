defmodule Chronicle.Event do
  @moduledoc """
  A single immutable audit fact.

  Events are deliberately not Ecto-specific.

  Actor, tenant, and subject are references: exactly a type and an id. A
  reference identifies, it does not describe — anything else about the party or
  the thing belongs in `data` or `metadata`.

  `data` is what this event asserts, supplied at the call site. `metadata` is
  ambient: it is inherited from `Chronicle.Context` and merged into every event
  raised while that context is in scope, so a request or job attaches its
  provenance once rather than at every call. Neither is queried; filter on the
  indexed columns — type, actor, tenant, subject, correlation, outcome, time.
  """

  alias Chronicle.{Context, ID, Reference, Value}

  @enforce_keys [:id, :type, :occurred_at]
  defstruct [
    :id,
    :group_id,
    :sequence,
    :type,
    :action,
    :outcome,
    :actor,
    :tenant,
    :subject,
    :correlation_id,
    :occurred_at,
    :duration_us,
    :error,
    data: %{},
    metadata: %{}
  ]

  @type outcome :: :unknown | :success | :failure | String.t()
  @type t :: %__MODULE__{
          id: String.t(),
          group_id: String.t() | nil,
          sequence: non_neg_integer() | nil,
          type: String.t(),
          action: String.t() | nil,
          outcome: outcome(),
          actor: map() | nil,
          tenant: map() | nil,
          subject: map() | nil,
          correlation_id: String.t() | nil,
          occurred_at: DateTime.t(),
          duration_us: non_neg_integer() | nil,
          error: map() | nil,
          data: map(),
          metadata: map()
        }

  # Fields the caller may set on an event, plus the routing and adapter
  # options that legitimately travel alongside them. Anything else is a
  # mistake worth reporting: unknown keys used to be dropped silently, which
  # turned `record("type", user_id: 1)` into an event with no data at all.
  @options [
    :id,
    :group_id,
    :sequence,
    :type,
    :action,
    :outcome,
    :actor,
    :tenant,
    :subject,
    :correlation_id,
    :occurred_at,
    :duration_us,
    :error,
    :data,
    :metadata,
    :parent_id,
    :started_at,
    :store,
    :provider,
    :provider_options,
    :repo_options,
    :prefix,
    :immediate,
    :buffer,
    :classify,
    :redact,
    :ecto_options,
    :transaction_options
  ]

  @doc false
  @spec validate_options!(keyword(), String.t()) :: :ok
  def validate_options!(opts, context) when is_list(opts) do
    case Keyword.keys(opts) -- @options do
      [] ->
        :ok

      unknown ->
        raise ArgumentError,
              "#{context} received unknown option(s) #{inspect(unknown)}. " <>
                "Audit data must be a map: #{context}(type, %{...}, opts). " <>
                "Known options are #{inspect(@options)}."
    end
  end

  @spec new(String.t(), map(), keyword()) :: t()
  def new(type, data \\ %{}, opts \\ [])

  def new(type, data, opts)
      when is_binary(type) and byte_size(type) > 0 and is_map(data) and is_list(opts) do
    validate_options!(opts, "Chronicle.record")
    context = Context.get()

    %__MODULE__{
      id: Keyword.get(opts, :id, ID.generate()),
      group_id: Keyword.get(opts, :group_id),
      sequence: Keyword.get(opts, :sequence),
      type: type,
      action: optional_string(opts[:action]),
      outcome: normalize_outcome(Keyword.get(opts, :outcome, :unknown)),
      actor: contextual_map(opts, context, :actor),
      tenant: contextual_map(opts, context, :tenant),
      subject: contextual_map(opts, context, :subject),
      correlation_id: contextual_value(opts, context, :correlation_id),
      occurred_at: Keyword.get(opts, :occurred_at, DateTime.utc_now()),
      duration_us: Keyword.get(opts, :duration_us),
      error: opts |> Keyword.get(:error) |> normalize_optional_map(),
      data: Value.normalize(data),
      metadata: contextual_metadata(opts, context)
    }
  end

  def new(type, data, opts) do
    raise ArgumentError,
          "expected a non-empty event type, map data, and keyword options, got: " <>
            "#{inspect(type)}, #{inspect(data)}, #{inspect(opts)}"
  end

  @spec put_group(t(), String.t(), non_neg_integer()) :: t()
  def put_group(%__MODULE__{} = event, group_id, sequence) do
    %{event | group_id: group_id, sequence: sequence}
  end

  defp contextual_map(opts, context, key) do
    case Keyword.fetch(opts, key) do
      {:ok, nil} -> nil
      {:ok, value} -> normalize_reference_or_value(key, value)
      :error -> normalize_reference_or_value(key, Map.get(context, key))
    end
  end

  defp contextual_metadata(opts, context) do
    context_metadata = context |> Map.get(:metadata, %{}) |> Value.normalize()
    event_metadata = opts |> Keyword.get(:metadata, %{}) |> Value.normalize()
    Map.merge(context_metadata, event_metadata)
  end

  defp contextual_value(opts, context, key) do
    opts |> Keyword.get(key, Map.get(context, key)) |> optional_string()
  end

  defp normalize_optional_map(nil), do: nil
  defp normalize_optional_map(value), do: Value.normalize(value)

  defp normalize_reference_or_value(_key, nil), do: nil

  defp normalize_reference_or_value(key, value) when key in [:actor, :tenant, :subject],
    do: Reference.resolve(value)

  defp normalize_reference_or_value(_key, value), do: normalize_optional_map(value)

  @doc false
  @spec normalize_outcome(term()) :: outcome()
  def normalize_outcome(value) when value in [:unknown, :success, :failure], do: value
  def normalize_outcome(value) when is_binary(value) and byte_size(value) > 0, do: value

  def normalize_outcome(value) do
    raise ArgumentError, "invalid audit outcome: #{inspect(value)}"
  end

  defp optional_string(nil), do: nil
  defp optional_string(value) when is_binary(value), do: value
  defp optional_string(value) when is_atom(value), do: Atom.to_string(value)
  defp optional_string(value), do: to_string(value)
end
