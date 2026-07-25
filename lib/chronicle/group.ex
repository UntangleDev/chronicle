defmodule Chronicle.Group do
  @moduledoc """
  The durable envelope for a larger audited unit of work.

  A group has its own identity and outcome and contains zero or more ordered
  `Chronicle.Event`s. Events in a group may come from unrelated mechanisms—for
  example an Ecto update, an authorization decision, and a message publish.

  A group is stored as a record row alongside its events rather than in a
  separate table: it shares their identity, actor, subject, and correlation
  columns, and adds only the child count. One signed ledger entry covers the
  group and all of its children.
  """

  alias Chronicle.{Context, Event, ID, Reference, Value}

  @enforce_keys [:id, :type, :started_at]
  defstruct [
    :id,
    :type,
    :outcome,
    :actor,
    :tenant,
    :subject,
    :correlation_id,
    :started_at,
    :ended_at,
    :duration_us,
    :error,
    :event_count,
    data: %{},
    metadata: %{}
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          type: String.t(),
          outcome: Chronicle.Event.outcome(),
          actor: map() | nil,
          tenant: map() | nil,
          subject: map() | nil,
          correlation_id: String.t() | nil,
          started_at: DateTime.t(),
          ended_at: DateTime.t() | nil,
          duration_us: non_neg_integer() | nil,
          error: map() | nil,
          event_count: non_neg_integer() | nil,
          data: map(),
          metadata: map()
        }

  @spec new(String.t(), keyword()) :: t()
  def new(type, opts \\ [])

  def new(type, opts) when is_binary(type) and byte_size(type) > 0 and is_list(opts) do
    Event.validate_options!(opts, "Chronicle.transaction")
    context = Context.get()

    %__MODULE__{
      id: Keyword.get(opts, :id, ID.generate()),
      type: type,
      outcome: :unknown,
      actor: contextual_map(opts, context, :actor),
      tenant: contextual_map(opts, context, :tenant),
      subject: contextual_map(opts, context, :subject),
      correlation_id:
        opts
        |> Keyword.get(:correlation_id, Map.get(context, :correlation_id))
        |> optional_string(),
      started_at: Keyword.get(opts, :started_at, DateTime.utc_now()),
      data: opts |> Keyword.get(:data, %{}) |> Value.normalize(),
      metadata:
        context
        |> Map.get(:metadata, %{})
        |> Value.normalize()
        |> Map.merge(opts |> Keyword.get(:metadata, %{}) |> Value.normalize())
    }
  end

  def new(type, opts) do
    raise ArgumentError,
          "expected a non-empty group type and keyword options, got: #{inspect(type)}, #{inspect(opts)}"
  end

  @spec complete(
          t(),
          Chronicle.Event.outcome(),
          non_neg_integer(),
          non_neg_integer(),
          map() | nil
        ) ::
          t()
  def complete(%__MODULE__{} = group, outcome, duration_us, event_count, error \\ nil) do
    %{
      group
      | outcome: Event.normalize_outcome(outcome),
        ended_at: ended_at(group.started_at, duration_us),
        duration_us: duration_us,
        event_count: event_count,
        error: error
    }
  end

  @doc """
  Derives the end of a unit from its start and monotonic duration.

  `duration_us` is measured monotonically, so deriving the end from it is
  consistent by construction. A second wall-clock reading could disagree with
  it, or move backwards across a clock adjustment.
  """
  @spec ended_at(DateTime.t(), non_neg_integer() | nil) :: DateTime.t() | nil
  def ended_at(_started_at, nil), do: nil

  def ended_at(%DateTime{} = started_at, duration_us),
    do: DateTime.add(started_at, duration_us, :microsecond)

  defp contextual_map(opts, context, key) do
    case Keyword.get(opts, key, Map.get(context, key)) do
      nil -> nil
      value when key in [:actor, :tenant, :subject] -> Reference.resolve(value)
      value -> Value.normalize(value)
    end
  end

  defp optional_string(nil), do: nil
  defp optional_string(value) when is_binary(value), do: value
  defp optional_string(value), do: to_string(value)
end
