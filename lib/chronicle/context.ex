defmodule Chronicle.Context do
  @moduledoc """
  Carries audit identity and correlation data through the current process.

  A context can be captured in one process and attached in another. This is
  deliberately explicit: Elixir process dictionary state is not inherited by
  `Task`s.

      context = Chronicle.Context.capture()

      Task.async(fn ->
        Chronicle.Context.with(context, fn ->
          Chronicle.record("email.delivered", %{message_id: id})
        end)
      end)

  If the context was captured inside an `Chronicle.group/3`, events from the task
  join that group. The group owner must await those tasks before returning.
  """

  @enforce_keys [:values]
  defstruct values: %{}, group: nil

  @type t :: %__MODULE__{values: map(), group: pid() | nil}

  @context_key {__MODULE__, :context}
  @group_key {__MODULE__, :group}
  @allowed_keys [
    :actor,
    :tenant,
    :subject,
    :correlation_id,
    :metadata
  ]

  @doc """
  Returns the context keys that audit options may carry.
  """
  @spec allowed_keys() :: [atom()]
  def allowed_keys, do: @allowed_keys

  @spec capture() :: t()
  def capture do
    %__MODULE__{values: get(), group: current_group()}
  end

  @spec get() :: map()
  def get, do: Process.get(@context_key, %{})

  @spec current_group() :: pid() | nil
  def current_group, do: Process.get(@group_key)

  @spec put(map() | keyword()) :: :ok
  def put(values) do
    Process.put(@context_key, normalize_context(values))
    :ok
  end

  @spec merge(map() | keyword()) :: :ok
  def merge(values) do
    merged = deep_merge(get(), normalize_context(values))
    Process.put(@context_key, merged)
    :ok
  end

  @spec delete(atom() | String.t()) :: :ok
  def delete(key) do
    key = normalize_key(key)
    Process.put(@context_key, Map.delete(get(), key))
    :ok
  end

  @spec with(t() | map() | keyword(), (-> result)) :: result when result: term()
  def with(context, fun) when is_function(fun, 0) do
    previous_context = Process.get(@context_key)
    previous_group = Process.get(@group_key)

    {values, group} =
      case context do
        %__MODULE__{values: values, group: group} -> {values, group}
        values -> {normalize_context(values), previous_group}
      end

    Process.put(@context_key, values)
    put_or_delete(@group_key, group)

    try do
      fun.()
    after
      restore(@context_key, previous_context)
      restore(@group_key, previous_group)
    end
  end

  @doc false
  @spec with_group(pid(), (-> result)) :: result when result: term()
  def with_group(group, fun) when is_pid(group) and is_function(fun, 0) do
    previous = Process.get(@group_key)
    Process.put(@group_key, group)

    try do
      fun.()
    after
      restore(@group_key, previous)
    end
  end

  defp normalize_context(values) when is_list(values),
    do: values |> Map.new() |> normalize_context()

  defp normalize_context(values) when is_map(values) do
    Map.new(values, fn {key, value} -> {normalize_key(key), value} end)
  end

  defp normalize_context(other) do
    raise ArgumentError,
          "expected audit context to be a map or keyword list, got: #{inspect(other)}"
  end

  defp deep_merge(left, right) do
    Map.merge(left, right, fn
      _key, left_value, right_value when is_map(left_value) and is_map(right_value) ->
        deep_merge(left_value, right_value)

      _key, _left_value, right_value ->
        right_value
    end)
  end

  defp normalize_key(key) when is_binary(key) do
    Enum.find(@allowed_keys, &(Atom.to_string(&1) == key)) ||
      raise ArgumentError, "unknown audit context key: #{inspect(key)}"
  end

  defp normalize_key(key) when key in @allowed_keys, do: key

  defp normalize_key(key) do
    raise ArgumentError,
          "unknown audit context key: #{inspect(key)}; allowed keys are #{inspect(@allowed_keys)}"
  end

  defp put_or_delete(key, nil), do: Process.delete(key)
  defp put_or_delete(key, value), do: Process.put(key, value)

  defp restore(key, nil), do: Process.delete(key)
  defp restore(key, value), do: Process.put(key, value)
end
