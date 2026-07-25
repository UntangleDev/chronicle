defmodule Chronicle.Scope do
  @moduledoc false

  # Implementation of the timed-operation and grouped-unit primitives.
  # `Chronicle` is the public facade; `span/3` also backs the `Chronicle.span`
  # macro, which cannot share a name with a function in the same module.

  require Logger

  alias Chronicle.{Classifier, Context, Error, Group, Provider}
  alias Chronicle.Group.Buffer

  @spec span(String.t(), keyword(), (-> result)) :: result when result: term()
  def span(type, opts, fun) when is_binary(type) and is_list(opts) and is_function(fun, 0) do
    started = System.monotonic_time()

    result =
      try do
        fun.()
      rescue
        exception ->
          record_failed_span(type, opts, elapsed_us(started), error_map(:error, exception))
          reraise exception, __STACKTRACE__
      catch
        kind, reason ->
          record_failed_span(type, opts, elapsed_us(started), error_map(kind, reason))
          :erlang.raise(kind, reason, __STACKTRACE__)
      end

    record_span!(type, opts, classify(result, opts), elapsed_us(started), nil)
    result
  end

  @spec group(String.t(), keyword(), (-> result)) :: result when result: term()
  def group(type, opts, fun) when is_binary(type) and is_list(opts) and is_function(fun, 0) do
    if Context.current_group() do
      raise ArgumentError,
            "audit groups cannot be nested; use Chronicle.span/3 for an operation inside a group"
    end

    group = Group.new(type, opts)
    started = System.monotonic_time()
    {:ok, buffer} = Buffer.start_link(group)

    try do
      result =
        try do
          Context.with_group(buffer, fun)
        rescue
          exception ->
            finish_failed_group(buffer, group, started, error_map(:error, exception), opts)
            reraise exception, __STACKTRACE__
        catch
          kind, reason ->
            finish_failed_group(buffer, group, started, error_map(kind, reason), opts)
            :erlang.raise(kind, reason, __STACKTRACE__)
        end

      finish_group!(buffer, group, classify(result, opts), started, nil, opts)
      result
    after
      if Process.alive?(buffer), do: Agent.stop(buffer, :normal)
    end
  end

  @spec run(String.t(), keyword(), (-> result)) :: result when result: term()
  def run(type, opts, fun) when is_binary(type) and is_list(opts) and is_function(fun, 0) do
    context = opts |> Keyword.take(Context.allowed_keys()) |> Map.new()

    Context.with(Map.merge(Context.get(), context), fn -> group(type, opts, fun) end)
  end

  @doc false
  @spec telemetry(list(), map(), map()) :: :ok
  def telemetry(name, measurements, metadata),
    do: :telemetry.execute(name, measurements, metadata)

  defp record_span!(type, opts, outcome, duration, error) do
    data = Keyword.get(opts, :data, %{})

    event_opts =
      opts
      |> Keyword.drop([:data, :classify])
      |> Keyword.merge(outcome: outcome, duration_us: duration, error: error)

    Chronicle.record!(type, data, event_opts)
  end

  defp record_failed_span(type, opts, duration, error) do
    record_span!(type, opts, :failure, duration, error)
  rescue
    audit_error ->
      Logger.error(
        "failed to persist audit span while handling another failure: " <>
          Exception.message(audit_error)
      )
  end

  defp finish_group!(buffer, group, outcome, started, error, opts) do
    events = Buffer.close(buffer)
    group = Group.complete(group, outcome, elapsed_us(started), length(events), error)

    case Provider.write_group(group, events, opts) do
      :ok ->
        group_written(group, events)

      {:ok, _value} ->
        group_written(group, events)

      {:error, reason} ->
        raise Error.wrap(:write, reason, store: Chronicle.Config.store_name(opts))
    end
  end

  defp finish_failed_group(buffer, group, started, error, opts) do
    finish_group!(buffer, group, :failure, started, error, opts)
  rescue
    audit_error ->
      Logger.error(
        "failed to persist audit group while handling another failure: " <>
          Exception.message(audit_error)
      )
  end

  defp group_written(group, events) do
    telemetry(
      [:chronicle, :group, :written],
      %{event_count: length(events), duration_us: group.duration_us},
      %{group: group}
    )

    :ok
  end

  defp classify(result, opts),
    do: Classifier.classify(result, Keyword.get(opts, :classify, :default))

  defp elapsed_us(started) do
    System.monotonic_time()
    |> Kernel.-(started)
    |> System.convert_time_unit(:native, :microsecond)
  end

  defp error_map(kind, reason) do
    %{
      "kind" => to_string(kind),
      "type" => error_type(reason),
      "message" => Exception.format_banner(kind, reason)
    }
  end

  defp error_type(%{__struct__: module}), do: inspect(module)
  defp error_type(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp error_type(_reason), do: nil
end
