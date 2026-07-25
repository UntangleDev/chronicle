defmodule Chronicle.Test do
  @moduledoc """
  Lightweight capture and inspection helpers for application tests.

      {result, entries} =
        Chronicle.Test.capture(fn audit_opts ->
          Accounts.disable(account, audit_opts)
        end)

      assert result == :ok
      assert Chronicle.Test.event?(entries, "account.disabled")

  Capture does not mutate application configuration or install hidden routing.
  Pass the supplied options to audit calls, including spawned work:

      Chronicle.Test.capture(fn audit_opts ->
        Task.async(fn -> Chronicle.record!("job.started", %{}, audit_opts) end)
        |> Task.await()
      end)
  """

  alias Chronicle.Provider.Memory

  @spec capture((keyword() -> result)) :: {result, [Memory.entry()]}
        when result: term()
  def capture(fun) when is_function(fun, 1) do
    {:ok, server} = Memory.start_link()
    options = [provider: {Memory, server: server}]

    try do
      result = fun.(options)
      {result, Memory.entries(server)}
    after
      if Process.alive?(server), do: Agent.stop(server)
    end
  end

  @spec events([Memory.entry()]) :: [Chronicle.Event.t()]
  def events(entries) do
    Enum.flat_map(entries, fn
      {:event, event} -> [event]
      {:group, _group, events} -> events
    end)
  end

  @spec groups([Memory.entry()]) :: [Chronicle.Group.t()]
  def groups(entries) do
    Enum.flat_map(entries, fn
      {:group, group, _events} -> [group]
      {:event, _event} -> []
    end)
  end

  @spec event?([Memory.entry()], String.t(), (Chronicle.Event.t() -> boolean())) :: boolean()
  def event?(entries, type, predicate \\ fn _event -> true end)
      when is_binary(type) and is_function(predicate, 1) do
    Enum.any?(events(entries), &(&1.type == type and predicate.(&1)))
  end

  @spec group?([Memory.entry()], String.t(), (Chronicle.Group.t() -> boolean())) :: boolean()
  def group?(entries, type, predicate \\ fn _group -> true end)
      when is_binary(type) and is_function(predicate, 1) do
    Enum.any?(groups(entries), &(&1.type == type and predicate.(&1)))
  end
end
