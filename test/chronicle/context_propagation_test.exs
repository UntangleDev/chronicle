defmodule Chronicle.ContextPropagationTest do
  @moduledoc """
  Audit context is process-local, so anything that crosses a process boundary
  has to carry it deliberately. A task that silently loses the actor produces
  an unattributed audit record, which is worse than none.
  """

  use ExUnit.Case, async: true

  alias Chronicle.{Context, Provider, Test}

  defp actor, do: Chronicle.actor("user", "u-1")

  describe "Chronicle.Task" do
    test "async carries context into the task" do
      Context.put(%{actor: actor()})

      assert %{actor: %{"id" => "u-1"}} =
               Chronicle.Task.async(fn -> Context.get() end) |> Task.await()
    end

    test "a plain Task does not, which is why the helper exists" do
      Context.put(%{actor: actor()})
      assert Task.async(fn -> Context.get() end) |> Task.await() == %{}
    end

    test "async_stream carries context to every element" do
      Context.put(%{actor: actor(), correlation_id: "corr-1"})

      actors =
        [1, 2, 3]
        |> Chronicle.Task.async_stream(fn _ -> Context.get().correlation_id end)
        |> Enum.map(fn {:ok, value} -> value end)

      assert actors == ["corr-1", "corr-1", "corr-1"]
    end

    test "supervised async_stream carries context too" do
      {:ok, supervisor} = Task.Supervisor.start_link()
      Context.put(%{correlation_id: "corr-2"})

      results =
        supervisor
        |> Chronicle.Task.async_stream([1, 2], fn _ -> Context.get().correlation_id end, [])
        |> Enum.map(fn {:ok, value} -> value end)

      assert results == ["corr-2", "corr-2"]
    end

    test "start and start_link run the wrapped function with context" do
      Context.put(%{correlation_id: "corr-3"})
      parent = self()

      {:ok, _pid} = Chronicle.Task.start(fn -> send(parent, {:started, Context.get()}) end)
      assert_receive {:started, %{correlation_id: "corr-3"}}

      {:ok, _pid} = Chronicle.Task.start_link(fn -> send(parent, {:linked, Context.get()}) end)
      assert_receive {:linked, %{correlation_id: "corr-3"}}
    end

    test "wrap/1 returns a function that restores context wherever it runs" do
      Context.put(%{correlation_id: "corr-4"})
      wrapped = Chronicle.Task.wrap(fn -> Context.get().correlation_id end)

      assert Task.async(wrapped) |> Task.await() == "corr-4"
    end

    test "events raised in a task join the surrounding group" do
      {result, entries} =
        Test.capture(fn opts ->
          Chronicle.Scope.run("bulk.review", opts, fn ->
            [1, 2]
            |> Chronicle.Task.async_stream(fn n ->
              Chronicle.record!("item.reviewed", %{n: n}, opts)
            end)
            |> Stream.run()

            :ok
          end)
        end)

      assert result == :ok
      assert [{:group, group, events}] = entries
      assert group.event_count == 2
      assert Enum.map(events, & &1.sequence) == [1, 2]
    end
  end

  describe "Chronicle.Context" do
    test "merge/1 deep merges rather than replacing" do
      Context.put(%{metadata: %{"a" => 1}})
      Context.merge(%{metadata: %{"b" => 2}})

      assert Context.get().metadata == %{"a" => 1, "b" => 2}
    end

    test "delete/1 removes a key" do
      Context.put(%{actor: actor(), correlation_id: "c"})
      Context.delete(:actor)

      refute Map.has_key?(Context.get(), :actor)
      assert Context.get().correlation_id == "c"
    end

    test "accepts keyword lists and string keys" do
      Context.put(actor: actor())
      assert Context.get().actor == actor()

      Context.put(%{"correlation_id" => "c-1"})
      assert Context.get().correlation_id == "c-1"
    end

    test "rejects a key that is not part of the context model" do
      assert_raise ArgumentError, ~r/unknown audit context key/, fn ->
        Context.put(%{nonsense: 1})
      end

      assert_raise ArgumentError, ~r/unknown audit context key/, fn ->
        Context.put(%{"nonsense" => 1})
      end
    end

    test "rejects a context that is not a map or keyword list" do
      assert_raise ArgumentError, ~r/expected audit context/, fn -> Context.put("nope") end
    end

    test "with/2 restores the previous context, including no context at all" do
      assert Context.get() == %{}

      Context.with(%{correlation_id: "inner"}, fn ->
        assert Context.get().correlation_id == "inner"
      end)

      assert Context.get() == %{}
    end

    test "capture/0 carries the active group so a task can join it" do
      captured = Context.capture()
      assert captured.group == nil
      assert captured.values == %{}
    end
  end

  describe "Chronicle.Provider" do
    test "reports a provider that does not implement the callback" do
      defmodule NotAProvider do
        @moduledoc false
      end

      event = Chronicle.Event.new("x")

      assert {:error, {:provider_missing_callback, NotAProvider, :write_event}} =
               Provider.write_event(event, provider: NotAProvider)
    end

    test "reports a provider that returns something unexpected" do
      defmodule ChattyProvider do
        @moduledoc false
        def write_event(_event, _opts), do: :surprise
      end

      assert {:error, {:invalid_provider_return, ChattyProvider, :write_event, :surprise}} =
               Provider.write_event(Chronicle.Event.new("x"), provider: ChattyProvider)
    end

    test "captures a provider that raises rather than losing the cause" do
      defmodule RaisingProvider do
        @moduledoc false
        def write_event(_event, _opts), do: raise("boom")
      end

      assert {:error, {:provider_exception, %RuntimeError{message: "boom"}, _stacktrace}} =
               Provider.write_event(Chronicle.Event.new("x"), provider: RaisingProvider)
    end

    test "captures a provider that throws" do
      defmodule ThrowingProvider do
        @moduledoc false
        def write_event(_event, _opts), do: throw(:nope)
      end

      assert {:error, {:provider_throw, :throw, :nope}} =
               Provider.write_event(Chronicle.Event.new("x"), provider: ThrowingProvider)
    end

    test "an unconfigured store is reported before the provider is reached" do
      assert {:error, {:store_not_configured, :nope}} =
               Provider.write_event(Chronicle.Event.new("x"), store: :nope)
    end
  end
end
