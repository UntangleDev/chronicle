defmodule ChronicleTest do
  use ExUnit.Case, async: true

  use Chronicle

  alias Chronicle.{Context, Event}
  alias Chronicle.Provider.Memory

  defmodule FailingProvider do
    @behaviour Chronicle.Provider

    @impl true
    def write_event(event, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:write_event, event})
      {:error, :offline}
    end

    @impl true
    def write_group(group, events, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:write_group, group, events})
      {:error, :offline}
    end
  end

  setup do
    {:ok, store} = start_supervised(Memory)
    opts = [provider: {Memory, server: store}]
    %{store: store, opts: opts}
  end

  test "records generic events with context and explicit overrides", %{store: store, opts: opts} do
    Context.with(
      %{
        actor: %{type: :service, id: 17},
        correlation_id: "corr-1",
        metadata: %{tenant: "acme", shared: "context"}
      },
      fn ->
        assert {:ok, %Event{} = event} =
                 Chronicle.record(
                   "export.completed",
                   %{rows: 23, at: ~U[2026-07-24 12:00:00Z]},
                   opts ++ [metadata: %{shared: "event"}]
                 )

        assert event.actor == %{"id" => "17", "type" => "service"}
        assert event.data["at"] == "2026-07-24T12:00:00Z"
        assert event.correlation_id == "corr-1"
        assert event.metadata == %{"tenant" => "acme", "shared" => "event"}
      end
    )

    assert [{:event, event}] = Memory.entries(store)
    assert event.type == "export.completed"
  end

  test "returns an error when no provider is configured" do
    assert {:error, %Chronicle.Error{reason: :store_not_configured, store: :primary}} =
             Chronicle.record("unconfigured")
  end

  test "groups heterogeneous and cross-task events in entry order", %{store: store, opts: opts} do
    assert :done =
             Chronicle.group("checkout", opts, fn ->
               Chronicle.record!("authorization.approved", %{policy: "checkout"})
               context = Context.capture()

               task =
                 Task.async(fn ->
                   Context.with(context, fn ->
                     Chronicle.record!("inventory.reserved", %{sku: "A-1"})
                   end)
                 end)

               assert %Event{} = Task.await(task)

               Chronicle.span("notification.request", opts, fn ->
                 :queued
               end)

               :done
             end)

    assert [{:group, group, events}] = Memory.entries(store)
    assert group.type == "checkout"
    assert group.outcome == :success
    assert group.event_count == 3
    assert Enum.map(events, & &1.sequence) == [1, 2, 3]

    assert Enum.map(events, & &1.type) == [
             "authorization.approved",
             "inventory.reserved",
             "notification.request"
           ]

    assert Enum.all?(events, &(&1.group_id == group.id))
    assert List.last(events).duration_us >= 0
  end

  test "a failed group is written and the original exception is reraised", %{
    store: store,
    opts: opts
  } do
    assert_raise RuntimeError, "domain exploded", fn ->
      Chronicle.group("dangerous.operation", opts, fn ->
        Chronicle.record!("operation.started", %{})
        raise "domain exploded"
      end)
    end

    assert [{:group, group, [event]}] = Memory.entries(store)
    assert group.outcome == :failure
    assert group.error["type"] == "RuntimeError"
    assert group.error["message"] =~ "domain exploded"
    assert event.type == "operation.started"
  end

  test "span classifies error tuples without changing the return value", %{
    store: store,
    opts: opts
  } do
    result =
      Chronicle.span(
        "payment.authorize",
        opts ++
          [
            data: %{payment_id: "pay-1"},
            classify: fn
              {:ok, _} -> :success
              {:error, _} -> :failure
            end
          ],
        fn -> {:error, :declined} end
      )

    assert result == {:error, :declined}
    assert [{:event, event}] = Memory.entries(store)
    assert event.outcome == :failure
    assert event.data == %{"payment_id" => "pay-1"}
    assert event.duration_us >= 0
  end

  test "nested groups are rejected", %{opts: opts} do
    assert_raise ArgumentError, ~r/cannot be nested/, fn ->
      Chronicle.group("outer", opts, fn ->
        Chronicle.group("inner", opts, fn -> :ok end)
      end)
    end
  end

  test "a span provider failure is not mistaken for a function failure" do
    opts = [provider: {FailingProvider, test_pid: self()}]

    assert_raise Chronicle.Error, fn ->
      Chronicle.span("provider.failure", opts, fn -> :ok end)
    end

    assert_receive {:write_event, %{outcome: :success}}
    refute_receive {:write_event, _event}
  end

  test "a group provider failure attempts one group write" do
    opts = [provider: {FailingProvider, test_pid: self()}]

    assert_raise Chronicle.Error, fn ->
      Chronicle.group("provider.failure", opts, fn ->
        Chronicle.record!("inside.group")
      end)
    end

    assert_receive {:write_group, %{outcome: :success}, [_event]}
    refute_receive {:write_group, _group, _events}
  end

  test "context is restored after with/2" do
    Context.put(actor: %{id: "outer"})

    assert_raise RuntimeError, fn ->
      Context.with(%{actor: %{id: "inner"}}, fn ->
        assert Context.get().actor.id == "inner"
        raise "stop"
      end)
    end

    assert Context.get().actor.id == "outer"
  end
end
