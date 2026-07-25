defmodule Chronicle.VerifierTest do
  @moduledoc """
  The verifier is the component that turns a hash chain into evidence: it is
  what actually notices a rewind, and it must only advance the anchor after a
  clean verification.
  """

  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.CheckpointStore.Memory, as: MemoryStore
  alias Chronicle.Test.Databases
  alias Chronicle.Verifier

  setup do
    {repo, prefix} = Databases.start!(:sqlite)
    Databases.configure!(repo, prefix)
    start_supervised!(MemoryStore)
    %{repo: repo}
  end

  defp start_verifier(opts) do
    start_supervised!(
      {Verifier, Keyword.merge([store: :primary, checkpoint_store: MemoryStore], opts)}
    )
  end

  test "verifies on start and advances the anchor" do
    Chronicle.record!("a.happened", %{})
    verifier = start_verifier(interval: :manual)

    assert %{last_result: :ok, checkpoints: %{"primary" => checkpoint}} =
             eventually(fn ->
               status = Verifier.status(verifier)
               if status.last_result == :ok, do: status
             end)

    assert checkpoint.sequence == 1
    assert {:ok, %{"primary" => stored}} = MemoryStore.load(:primary)
    assert stored.sequence == 1
  end

  test "verify_now/1 picks up writes made since the last run" do
    verifier = start_verifier(interval: :manual, verify_on_start: false)

    assert Verifier.status(verifier).last_result == :not_run

    Chronicle.record!("a.happened", %{})
    assert {:ok, %{"primary" => %{sequence: 1}}} = Verifier.verify_now(verifier)

    Chronicle.record!("b.happened", %{})
    assert {:ok, %{"primary" => %{sequence: 2}}} = Verifier.verify_now(verifier)
  end

  test "reports tampering and does not advance the anchor", %{repo: repo} do
    Chronicle.record!("a.happened", %{})
    verifier = start_verifier(interval: :manual, verify_on_start: false)
    assert {:ok, _} = Verifier.verify_now(verifier)

    Ecto.Adapters.SQL.query!(
      repo,
      "UPDATE audit_events SET type = 'tampered' WHERE type = 'a.happened'",
      [],
      log: false
    )

    assert {:error, %Chronicle.Error{reason: reason}} = Verifier.verify_now(verifier)
    assert reason in [:content_tampered, :ledger_tampered]

    assert {:error, %Chronicle.Error{}} = Verifier.status(verifier).last_result
    assert {:ok, %{"primary" => %{sequence: 1}}} = MemoryStore.load(:primary)
  end

  test "an on_failure function is called with the error" do
    parent = self()

    verifier =
      start_verifier(
        interval: :manual,
        verify_on_start: false,
        on_failure: fn error -> send(parent, {:failed, error}) end
      )

    Application.put_env(:chronicle, :stores, primary: [provider: Chronicle.Provider.Ecto])
    assert {:error, _} = Verifier.verify_now(verifier)
    assert_receive {:failed, %Chronicle.Error{}}
  end

  test "an on_failure callback that crashes does not take the verifier down" do
    verifier =
      start_verifier(
        interval: :manual,
        verify_on_start: false,
        on_failure: fn _error -> raise "callback boom" end
      )

    Application.put_env(:chronicle, :stores, primary: [provider: Chronicle.Provider.Ecto])

    assert {:error, _} = Verifier.verify_now(verifier)
    assert Process.alive?(verifier)
  end

  test "a checkpoint store that fails to load is reported, not ignored" do
    defmodule BrokenStore do
      @moduledoc false
      @behaviour Chronicle.CheckpointStore
      @impl true
      def load(_store), do: {:error, :unreachable}
      @impl true
      def save(_store, _checkpoints), do: :ok
    end

    Chronicle.record!("a.happened", %{})

    verifier =
      start_verifier(interval: :manual, verify_on_start: false, checkpoint_store: BrokenStore)

    assert {:error, %Chronicle.Error{reason: :checkpoint_store_failure}} =
             Verifier.verify_now(verifier)
  end

  test "a checkpoint store that fails to save is reported" do
    defmodule UnwritableStore do
      @moduledoc false
      @behaviour Chronicle.CheckpointStore
      @impl true
      def load(_store), do: :not_found
      @impl true
      def save(_store, _checkpoints), do: {:error, :read_only}
    end

    Chronicle.record!("a.happened", %{})

    verifier =
      start_verifier(interval: :manual, verify_on_start: false, checkpoint_store: UnwritableStore)

    assert {:error, %Chronicle.Error{reason: :checkpoint_store_failure}} =
             Verifier.verify_now(verifier)
  end

  test "requires a checkpoint store" do
    assert_raise ArgumentError, ~r/requires :checkpoint_store/, fn ->
      Verifier.init(store: :primary)
    end
  end

  test "rejects a checkpoint store that does not implement the behaviour" do
    assert_raise ArgumentError, ~r/must implement Chronicle.CheckpointStore/, fn ->
      Verifier.init(store: :primary, checkpoint_store: Enum)
    end
  end

  test "rejects an interval that is neither :manual nor a positive number" do
    assert_raise ArgumentError, ~r/:interval must be/, fn ->
      Verifier.init(store: :primary, checkpoint_store: MemoryStore, interval: 0)
    end
  end

  test "a scheduled interval re-runs without being asked" do
    Chronicle.record!("a.happened", %{})
    verifier = start_verifier(interval: 20)

    assert eventually(fn ->
             status = Verifier.status(verifier)
             if status.last_result == :ok, do: status
           end)

    assert Process.alive?(verifier)
  end

  test "child_spec/1 gives distinct ids per store" do
    assert Verifier.child_spec(store: :primary).id == {Verifier, :primary}
    assert Verifier.child_spec(store: :other).id == {Verifier, :other}
    assert Verifier.child_spec(id: :custom, store: :primary).id == :custom
  end

  defp eventually(fun, attempts \\ 100) do
    case fun.() do
      nil when attempts > 0 ->
        Process.sleep(10)
        eventually(fun, attempts - 1)

      nil ->
        flunk("condition never became true")

      value ->
        value
    end
  end
end
