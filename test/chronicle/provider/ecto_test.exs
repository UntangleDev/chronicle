defmodule Chronicle.Provider.EctoTest do
  use ExUnit.Case, async: true

  alias Chronicle.{Event, Group}
  alias Chronicle.Provider.Ecto, as: EctoProvider

  defmodule RepoStub do
    def transaction(fun), do: {:ok, fun.()}

    def insert_all({table, _schema}, rows, opts), do: insert_all(table, rows, opts)

    def insert_all(table, rows, opts) do
      send(self(), {:insert_all, table, rows, opts})
      {length(rows), nil}
    end

    def rollback(reason), do: throw({:rollback, reason})
  end

  defmodule SignedRepoStub do
    def transaction(fun) do
      {:ok, fun.()}
    catch
      {:rollback, reason} -> {:error, reason}
    end

    def insert_all({table, _schema}, rows, opts), do: insert_all(table, rows, opts)

    def insert_all("audit_ledger_heads", [row], _opts) do
      case Process.get({__MODULE__, :head}) do
        nil ->
          Process.put({__MODULE__, :head}, %{sequence: row.sequence, digest: row.digest})
          {1, nil}

        _head ->
          {0, nil}
      end
    end

    def insert_all("audit_ledger_entries", [row], _opts) do
      send(self(), {:ledger_entry, row})

      Process.put(
        {__MODULE__, :ledger_entries},
        Process.get({__MODULE__, :ledger_entries}, []) ++ [row]
      )

      {1, nil}
    end

    def insert_all(table, rows, opts) do
      send(self(), {:insert_all, table, rows, opts})
      Process.put({__MODULE__, table}, Process.get({__MODULE__, table}, []) ++ rows)
      {length(rows), nil}
    end

    def one(query, _opts) do
      table = source(query)

      cond do
        table == "audit_ledger_heads" ->
          head =
            Process.get({__MODULE__, :head}) ||
              raise "ledger head was not initialized"

          {head.sequence, head.digest}

        count_query?(query) and query.group_bys != [] ->
          nil

        count_query?(query) and query.joins != [] ->
          0

        count_query?(query) ->
          table
          |> stored_rows()
          |> count_rows(table)

        true ->
          table
          |> then(&Process.get({__MODULE__, &1}, []))
          |> List.first()
          |> case do
            nil -> nil
            row -> Map.delete(row, :inserted_at)
          end
      end
    end

    def all(query, _opts) do
      case source(query) do
        "audit_ledger_entries" -> Process.get({__MODULE__, :ledger_entries}, [])
        table -> Process.get({__MODULE__, table}, []) |> Enum.map(&Map.delete(&1, :inserted_at))
      end
    end

    def update_all(_query, [set: values], _opts) do
      Process.put(
        {__MODULE__, :head},
        Map.take(Map.new(values), [:sequence, :digest])
      )

      {1, nil}
    end

    def rollback(reason), do: throw({:rollback, reason})

    def tamper_first_event(fun) do
      [event | rest] = Process.get({__MODULE__, "audit_events"})
      Process.put({__MODULE__, "audit_events"}, [fun.(event) | rest])
    end

    def insert_orphan_event(event) do
      Process.put(
        {__MODULE__, "audit_events"},
        Process.get({__MODULE__, "audit_events"}, []) ++ [event]
      )
    end

    def rewind_event_ledger(%{sequence: sequence, digest: digest}) do
      Process.put(
        {__MODULE__, :ledger_entries},
        Process.get({__MODULE__, :ledger_entries}, [])
        |> Enum.filter(&(&1.sequence <= sequence))
      )

      Process.put(
        {__MODULE__, "audit_events"},
        Process.get({__MODULE__, "audit_events"}, [])
        |> Enum.take(sequence)
      )

      Process.put({__MODULE__, :head}, %{sequence: sequence, digest: digest})
    end

    def reset do
      for key <- [
            :head,
            :ledger_entries,
            "audit_events"
          ] do
        Process.delete({__MODULE__, key})
      end
    end

    defp source(%Ecto.Query{from: %{source: {source, _schema}}}), do: source

    defp count_query?(%Ecto.Query{select: %{expr: {:count, _, _}}}), do: true
    defp count_query?(_query), do: false

    defp count_rows(rows, "audit_events"), do: Enum.count(rows, &is_nil(&1.group_id))
    defp count_rows(rows, _table), do: length(rows)

    defp stored_rows("audit_ledger_entries"),
      do: Process.get({__MODULE__, :ledger_entries}, [])

    defp stored_rows(table), do: Process.get({__MODULE__, table}, [])
  end

  test "writes an individual event as an append-only row" do
    SignedRepoStub.reset()
    event = Event.new("access.granted", %{resource: "report"}, outcome: :success)
    key = :crypto.strong_rand_bytes(32)

    assert {:ok, %{sequence: 1}} =
             EctoProvider.write_event(event,
               repo: SignedRepoStub,
               integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false],
               events_table: "entries",
               prefix: "compliance"
             )

    assert_receive {:insert_all, "entries", [row], [prefix: "compliance"]}
    assert row.id == event.id
    assert row.type == "access.granted"
    assert row.data == %{"resource" => "report"}
    assert row.outcome == "success"
  end

  test "fails closed when Ecto integrity configuration is missing" do
    event = Event.new("access.granted", %{}, outcome: :success)

    assert {:error, {:ecto, %ArgumentError{}, _stacktrace}} =
             EctoProvider.write_event(event, repo: RepoStub)
  end

  test "writes a group before its ordered event rows in one transaction" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    group =
      "checkout"
      |> Group.new()
      |> Group.complete(:success, 15, 2)

    events = [
      Event.new("authorization.approved")
      |> Event.put_group(group.id, 1),
      Event.new("inventory.reserved")
      |> Event.put_group(group.id, 2)
    ]

    assert {:ok, %{sequence: 1}} =
             EctoProvider.write_group(group, events,
               repo: SignedRepoStub,
               integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false],
               events_table: "entries",
               chunk_size: 10
             )

    # The root and its children are one insert into one table.
    assert_receive {:insert_all, "entries", [group_row | event_rows], []}

    assert group_row.id == group.id
    assert group_row.kind == "group"
    assert group_row.event_count == 2
    assert is_nil(group_row.group_id)

    assert Enum.map(event_rows, & &1.sequence) == [1, 2]
    assert Enum.all?(event_rows, &(&1.group_id == group.id))
    assert Enum.all?(event_rows, &(&1.kind == "event"))
    assert Enum.all?(event_rows, &is_nil(&1.event_count))
  end

  test "serializes and signs successive writes into one ledger chain" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: SignedRepoStub,
      integrity: [ledger: "primary", key_id: "key-2026-07", key: key, lock: false]
    ]

    first = Event.new("account.created", %{id: "a-1"}, outcome: :success)
    second = Event.new("account.enabled", %{id: "a-1"}, outcome: :success)

    assert {:ok, %{sequence: 1, ledger: "primary"} = first_checkpoint} =
             EctoProvider.write_event(first, opts)

    assert_receive {:ledger_entry, first_entry}
    assert first_entry.previous_digest == nil
    assert first_entry.digest == first_checkpoint.digest
    assert first_entry.key_id == "key-2026-07"

    assert {:ok, %{sequence: 2, ledger: "primary"} = second_checkpoint} =
             EctoProvider.write_event(second, opts)

    assert_receive {:ledger_entry, second_entry}
    assert second_entry.previous_digest == first_entry.digest
    assert second_entry.digest == second_checkpoint.digest
    refute second_entry.signature == first_entry.signature
  end

  test "verifier recomputes stored content and detects tampering" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: SignedRepoStub,
      integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
    ]

    event = Event.new("account.created", %{id: "a-1"}, outcome: :success)

    assert {:ok, checkpoint} = EctoProvider.write_event(event, opts)
    assert {:ok, ^checkpoint} = Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)

    SignedRepoStub.tamper_first_event(fn row ->
      put_in(row, [:data, "id"], "attacker-value")
    end)

    assert {:error, {:content_digest_mismatch, 1}} =
             Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)
  end

  test "verifier detects an inserted record that has no signed ledger commitment" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: SignedRepoStub,
      integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
    ]

    event = Event.new("account.created", %{id: "a-1"}, outcome: :success)
    assert {:ok, _checkpoint} = EctoProvider.write_event(event, opts)

    SignedRepoStub.insert_orphan_event(%{
      id: Chronicle.ID.generate(),
      group_id: nil,
      data: %{"forged" => true}
    })

    assert {:error, {:ledger_coverage_mismatch, %{expected_records: 2, ledger_records: 1}}} =
             Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)
  end

  test "an external checkpoint detects deletion and rewind of the ledger tail" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: SignedRepoStub,
      integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
    ]

    first = Event.new("account.created", %{}, outcome: :success)
    second = Event.new("account.enabled", %{}, outcome: :success)

    assert {:ok, first_checkpoint} = EctoProvider.write_event(first, opts)
    assert {:ok, second_checkpoint} = EctoProvider.write_event(second, opts)

    SignedRepoStub.rewind_event_ledger(first_checkpoint)

    assert {:ok, ^first_checkpoint} = Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)

    assert {:error, {:checkpoint_mismatch, ^second_checkpoint}} =
             Chronicle.Ecto.Integrity.verify(
               SignedRepoStub,
               Keyword.put(opts, :checkpoint, second_checkpoint)
             )
  end

  test "a signed group commits to every ordered child event" do
    SignedRepoStub.reset()
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: SignedRepoStub,
      integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
    ]

    group =
      "checkout"
      |> Group.new()
      |> Group.complete(:success, 20, 1)

    event =
      Event.new("inventory.reserved", %{sku: "A-1"}, outcome: :success)
      |> Event.put_group(group.id, 1)

    assert {:ok, checkpoint} = EctoProvider.write_group(group, [event], opts)
    assert {:ok, ^checkpoint} = Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)

    SignedRepoStub.tamper_first_event(fn row ->
      put_in(row, [:data, "sku"], "FORGED")
    end)

    assert {:error, {:content_digest_mismatch, 1}} =
             Chronicle.Ecto.Integrity.verify(SignedRepoStub, opts)
  end
end
