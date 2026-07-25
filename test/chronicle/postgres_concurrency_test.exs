defmodule Chronicle.PostgresConcurrencyTest do
  @moduledoc """
  Exercises the ledger-head row lock under real concurrency.

  The integrity model rests on one claim: a single locked ledger head
  serializes writers, so the chain cannot fork. That claim is implemented as
  `SELECT ... FOR UPDATE` in `Chronicle.Ecto.Ledger.lock_head/3`, which SQLite
  cannot run — the rest of the suite sets `lock: false`. Without this file the
  mechanism the whole design depends on is never executed.
  """

  use ExUnit.Case, async: false

  use Chronicle

  import Ecto.Query

  alias Chronicle.Ecto.Schema.{Event, LedgerEntry, LedgerHead}
  alias Chronicle.Test.Databases

  defmodule Item do
    @moduledoc false
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "items" do
      field :name, :string
    end
  end

  @moduletag :postgres
  @moduletag timeout: 120_000

  setup do
    {repo, prefix} = Databases.start!(:postgres, pool_size: 25)
    options = Databases.configure!(repo, prefix)

    Databases.create_table!(repo, prefix, "items", "id uuid PRIMARY KEY, name text")

    %{repo: repo, prefix: prefix, options: options}
  end

  defp query_options(prefix), do: [prefix: prefix, log: false]

  defp ledger_sequences(repo, prefix) do
    repo.all(
      from(entry in LedgerEntry,
        where: entry.ledger == "primary",
        order_by: entry.sequence,
        select: entry.sequence
      ),
      query_options(prefix)
    )
  end

  test "the ledger head lock is actually in force", %{options: options} do
    assert options |> Keyword.fetch!(:integrity) |> Keyword.fetch!(:lock) == true
  end

  test "concurrent writers produce one contiguous chain", %{repo: repo, prefix: prefix} do
    writers = 16
    per_writer = 8
    expected = writers * per_writer

    results =
      1..writers
      |> Task.async_stream(
        fn writer ->
          for index <- 1..per_writer do
            Chronicle.record!("concurrent.write", %{writer: writer, index: index})
          end
        end,
        max_concurrency: writers,
        timeout: 60_000,
        ordered: false
      )
      |> Enum.map(fn {:ok, events} -> events end)

    assert length(List.flatten(results)) == expected

    sequences = ledger_sequences(repo, prefix)

    # Contiguous from 1 with no gaps, no duplicates, and nothing lost.
    assert sequences == Enum.to_list(1..expected)

    assert repo.aggregate(from(e in Event, where: e.ledger == "primary"), :count, :id,
             prefix: prefix
           ) == expected

    # Every write is present exactly once.
    written =
      repo.all(from(e in Event, where: e.ledger == "primary", select: e.data), prefix: prefix)
      |> Enum.map(&{&1["writer"], &1["index"]})
      |> Enum.sort()

    assert written == Enum.sort(for w <- 1..writers, i <- 1..per_writer, do: {w, i})

    # The mutable head agrees with the verified chain.
    assert {:ok, %{"primary" => checkpoint}} = Chronicle.verify_all()
    assert checkpoint.sequence == expected

    head =
      repo.one(from(h in LedgerHead, where: h.ledger == "primary"), query_options(prefix))

    assert head.sequence == expected
    assert head.digest == checkpoint.digest
  end

  test "concurrent grouped transactions each commit atomically", %{repo: repo, prefix: prefix} do
    groups = 8
    children = 3

    1..groups
    |> Task.async_stream(
      fn index ->
        Chronicle.transaction "bulk.unit", actor: Chronicle.actor("worker", index) do
          for child <- 1..children do
            Chronicle.record!("unit.step", %{group: index, step: child})
          end

          :ok
        end
      end,
      max_concurrency: groups,
      timeout: 60_000,
      ordered: false
    )
    |> Enum.each(fn {:ok, result} -> assert result == {:ok, :ok} end)

    # One ledger entry per group, and every child bound to its own group.
    assert ledger_sequences(repo, prefix) == Enum.to_list(1..groups)

    roots =
      repo.all(from(e in Event, where: e.kind == "group", select: e.id), prefix: prefix)

    assert length(roots) == groups

    child_counts =
      repo.all(
        from(e in Event,
          where: e.kind == "event" and not is_nil(e.group_id),
          group_by: e.group_id,
          select: count(e.id)
        ),
        prefix: prefix
      )

    assert child_counts == List.duplicate(children, groups)
    assert {:ok, %{"primary" => %{sequence: ^groups}}} = Chronicle.verify_all()
  end

  test "a failing writer does not consume a ledger position", %{repo: repo, prefix: prefix} do
    Chronicle.record!("before.failure", %{})

    assert_raise RuntimeError, "boom", fn ->
      Chronicle.transaction("doomed.unit", [], fn ->
        Chronicle.record!("never.committed", %{})
        raise "boom"
      end)
    end

    Chronicle.record!("after.failure", %{})

    # The rolled-back unit leaves no row and no gap in the chain.
    assert ledger_sequences(repo, prefix) == [1, 2]

    types =
      repo.all(from(e in Event, order_by: e.ledger_sequence, select: e.type), prefix: prefix)

    assert types == ["before.failure", "after.failure"]
    assert {:ok, %{"primary" => %{sequence: 2}}} = Chronicle.verify_all()
  end

  test "concurrent Ecto record writes keep per-record history ordered", %{
    repo: repo,
    prefix: prefix
  } do
    # The store `:prefix` scopes the audit tables; the domain write carries its
    # own prefix through `:ecto_options`.
    domain = [ecto_options: [prefix: prefix]]

    {:ok, item} = Chronicle.insert(Ecto.Changeset.change(%Item{}, %{name: "v0"}), domain)

    updates = 12

    1..updates
    |> Task.async_stream(
      fn index ->
        item
        |> Ecto.Changeset.change(%{name: "v#{index}"})
        |> Chronicle.update(domain)
      end,
      max_concurrency: updates,
      timeout: 60_000,
      ordered: false
    )
    |> Enum.each(fn {:ok, result} -> assert {:ok, _} = result end)

    assert {:ok, versions} = Chronicle.history(item, limit: 100)
    assert length(versions) == updates + 1

    # Version numbers are dense and strictly ordered despite concurrent writes.
    assert Enum.map(versions, & &1.version) == Enum.to_list((updates + 1)..1//-1)

    assert ledger_sequences(repo, prefix) == Enum.to_list(1..(updates + 1))
    assert {:ok, _} = Chronicle.verify_all()
  end
end
