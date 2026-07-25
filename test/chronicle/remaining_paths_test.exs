defmodule Chronicle.RemainingPathsTest do
  @moduledoc """
  The last branches: rotation internals, doctor diagnostics against a broken
  store, snapshot type handling, and the Oban changeset helper.
  """

  use ExUnit.Case, async: false

  use Chronicle

  import ExUnit.CaptureIO

  alias Chronicle.Test.Databases

  defmodule Thing do
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "things" do
      field :name, :string
      field :amount, :decimal
      field :at, :utc_datetime_usec
      field :tags, {:array, :string}
      field :payload, :map
      field :status, Ecto.Enum, values: [:draft, :live]
    end
  end

  setup do
    {repo, prefix} = Databases.start!(:sqlite)
    key = :crypto.strong_rand_bytes(32)
    Databases.configure!(repo, prefix, key: key)

    Databases.create_table!(
      repo,
      prefix,
      "things",
      "id TEXT PRIMARY KEY, name TEXT, amount DECIMAL, at TEXT, tags TEXT, payload TEXT, status TEXT"
    )

    %{repo: repo, key: key}
  end

  describe "snapshot round-trips every column type" do
    test "reconstructs decimals, timestamps, arrays, maps, and enums" do
      attrs = %{
        name: "first",
        amount: Decimal.new("12.50"),
        at: ~U[2026-07-25 12:00:00.123456Z],
        tags: ["a", "b"],
        payload: %{"k" => "v"},
        status: :draft
      }

      {:ok, thing} = Chronicle.insert(Ecto.Changeset.change(%Thing{}, attrs))
      {:ok, thing} = Chronicle.update(Ecto.Changeset.change(thing, %{name: "second"}))

      assert {:ok, restored} = Chronicle.at(thing, version: 1)

      assert restored.name == "first"
      assert Decimal.equal?(restored.amount, Decimal.new("12.50"))
      assert restored.at == ~U[2026-07-25 12:00:00.123456Z]
      assert restored.tags == ["a", "b"]
      assert restored.payload == %{"k" => "v"}
      assert restored.status == :draft
    end

    test "a stored value that cannot be cast is reported, not coerced" do
      snapshot = valid_snapshot(%{"amount" => "not-a-number"})

      assert {:error, {:snapshot_field_invalid, :amount, _}} =
               Chronicle.Ecto.Snapshot.reify(Thing, snapshot)
    end

    test "a snapshot missing a field the schema now has is incomplete" do
      snapshot = update_in(valid_snapshot(), ["fields"], &Map.delete(&1, "tags"))

      assert {:error, {:snapshot_incomplete, [:tags]}} =
               Chronicle.Ecto.Snapshot.reify(Thing, snapshot)
    end

    test "a snapshot from a different schema or format is refused" do
      assert {:error, {:snapshot_schema_mismatch, _, _}} =
               Chronicle.Ecto.Snapshot.reify(Thing, %{valid_snapshot() | "schema" => "Other"})

      assert {:error, {:unsupported_snapshot_format, 99}} =
               Chronicle.Ecto.Snapshot.reify(Thing, %{valid_snapshot() | "format" => 99})

      assert {:error, {:schema_incompatible, _, _}} =
               Chronicle.Ecto.Snapshot.reify(Thing, %{
                 valid_snapshot()
                 | "schema_fingerprint" => "0000"
               })
    end

    test "a tombstone snapshot is refused rather than reconstructed" do
      assert {:error, :record_deleted} =
               Chronicle.Ecto.Snapshot.reify(Thing, %{valid_snapshot() | "state" => "deleted"})

      assert {:error, {:invalid_snapshot_state, "odd"}} =
               Chronicle.Ecto.Snapshot.reify(Thing, %{valid_snapshot() | "state" => "odd"})
    end

    test "an incomplete snapshot never yields attributes" do
      snapshot = %{valid_snapshot() | "complete" => false, "missing_fields" => ["name"]}

      assert {:error, {:snapshot_incomplete, [:name]}} =
               Chronicle.Ecto.Snapshot.attributes(Thing, snapshot)
    end

    defp valid_snapshot(overrides \\ %{}) do
      fields =
        %{
          "id" => Ecto.UUID.generate(),
          "name" => "n",
          "amount" => nil,
          "at" => nil,
          "tags" => nil,
          "payload" => nil,
          "status" => nil
        }
        |> Map.merge(overrides)

      %{
        "format" => 1,
        "state" => "present",
        "schema" => inspect(Thing),
        "source" => "things",
        "schema_fingerprint" => Chronicle.Ecto.Snapshot.fingerprint(Thing),
        "complete" => true,
        "missing_fields" => [],
        "fields" => fields
      }
    end
  end

  describe "doctor diagnoses a broken store" do
    test "reports a missing table" do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: Databases.SQLiteRepo,
          integrity: [
            ledger: "primary",
            key_id: "k",
            key: :crypto.strong_rand_bytes(32),
            lock: false
          ],
          events_table: "absent_events"
        ]
      )

      assert_raise Mix.Error, ~r/failing checks/, fn ->
        output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
        assert output =~ "[ERROR] events_table"
        assert output =~ "not run because required tables are missing"
      end
    end

    test "reports a key that cannot be resolved" do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: Databases.SQLiteRepo,
          integrity: [
            ledger: "primary",
            key_id: "k",
            key: {:system, "CHRONICLE_ABSENT"},
            lock: false
          ]
        ]
      )

      assert_raise Mix.Error, fn ->
        output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
        assert output =~ "[ERROR] signing_key"
      end
    end

    test "warns that FOR UPDATE is disabled on a database that supports it" do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: Databases.SQLiteRepo,
          integrity: [ledger: "primary", key_id: "k", key: :crypto.strong_rand_bytes(32)]
        ]
      )

      assert_raise Mix.Error, fn ->
        output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
        assert output =~ "ledger_lock"
      end
    end

    test "says so when there are no audited schemas rather than printing nothing" do
      output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)

      # Silence would be indistinguishable from "checked, all fine".
      assert output =~ "snapshot_coverage"
    end

    test "warns about an in-memory checkpoint store" do
      previous = Application.get_env(:chronicle, :stores)

      Application.put_env(
        :chronicle,
        :stores,
        put_in(previous, [:primary, :checkpoint_store], Chronicle.CheckpointStore.Memory)
      )

      output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
      assert output =~ "in-memory checkpoints are not a durable anchor"
    end

    test "reports a checkpoint store that does not implement the behaviour" do
      previous = Application.get_env(:chronicle, :stores)

      Application.put_env(
        :chronicle,
        :stores,
        put_in(previous, [:primary, :checkpoint_store], Enum)
      )

      assert_raise Mix.Error, fn ->
        output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
        assert output =~ "does not implement load/1 and save/2"
      end
    end
  end

  describe "rotation internals" do
    test "rotate/3 refuses a key id already current", %{key: key} do
      Chronicle.record!("a.happened", %{})

      assert {:error, %Chronicle.Error{}} =
               Chronicle.Keys.rotate(:primary, "test-key", key)
    end

    test "rotate/3 refuses an unusable new key" do
      Chronicle.record!("a.happened", %{})
      assert {:error, %Chronicle.Error{}} = Chronicle.Keys.rotate(:primary, "key-2", "too-short")
    end

    test "generate/0 produces a usable 256-bit key" do
      encoded = Chronicle.Keys.generate()
      assert {:ok, key} = Base.decode64(encoded)
      assert byte_size(key) == 32
      assert {:ok, ^key} = Chronicle.Integrity.resolve_key({:base64, encoded})
    end

    test "a transition proof binds both keys, the ledger, and the boundary" do
      key = :crypto.strong_rand_bytes(32)

      proof = Chronicle.Keys.transition_proof("primary", "a", "b", 1, 2, nil, key)

      assert proof == Chronicle.Keys.transition_proof("primary", "a", "b", 1, 2, nil, key)
      refute proof == Chronicle.Keys.transition_proof("other", "a", "b", 1, 2, nil, key)
      refute proof == Chronicle.Keys.transition_proof("primary", "a", "c", 1, 2, nil, key)
      refute proof == Chronicle.Keys.transition_proof("primary", "a", "b", 1, 3, nil, key)

      refute proof ==
               Chronicle.Keys.transition_proof(
                 "primary",
                 "a",
                 "b",
                 1,
                 2,
                 nil,
                 :crypto.strong_rand_bytes(32)
               )
    end
  end

  describe "Oban changeset helper" do
    defmodule Job do
      @moduledoc false
      use Ecto.Schema

      schema "jobs" do
        field :args, :map
      end
    end

    test "attaches context to a job changeset's args" do
      changeset = Ecto.Changeset.change(%Job{}, %{args: %{"account_id" => "a-1"}})

      attached =
        Chronicle.Context.with(%{correlation_id: "c-1"}, fn ->
          Chronicle.Oban.attach(changeset, [])
        end)

      args = Ecto.Changeset.get_field(attached, :args)
      assert args["account_id"] == "a-1"
      assert args["_audit_context"]["correlation_id"] == "c-1"

      assert Chronicle.Oban.with_context(%{args: args}, fn ->
               Chronicle.Context.get().correlation_id
             end) == "c-1"
    end
  end

  describe "version accessors" do
    test "return nil and an empty list for a non-Ecto event" do
      {_result, entries} =
        Chronicle.Test.capture(fn opts -> Chronicle.record!("plain.fact", %{}, opts) end)

      [event] = Chronicle.Test.events(entries)

      version = %Chronicle.Version{
        version: 1,
        operation: :insert,
        schema: Thing,
        event: event
      }

      assert Chronicle.Version.snapshot(version) == nil
      assert Chronicle.Version.changes(version) == []
    end
  end
end
