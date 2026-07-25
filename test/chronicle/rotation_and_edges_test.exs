defmodule Chronicle.RotationAndEdgesTest do
  @moduledoc """
  Key rotation is the riskiest operational procedure the library offers, and
  the remaining edges of the write path. A rotation that leaves the chain
  unverifiable is unrecoverable, so the cutover is covered end to end.
  """

  use ExUnit.Case, async: false

  use Chronicle

  import ExUnit.CaptureIO

  alias Chronicle.CheckpointStore.Memory, as: MemoryStore
  alias Chronicle.Test.Databases

  defmodule Post do
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "posts" do
      field :title, :string
      field :blob, :binary
      field :count, :integer
    end
  end

  setup do
    {repo, prefix} = Databases.start!(:sqlite)
    key = :crypto.strong_rand_bytes(32)
    Databases.configure!(repo, prefix, key: key)

    Databases.create_table!(
      repo,
      prefix,
      "posts",
      "id TEXT PRIMARY KEY, title TEXT, blob BLOB, count INTEGER"
    )

    %{repo: repo, key: key}
  end

  describe "key rotation cutover" do
    test "appends a transition and both keys verify across the boundary", %{repo: repo, key: key} do
      Chronicle.record!("before.rotation", %{})

      output =
        capture_io(fn ->
          Mix.Tasks.Chronicle.Keys.Rotate.run(["--key-id", "key-2", "--append-transition"])
        end)

      assert output =~ "key-2"

      # The task generates the key and prints it; it is never written to disk.
      [_, encoded] = Regex.run(~r/New 256-bit Base64 key:\n(\S+)/, output)
      {:ok, new_key} = Base.decode64(encoded)

      # The transition is itself a signed record.
      assert repo.aggregate(Chronicle.Ecto.Schema.Event, :count) == 2

      # Both keys are needed from here on: the old one through the transition,
      # the new one from its activation.
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            keys: %{"test-key" => key, "key-2" => new_key},
            key_epochs: %{"test-key" => [from: 1, through: 2], "key-2" => [from: 3]},
            lock: false
          ]
        ]
      )

      assert {:ok, %{"primary" => %{sequence: 2}}} = Chronicle.verify_all()

      # Writes after the cutover use the new key and still verify.
      Chronicle.record!("after.rotation", %{})
      assert {:ok, %{"primary" => %{sequence: 3}}} = Chronicle.verify_all()
    end

    test "the reserved transition event type cannot be recorded by an application" do
      assert {:error, %Chronicle.Error{reason: :reserved_audit_event_type}} =
               Chronicle.record("chronicle.key_transition", %{})
    end

    test "an epoch that does not cover the next sequence refuses the write", %{
      repo: repo,
      key: key
    } do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            keys: %{"k" => key},
            key_epochs: %{"k" => [from: 500]},
            lock: false
          ]
        ]
      )

      assert {:error, %Chronicle.Error{reason: :signing_key_invalid}} =
               Chronicle.record("blocked", %{})
    end

    test "overlapping epochs are refused rather than picked between", %{repo: repo, key: key} do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            keys: %{"a" => key, "b" => key},
            key_epochs: %{"a" => [from: 1], "b" => [from: 1]},
            lock: false
          ]
        ]
      )

      assert {:error, %Chronicle.Error{reason: :signing_key_invalid}} =
               Chronicle.record("blocked", %{})
    end
  end

  describe "custom keyring" do
    defmodule StaticKeyring do
      @moduledoc false
      @behaviour Chronicle.Keyring

      @impl true
      def current(_ledger, _sequence, opts) do
        {:ok, %Chronicle.Key{id: "vault-key", source: Keyword.fetch!(opts, :material)}}
      end

      @impl true
      def fetch(_ledger, key_id, opts) do
        {:ok, %Chronicle.Key{id: key_id, source: Keyword.fetch!(opts, :material)}}
      end
    end

    test "supplies keys without exposing the integration to the rest of the library", %{
      repo: repo,
      key: key
    } do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [ledger: "primary", keyring: {StaticKeyring, material: key}, lock: false]
        ]
      )

      assert {:ok, _} = Chronicle.record("via.keyring", %{})
      assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
    end

    test "a keyring returning the wrong shape is reported" do
      defmodule BadKeyring do
        @moduledoc false
        @behaviour Chronicle.Keyring
        @impl true
        def current(_ledger, _sequence, _opts), do: {:ok, :not_a_key}
        @impl true
        def fetch(_ledger, _key_id, _opts), do: {:ok, :not_a_key}
      end

      assert {:error, {:invalid_keyring_result, :not_a_key}} =
               Chronicle.Keyring.current("primary", 1, keyring: BadKeyring)
    end

    test "a keyring that raises is reported, not left to crash the write" do
      defmodule RaisingKeyring do
        @moduledoc false
        @behaviour Chronicle.Keyring
        @impl true
        def current(_ledger, _sequence, _opts), do: raise("vault down")
        @impl true
        def fetch(_ledger, _key_id, _opts), do: raise("vault down")
      end

      assert {:error, {:keyring_failure, RuntimeError}} =
               Chronicle.Keyring.current("primary", 1, keyring: RaisingKeyring)
    end

    test "an unusable keyring configuration is reported rather than crashing the write" do
      assert {:error, {:keyring_failure, ArgumentError}} =
               Chronicle.Keyring.current("primary", 1, keyring: "nope")
    end

    test "a key returned under the wrong id is rejected" do
      defmodule WrongIdKeyring do
        @moduledoc false
        @behaviour Chronicle.Keyring
        @impl true
        def current(_l, _s, _o), do: {:ok, %Chronicle.Key{id: "a", source: "x"}}
        @impl true
        def fetch(_l, _key_id, _o), do: {:ok, %Chronicle.Key{id: "a", source: "x"}}
      end

      assert {:error, {:key_id_mismatch, "b", "a"}} =
               Chronicle.Keyring.fetch("primary", "b", 1, keyring: WrongIdKeyring)
    end
  end

  describe "Repo-shaped bang variants" do
    test "return the record or raise" do
      changeset = Ecto.Changeset.change(%Post{}, %{title: "t"})
      assert %Post{title: "t"} = post = Chronicle.insert!(changeset)

      assert %Post{title: "u"} =
               post = Chronicle.update!(Ecto.Changeset.change(post, %{title: "u"}))

      assert %Post{} = Chronicle.delete!(post)
    end

    test "raise on an invalid changeset" do
      invalid =
        %Post{}
        |> Ecto.Changeset.change(%{title: "t"})
        |> Ecto.Changeset.add_error(:title, "is not allowed")

      assert_raise Ecto.InvalidChangesetError, fn -> Chronicle.insert!(invalid) end
    end

    test "raise when the audit write itself fails", %{repo: repo} do
      Application.put_env(:chronicle, :stores,
        primary: [provider: Chronicle.Provider.Ecto, repo: repo]
      )

      assert_raise Chronicle.Error, fn ->
        Chronicle.insert!(Ecto.Changeset.change(%Post{}, %{title: "t"}))
      end
    end
  end

  describe "write and read against a non-Ecto store" do
    setup do
      {:ok, server} = Chronicle.Provider.Memory.start_link()

      Application.put_env(:chronicle, :stores,
        mem: [provider: Chronicle.Provider.Memory, server: server]
      )

      :ok
    end

    test "every Ecto entry point reports that it needs an Ecto store" do
      changeset = Ecto.Changeset.change(%Post{}, %{title: "t"})

      results = [
        Chronicle.insert(changeset, store: :mem),
        Chronicle.update(changeset, store: :mem),
        Chronicle.delete(changeset, store: :mem),
        Chronicle.history(Post, "id", store: :mem),
        Chronicle.at(Post, "id", store: :mem),
        Chronicle.revert(%Post{id: "id"}, store: :mem),
        Chronicle.transaction("unit", [store: :mem], fn -> :ok end)
      ]

      for result <- results do
        assert {:error, %Chronicle.Error{reason: :ecto_store_required}} = result
      end
    end

    test "keys and health also require an Ecto store" do
      assert {:error, %Chronicle.Error{}} = Chronicle.keys(:mem)
      assert {:error, %Chronicle.Error{}} = Chronicle.health(:mem)
      assert {:error, %Chronicle.Error{reason: :ecto_store_required}} = Chronicle.verify(:mem)
      assert {:error, %Chronicle.Error{reason: :ecto_store_required}} = Chronicle.checkpoint(:mem)
    end

    test "the query API reports it too" do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline([], store: :mem)

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.group("id", store: :mem)
    end
  end

  describe "checkpoint reads" do
    test "reports an uninitialised ledger" do
      assert {:error, %Chronicle.Error{reason: :ledger_not_initialized}} = Chronicle.checkpoint()
    end

    test "reads the head once something is written" do
      Chronicle.record!("a.happened", %{})
      assert {:ok, %{ledger: "primary", sequence: 1}} = Chronicle.checkpoint()
    end

    test "verify/2 checks a single ledger" do
      Chronicle.record!("a.happened", %{})
      assert {:ok, %{ledger: "primary", sequence: 1}} = Chronicle.verify()
    end
  end

  describe "snapshot value handling" do
    test "round-trips a binary that is not valid text" do
      blob = <<0, 159, 146, 150>>
      {:ok, post} = Chronicle.insert(Ecto.Changeset.change(%Post{}, %{title: "t", blob: blob}))
      {:ok, post} = Chronicle.update(Ecto.Changeset.change(post, %{title: "u"}))

      assert {:ok, restored} = Chronicle.at(post, version: 1)
      assert restored.blob == blob
    end

    test "round-trips integers and nils" do
      {:ok, post} = Chronicle.insert(Ecto.Changeset.change(%Post{}, %{title: "t", count: 42}))
      {:ok, post} = Chronicle.update(Ecto.Changeset.change(post, %{count: nil}))

      assert {:ok, first} = Chronicle.at(post, version: 1)
      assert first.count == 42

      assert {:ok, second} = Chronicle.at(post, version: 2)
      assert second.count == nil
    end

    test "a record with a nil primary key cannot be identified" do
      assert_raise ArgumentError, ~r/primary key/, fn ->
        Chronicle.Ecto.Snapshot.subject(%Post{id: nil})
      end
    end
  end

  describe "Multi event builders" do
    test "accept a type, a type and data, a type with options, or an event" do
      {:ok, changes} =
        Ecto.Multi.new()
        |> Chronicle.Multi.record(:bare, fn _ -> "bare.fact" end)
        |> Chronicle.Multi.record(:with_data, fn _ -> {"data.fact", %{n: 1}} end)
        |> Chronicle.Multi.record(:with_opts, fn _ ->
          {"opts.fact", %{}, [correlation_id: "c-1"]}
        end)
        |> Chronicle.Multi.record(:prebuilt, fn _ -> Chronicle.Event.new("prebuilt.fact") end)
        |> Databases.SQLiteRepo.transaction()

      assert map_size(changes) == 4
      assert {:ok, page} = Chronicle.Query.timeline([], limit: 10)

      types = Enum.map(page.items, & &1.record.type)
      assert "bare.fact" in types
      assert "data.fact" in types
      assert "opts.fact" in types
      assert "prebuilt.fact" in types
    end

    test "delete accepts a struct as well as a changeset" do
      {:ok, post} = Chronicle.insert(Ecto.Changeset.change(%Post{}, %{title: "t"}))

      assert {:ok, _} =
               Ecto.Multi.new()
               |> Chronicle.Multi.delete(:post, post)
               |> Databases.SQLiteRepo.transaction()

      assert {:ok, [tombstone | _]} = Chronicle.history(Post, post.id)
      assert tombstone.operation == :delete
    end
  end

  describe "group envelope" do
    test "derives its end from its monotonic duration" do
      group = Chronicle.Group.new("unit") |> Chronicle.Group.complete(:success, 1_500_000, 2)

      assert group.duration_us == 1_500_000
      assert DateTime.diff(group.ended_at, group.started_at, :microsecond) == 1_500_000
      assert group.event_count == 2
    end

    test "has no end before it completes" do
      assert Chronicle.Group.new("unit").ended_at == nil
      assert Chronicle.Group.ended_at(DateTime.utc_now(), nil) == nil
    end

    test "rejects an outcome that is not a recognised value" do
      assert_raise ArgumentError, ~r/invalid audit outcome/, fn ->
        Chronicle.Event.normalize_outcome(:nonsense)
      end

      assert Chronicle.Event.normalize_outcome("partial") == "partial"
    end

    test "rejects a malformed type" do
      assert_raise ArgumentError, ~r/expected a non-empty group type/, fn ->
        Chronicle.Group.new("")
      end

      assert_raise ArgumentError, ~r/expected a non-empty event type/, fn ->
        Chronicle.Event.new("", %{})
      end
    end
  end

  describe "in-memory checkpoint store" do
    test "reports that it is not started rather than crashing" do
      assert {:error, :checkpoint_store_not_started} = MemoryStore.load(:primary)
      assert {:error, :checkpoint_store_not_started} = MemoryStore.save(:primary, %{})
      assert {:error, :checkpoint_store_not_started} = MemoryStore.reset()
    end

    test "stores and clears checkpoints per store" do
      start_supervised!(MemoryStore)

      assert MemoryStore.load(:primary) == :not_found
      assert :ok = MemoryStore.save(:primary, %{"primary" => %{sequence: 1}})
      assert {:ok, %{"primary" => %{sequence: 1}}} = MemoryStore.load(:primary)

      assert :ok = MemoryStore.reset()
      assert MemoryStore.load(:primary) == :not_found
    end
  end
end
