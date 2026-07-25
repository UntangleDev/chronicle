defmodule Chronicle.OperationsSurfaceTest do
  @moduledoc """
  Operator-facing surfaces: doctor, key inventory and rotation, health, and the
  read API. These are what someone reaches for when something is wrong, so
  their failure paths matter as much as their happy paths.
  """

  use ExUnit.Case, async: false

  use Chronicle

  import ExUnit.CaptureIO

  alias Chronicle.CheckpointStore.Memory, as: MemoryStore
  alias Chronicle.Test.Databases

  defmodule Post do
    use Ecto.Schema
    use Chronicle.Schema, redact: [:secret]

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "posts" do
      field :title, :string
      field :secret, :string
    end
  end

  setup do
    {repo, prefix} = Databases.start!(:sqlite)
    key = :crypto.strong_rand_bytes(32)
    Databases.configure!(repo, prefix, key: key)

    Databases.create_table!(repo, prefix, "posts", "id TEXT PRIMARY KEY, title TEXT, secret TEXT")

    %{repo: repo, key: key}
  end

  describe "mix chronicle.doctor" do
    test "reports a healthy store" do
      Chronicle.record!("a.happened", %{})
      output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)

      assert output =~ "[OK] store"
      assert output =~ "[OK] signing_key"
      assert output =~ "[OK] verification"
      assert output =~ "0 errors"
    end

    test "warns about an unbounded key and a missing anchor" do
      output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)

      assert output =~ "[WARNING] key_epochs"
      assert output =~ "[WARNING] checkpoint_anchor"
    end

    test "reports snapshot coverage across the host application's schemas" do
      output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
      assert output =~ "snapshot_coverage"
    end

    test "fails when the store is not configured" do
      Application.put_env(:chronicle, :stores, other: [provider: Chronicle.Provider.Ecto])
      Application.put_env(:chronicle, :default_store, :other)

      assert_raise Mix.Error, ~r/failing checks/, fn ->
        capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
      end
    end

    test "rejects an unknown store and stray arguments" do
      assert_raise Mix.Error, ~r/unknown audit store/, fn ->
        capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run(["--store", "nope"]) end)
      end

      assert_raise Mix.Error, ~r/invalid arguments/, fn ->
        capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run(["stray"]) end)
      end
    end
  end

  describe "key inventory" do
    test "reports the configured key as present and signable" do
      assert {:ok, status} = Chronicle.keys()
      assert status.missing == []
      assert status.signing == :ok
      assert status.current == "test-key"
    end

    test "reports no current key when it cannot be resolved", %{repo: repo} do
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            key_id: "k",
            key: {:system, "CHRONICLE_DEFINITELY_NOT_SET"},
            lock: false
          ]
        ]
      )

      assert {:ok, status} = Chronicle.keys()
      assert status.current == nil
      assert {:error, _reason} = status.signing
    end

    test "reports a historical key that can no longer be resolved as missing", %{repo: repo} do
      # Signed under "test-key", which the store then stops being able to resolve.
      Chronicle.record!("a.happened", %{})

      assert {:ok, %{required: ["test-key"], missing: []}} = Chronicle.keys()

      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            keys: %{"rotated-to" => {:system, "CHRONICLE_NOT_SET"}},
            key_epochs: %{"rotated-to" => [from: 1]},
            lock: false
          ]
        ]
      )

      assert {:ok, status} = Chronicle.keys()
      assert status.missing == ["test-key"]
      assert status.epoch_policy?
    end
  end

  describe "health" do
    test "reports keys, verifier, and anchor without running a verification" do
      Chronicle.record!("a.happened", %{})

      assert {:ok, health} = Chronicle.health()
      assert health.store == :primary
      assert health.keys.missing == []
      assert health.verifier.last_result == :not_running
      assert health.anchor.status == :not_configured
      refute health.healthy?
    end

    test "is healthy once a verifier has run against an anchor" do
      start_supervised!(MemoryStore)
      Chronicle.record!("a.happened", %{})

      verifier =
        start_supervised!(
          {Chronicle.Verifier,
           store: :primary,
           checkpoint_store: MemoryStore,
           interval: :manual,
           verify_on_start: false}
        )

      assert {:ok, _} = Chronicle.Verifier.verify_now(verifier)

      assert {:ok, health} =
               Chronicle.health(:primary, verifier: verifier, checkpoint_store: MemoryStore)

      assert health.healthy?
      assert health.anchor.status == :ok
      assert health.anchor.lag == %{"primary" => 0}
    end

    test "reports an anchor that lags behind the database" do
      start_supervised!(MemoryStore)
      Chronicle.record!("a.happened", %{})

      verifier =
        start_supervised!(
          {Chronicle.Verifier,
           store: :primary,
           checkpoint_store: MemoryStore,
           interval: :manual,
           verify_on_start: false}
        )

      assert {:ok, _} = Chronicle.Verifier.verify_now(verifier)
      Chronicle.record!("b.happened", %{})

      assert {:ok, health} =
               Chronicle.health(:primary, verifier: verifier, checkpoint_store: MemoryStore)

      assert health.anchor.status == :behind
      assert health.anchor.lag == %{"primary" => 1}
      refute health.healthy?
    end

    test "is unhealthy when the signing key cannot be resolved, even with no history", %{
      repo: repo
    } do
      start_supervised!(MemoryStore)

      # A fresh store: nothing signed yet, so nothing is missing — but nothing
      # can be written either, and the provider fails closed.
      Application.put_env(:chronicle, :stores,
        primary: [
          provider: Chronicle.Provider.Ecto,
          repo: repo,
          integrity: [
            ledger: "primary",
            key_id: "k",
            key: {:system, "CHRONICLE_DEFINITELY_NOT_SET"},
            lock: false
          ]
        ]
      )

      assert {:error, %Chronicle.Error{}} = Chronicle.record("blocked", %{})

      verifier =
        start_supervised!(
          {Chronicle.Verifier,
           store: :primary,
           checkpoint_store: MemoryStore,
           interval: :manual,
           verify_on_start: false}
        )

      # An empty ledger verifies and anchors cleanly, so every other signal is
      # green. Signing readiness is the only thing that catches this.
      assert {:ok, _} = Chronicle.Verifier.verify_now(verifier)

      assert {:ok, health} =
               Chronicle.health(:primary, verifier: verifier, checkpoint_store: MemoryStore)

      assert health.keys.missing == []
      assert health.anchor.status == :ok
      assert health.verifier.last_result == :ok

      assert {:error, _reason} = health.keys.signing
      refute health.healthy?
    end

    test "reports an unreachable verifier rather than crashing" do
      assert {:ok, health} = Chronicle.health(:primary, verifier: :no_such_verifier)
      assert {:unavailable, _reason} = health.verifier.last_result
    end
  end

  describe "key rotation" do
    test "plans a rotation without touching the ledger", %{repo: repo} do
      Chronicle.record!("a.happened", %{})

      output =
        capture_io(fn -> Mix.Tasks.Chronicle.Keys.Rotate.run(["--key-id", "next-key"]) end)

      assert output =~ "next-key"
      assert repo.aggregate(Chronicle.Ecto.Schema.Event, :count) == 1
      assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
    end

    test "refuses a key id already in use" do
      Chronicle.record!("a.happened", %{})

      assert_raise Mix.Error, ~r/already/, fn ->
        capture_io(fn -> Mix.Tasks.Chronicle.Keys.Rotate.run(["--key-id", "test-key"]) end)
      end
    end

    test "requires a key id" do
      assert_raise Mix.Error, ~r/--key-id/, fn ->
        capture_io(fn -> Mix.Tasks.Chronicle.Keys.Rotate.run([]) end)
      end
    end
  end

  describe "read API" do
    test "pages a timeline with an opaque cursor" do
      for n <- 1..5, do: Chronicle.record!("event.#{n}", %{n: n})

      assert {:ok, page} = Chronicle.Query.timeline([], limit: 2)
      assert length(page.items) == 2
      assert is_binary(page.next_cursor)

      assert {:ok, next} = Chronicle.Query.timeline([], limit: 2, cursor: page.next_cursor)
      assert length(next.items) == 2

      first_ids = Enum.map(page.items, & &1.record.id)
      refute Enum.any?(next.items, &(&1.record.id in first_ids))
    end

    test "rejects a corrupt or foreign cursor" do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline([], cursor: "not-a-cursor")

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline([], cursor: Base.url_encode64("junk", padding: false))
    end

    test "rejects unusable query options" do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline([], limit: 0)

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline(%{kinds: [:nonsense]})

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline(%{nonsense: 1})

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline(%{from: "yesterday"})

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.Query.timeline(%{actor: "not-a-reference"})
    end

    test "filters by actor, type, outcome, and time window" do
      actor = Chronicle.actor("user", "u-1")
      Chronicle.record!("wanted", %{}, actor: actor, outcome: :success)
      Chronicle.record!("unwanted", %{})

      assert {:ok, page} = Chronicle.Query.for_actor(actor)
      assert Enum.map(page.items, & &1.record.type) == ["wanted"]

      assert {:ok, page} = Chronicle.Query.timeline(%{type: "wanted"})
      assert length(page.items) == 1

      assert {:ok, page} = Chronicle.Query.timeline(%{outcome: "success"})
      assert length(page.items) == 1

      assert {:ok, page} =
               Chronicle.Query.timeline(%{from: ~U[2000-01-01 00:00:00Z], to: DateTime.utc_now()})

      assert length(page.items) == 2
    end

    test "reads a group with its ordered children" do
      {:ok, _} =
        Chronicle.transaction("unit", [], fn ->
          Chronicle.record!("step.one", %{})
          Chronicle.record!("step.two", %{})
          :ok
        end)

      assert {:ok, page} = Chronicle.Query.timeline(%{kinds: [:group]})
      assert [%{record: group}] = page.items

      assert {:ok, {read_group, events}} = Chronicle.Query.group(group.id)
      assert read_group.id == group.id
      assert Enum.map(events, & &1.type) == ["step.one", "step.two"]
    end

    test "reports a group that does not exist" do
      assert {:error, %Chronicle.Error{reason: :version_not_found}} =
               Chronicle.Query.group(Ecto.UUID.generate())
    end

    test "for_correlation and for_tenant filter on their own columns" do
      Chronicle.record!("with.correlation", %{}, correlation_id: "c-1")
      Chronicle.record!("with.tenant", %{}, tenant: Chronicle.ref("org", "o-1"))

      assert {:ok, page} = Chronicle.Query.for_correlation("c-1")
      assert Enum.map(page.items, & &1.record.type) == ["with.correlation"]

      assert {:ok, page} = Chronicle.Query.for_tenant(Chronicle.ref("org", "o-1"))
      assert Enum.map(page.items, & &1.record.type) == ["with.tenant"]
    end
  end

  describe "snapshot protection" do
    test "a redacted field is withheld and blocks reconstruction" do
      changeset = Ecto.Changeset.cast(%Post{}, %{title: "t", secret: "s"}, [:title, :secret])
      {:ok, post} = Chronicle.insert(changeset)

      assert {:ok, [version]} = Chronicle.history(post)
      refute version.restorable?
      assert version.missing_fields == [:secret]
      refute Chronicle.Version.snapshot(version)["fields"]["secret"]

      assert {:error, %Chronicle.Error{reason: :snapshot_incomplete}} =
               Chronicle.at(post, version: 1)
    end
  end
end
