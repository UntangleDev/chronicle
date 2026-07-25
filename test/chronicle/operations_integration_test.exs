defmodule Chronicle.OperationsIntegrationTest do
  use ExUnit.Case, async: false

  use Chronicle

  import ExUnit.CaptureIO
  import Ecto.Query, only: [from: 2]

  alias Chronicle.CheckpointStore.Memory, as: CheckpointMemory

  defmodule Repo do
    use Ecto.Repo,
      otp_app: :chronicle,
      adapter: Ecto.Adapters.SQLite3
  end

  defmodule Item do
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "operation_items" do
      field :name, :string
    end
  end

  defmodule CompositeItem do
    use Ecto.Schema

    @primary_key false
    schema "composite_items" do
      field :account_id, :string, primary_key: true
      field :code, :string, primary_key: true
      field :name, :string
    end
  end

  defmodule SelectiveItem do
    use Ecto.Schema
    use Chronicle.Schema, except: [:touched_at]

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "selective_items" do
      field :name, :string
      field :touched_at, :utc_datetime_usec
    end
  end

  defmodule ProtectedItem do
    use Ecto.Schema
    use Chronicle.Schema, redact: [:secret]

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "protected_items" do
      field :name, :string
      field :secret, :string
    end
  end

  setup do
    database =
      Path.join(
        System.tmp_dir!(),
        "audit-operations-#{System.unique_integer([:positive, :monotonic])}.sqlite3"
      )

    start_supervised!({Repo, database: database, pool_size: 1, log: false})
    :ok = Ecto.Migrator.up(Repo, 20_260_724_02, Chronicle.Ecto.Migration, log: false)

    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE TABLE operation_items (id TEXT PRIMARY KEY, name TEXT)",
      [],
      log: false
    )

    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE TABLE composite_items (account_id TEXT, code TEXT, name TEXT, PRIMARY KEY (account_id, code))",
      [],
      log: false
    )

    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE TABLE protected_items (id TEXT PRIMARY KEY, name TEXT, secret TEXT)",
      [],
      log: false
    )

    Ecto.Adapters.SQL.query!(
      Repo,
      "CREATE TABLE selective_items (id TEXT PRIMARY KEY, name TEXT, touched_at TEXT)",
      [],
      log: false
    )

    key = :crypto.strong_rand_bytes(32)

    previous_config =
      for config_key <- [
            :stores,
            :default_store,
            :repo,
            :signing_key,
            :key_id,
            :integrity,
            :prefix
          ],
          into: %{} do
        {config_key, Application.get_env(:chronicle, config_key, :__missing__)}
      end

    configure_store(key)

    on_exit(fn ->
      File.rm(database)
      Enum.each(previous_config, fn {config_key, value} -> restore_env(config_key, value) end)
    end)

    %{key: key}
  end

  test "ordinary Ecto.Multi operations join an ambient signed transaction group" do
    changeset = Ecto.Changeset.change(%Item{}, %{name: "first"})

    assert {:ok, %{item: item}} =
             Chronicle.transaction(
               "catalog.item_create",
               [actor: Chronicle.actor("service", "catalog")],
               fn ->
                 multi =
                   Ecto.Multi.new()
                   |> Chronicle.Multi.insert(:item, changeset)
                   |> Chronicle.Multi.record(:indexed, fn changes ->
                     {"search.index_requested", %{item_id: changes.item.id}}
                   end)

                 {:ok, changes} = Repo.transaction(multi)

                 Map.drop(changes, [
                   Chronicle.Multi.audit_name(:item),
                   Chronicle.Multi.audit_name(:indexed)
                 ])
               end
             )

    assert Repo.get!(Item, item.id).name == "first"

    [group] = Repo.all(from record in Chronicle.Ecto.Schema.Event, where: record.kind == "group")

    events =
      Repo.all(from record in Chronicle.Ecto.Schema.Event, where: record.kind == "event")

    assert group.type == "catalog.item_create"
    assert group.event_count == 2

    assert Enum.sort_by(events, & &1.sequence) |> Enum.map(& &1.type) ==
             ["ecto.operation_items.insert", "search.index_requested"]

    assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
  end

  test "transaction facade commits domain work and a signed group atomically" do
    assert {:ok, item} =
             Chronicle.transaction("catalog.item_validate", fn ->
               item = Repo.insert!(%Item{name: "validated"})
               Chronicle.record!("catalog.item_validated", %{item_id: item.id})
               item
             end)

    assert Repo.get!(Item, item.id).name == "validated"

    assert [%{type: "catalog.item_validate"}] =
             Repo.all(from record in Chronicle.Ecto.Schema.Event, where: record.kind == "group")

    assert [%{type: "catalog.item_validated"}] =
             Repo.all(from record in Chronicle.Ecto.Schema.Event, where: record.kind == "event")

    assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
  end

  test "Repo-like facade rolls domain changes back when the audit write fails" do
    Application.put_env(
      :chronicle,
      :stores,
      primary: [provider: Chronicle.Provider.Ecto, repo: Repo]
    )

    changeset = Ecto.Changeset.change(%Item{}, %{name: "must-roll-back"})

    assert {:error, %Chronicle.Error{}} = Chronicle.insert(changeset)

    assert Repo.aggregate(Item, :count) == 0
  end

  test "Repo-like facade returns invalid changesets without leaking or auditing submitted values" do
    invalid_changeset =
      %Item{}
      |> Ecto.Changeset.change(%{name: "sensitive-rejected-value"})
      |> Ecto.Changeset.add_error(:name, "is not allowed")

    assert {:error, %Ecto.Changeset{}} = Chronicle.insert(invalid_changeset)

    assert Repo.aggregate(Item, :count) == 0
    assert Repo.aggregate(Chronicle.Ecto.Schema.Event, :count) == 0
  end

  test "Repo-like writes provide history, point-in-time reads, reversion, and tombstones" do
    assert {:ok, inserted} =
             %Item{}
             |> Ecto.Changeset.change(name: "first")
             |> Chronicle.insert(actor: Chronicle.actor("user", "42"))

    assert {:ok, updated} =
             inserted
             |> Ecto.Changeset.change(name: "second")
             |> Chronicle.update(actor: Chronicle.actor("user", "42"))

    assert {:ok, [second, first]} = Chronicle.history(updated)
    assert {second.version, second.operation, second.record.name} == {2, :update, "second"}
    assert {first.version, first.operation, first.record.name} == {1, :insert, "first"}
    assert first.restorable?

    assert {:ok, historical} = Chronicle.at(Item, updated.id, version: 1)
    assert historical.id == updated.id
    assert historical.name == "first"

    assert {:ok, revert_changeset} = Chronicle.revert(updated, version: 1)
    assert Ecto.Changeset.apply_changes(revert_changeset).name == "first"

    assert {:ok, reverted} =
             Chronicle.update(revert_changeset, actor: Chronicle.actor("user", "42"))

    assert {:ok, deleted} = Chronicle.delete(reverted, actor: Chronicle.actor("user", "42"))
    assert deleted.id == reverted.id
    assert Repo.get(Item, reverted.id) == nil

    assert {:ok, [tombstone | _]} = Chronicle.history(Item, reverted.id)
    assert tombstone.version == 4
    assert tombstone.operation == :delete
    assert tombstone.record == nil

    assert {:error, %Chronicle.Error{reason: :record_deleted}} =
             Chronicle.at(Item, reverted.id, version: 4)

    assert {:ok, historical_again} = Chronicle.at(Item, reverted.id, version: 3)
    assert historical_again.name == "first"
    assert {:ok, %{"primary" => %{sequence: 4}}} = Chronicle.verify_all()
  end

  test "the common configuration is only a repo and signing key", %{key: key} do
    Application.delete_env(:chronicle, :stores)
    Application.put_env(:chronicle, :repo, Repo)
    Application.put_env(:chronicle, :signing_key, key)
    Application.put_env(:chronicle, :key_id, "simple-key")

    assert {:ok, item} =
             %Item{}
             |> Ecto.Changeset.change(name: "simple")
             |> Chronicle.insert()

    assert {:ok, [version]} = Chronicle.history(item)
    assert version.record.name == "simple"
    assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
  end

  test "composite primary keys have stable indexed record history" do
    changeset =
      Ecto.Changeset.change(%CompositeItem{},
        account_id: "account-7",
        code: "A-1",
        name: "first"
      )

    assert {:ok, item} = Chronicle.insert(changeset)

    assert {:ok, [version]} =
             Chronicle.history(CompositeItem, %{account_id: "account-7", code: "A-1"})

    # The reference carries a digest so one indexed column can identify any
    # record; the key columns themselves stay readable in the snapshot.
    assert "sha256:" <> _ = version.event.subject["id"]

    assert %{"account_id" => "account-7", "code" => "A-1"} =
             Chronicle.Version.snapshot(version)["fields"]

    assert version.record == item

    assert {:ok, ^item} =
             Chronicle.at(CompositeItem, [account_id: "account-7", code: "A-1"], version: 1)
  end

  test "protected fields fail closed instead of producing corrupt historical records" do
    assert {:ok, item} =
             %ProtectedItem{}
             |> Ecto.Changeset.change(name: "visible", secret: "never-in-a-snapshot")
             |> Chronicle.insert()

    assert {:ok, [version]} = Chronicle.history(item)
    refute version.restorable?
    assert version.missing_fields == [:secret]
    refute inspect(Chronicle.Version.snapshot(version)) =~ "never-in-a-snapshot"

    assert {:error,
            %Chronicle.Error{
              cause: {:snapshot_incomplete, [:secret]}
            }} = Chronicle.at(item, version: 1)
  end

  test "verifier advances external checkpoints and detects deletion of an entire ledger" do
    start_supervised!(CheckpointMemory)
    assert {:ok, _event} = Chronicle.record("security.baseline")
    test_pid = self()

    verifier =
      start_supervised!(
        {Chronicle.Verifier,
         store: :primary,
         checkpoint_store: CheckpointMemory,
         interval: :manual,
         verify_on_start: false,
         on_failure: &send(test_pid, {:verification_failure, &1})}
      )

    assert {:ok, %{"primary" => checkpoint}} = Chronicle.Verifier.verify_now(verifier)
    assert {:ok, %{"primary" => ^checkpoint}} = CheckpointMemory.load(:primary)

    assert {:ok, %{healthy?: true, anchor: %{status: :ok}}} =
             Chronicle.health(:primary,
               verifier: verifier,
               checkpoint_store: CheckpointMemory
             )

    Ecto.Adapters.SQL.query!(Repo, "DELETE FROM audit_events", [], log: false)
    Ecto.Adapters.SQL.query!(Repo, "DELETE FROM audit_ledger_entries", [], log: false)
    Ecto.Adapters.SQL.query!(Repo, "DELETE FROM audit_ledger_heads", [], log: false)

    assert {:error, %Chronicle.Error{reason: :checkpoint_mismatch}} =
             Chronicle.Verifier.verify_now(verifier)

    assert_receive {:verification_failure, %Chronicle.Error{reason: :checkpoint_mismatch}}
    assert {:ok, %{"primary" => ^checkpoint}} = CheckpointMemory.load(:primary)
  end

  test "health reports cached verifier absence without launching verification" do
    assert {:ok,
            %{
              healthy?: false,
              verifier: %{last_result: :not_running},
              checkpoints: %{}
            }} = Chronicle.health(:primary)
  end

  test "key status reports current, required, and unavailable historical key ids", %{key: key} do
    assert {:ok, _event} = Chronicle.record("key.one")

    Application.put_env(
      :chronicle,
      :stores,
      primary: [
        provider: Chronicle.Provider.Ecto,
        repo: Repo,
        integrity: [
          ledger: "primary",
          key_id: "key-2",
          key: :crypto.strong_rand_bytes(32),
          lock: false
        ]
      ]
    )

    assert {:ok,
            %{
              current: "key-2",
              required: ["key-1"],
              missing: ["key-1"]
            }} = Chronicle.keys()

    Application.put_env(
      :chronicle,
      :stores,
      primary: [
        provider: Chronicle.Provider.Ecto,
        repo: Repo,
        integrity: [
          ledger: "primary",
          key_id: "key-2",
          key: :crypto.strong_rand_bytes(32),
          keys: %{"key-1" => key},
          lock: false
        ]
      ]
    )

    assert {:ok, %{missing: []}} = Chronicle.keys()
  end

  test "rotation appends a dual-key transition and epochs enforce the cutover", %{key: old_key} do
    new_key = :crypto.strong_rand_bytes(32)
    assert {:ok, _event} = Chronicle.record("rotation.baseline")

    assert {:ok, plan} = Chronicle.Keys.rotate(:primary, "key-2", new_key)
    assert plan.old_key_id == "key-1"
    assert plan.new_key_id == "key-2"
    assert plan.transition_sequence == 2
    assert plan.activates_at_sequence == 3

    transition = Repo.get!(Chronicle.Ecto.Schema.Event, plan.event.id)
    assert transition.type == "chronicle.key_transition"
    assert transition.data["new_key_proof"] == plan.new_key_proof
    refute inspect(transition.data) =~ Base.encode64(new_key)

    Application.put_env(
      :chronicle,
      :stores,
      primary: [
        provider: Chronicle.Provider.Ecto,
        repo: Repo,
        integrity: [
          ledger: "primary",
          keys: %{"key-1" => old_key, "key-2" => new_key},
          key_epochs: %{
            "key-1" => [from: 1, through: 2],
            "key-2" => [from: 3]
          },
          lock: false
        ]
      ]
    )

    assert {:ok, _event} = Chronicle.record("rotation.after_cutover")
    assert {:ok, %{"primary" => %{sequence: 3}}} = Chronicle.verify_all()

    assert Repo.all(from entry in Chronicle.Ecto.Schema.LedgerEntry, order_by: entry.sequence)
           |> Enum.map(& &1.key_id) == ["key-1", "key-1", "key-2"]
  end

  test "verifier rejects a transition claim without proof from the new key" do
    event =
      Chronicle.Event.new("chronicle.key_transition", %{
        from_key_id: "key-1",
        to_key_id: "key-2",
        transition_sequence: 1,
        activates_at_sequence: 2,
        previous_digest: nil,
        new_key_proof: String.duplicate("0", 64)
      })

    {:ok, config} = Chronicle.Config.fetch_store(:primary)
    assert {:ok, _checkpoint} = Chronicle.Provider.Ecto.write_event(event, config.options)

    assert {:error, %Chronicle.Error{reason: :verification_failed, cause: cause}} =
             Chronicle.verify_all()

    assert inspect(cause) =~ "invalid_key_transition"
  end

  test "public event API reserves the cryptographic transition type" do
    assert {:error, %Chronicle.Error{reason: :reserved_audit_event_type}} =
             Chronicle.record("chronicle.key_transition", %{})
  end

  test "query API reads filtered timelines, groups, and cursors" do
    actor = Chronicle.actor("user", "42")
    tenant = Chronicle.ref("account", "acme")

    assert {:ok, _event} =
             Chronicle.record("session.signed_in", %{method: "passkey"},
               actor: actor,
               tenant: tenant,
               correlation_id: "request-1"
             )

    %Chronicle.Event{} =
      Chronicle.run(
        "order.checkout",
        [actor: actor, tenant: tenant, correlation_id: "request-1"],
        fn ->
          Chronicle.record!("payment.authorized", %{amount: 100})
        end
      )

    assert {:ok, first_page} = Chronicle.Query.for_actor(actor, limit: 1)
    assert length(first_page.items) == 1
    assert is_binary(first_page.next_cursor)

    assert {:ok, second_page} =
             Chronicle.Query.for_actor(actor, limit: 10, cursor: first_page.next_cursor)

    refute Enum.any?(second_page.items, &(&1.record.id == hd(first_page.items).record.id))

    assert {:ok, tenant_page} = Chronicle.Query.for_tenant(tenant, limit: 10)
    assert Enum.all?(tenant_page.items, &(&1.record.tenant == tenant))

    group_item = Enum.find(tenant_page.items, &(&1.kind == :group))
    assert {:ok, {group, [event]}} = Chronicle.Query.group(group_item.record.id)
    assert group.type == "order.checkout"
    assert event.type == "payment.authorized"
  end

  test "query pagination follows immutable ledger positions, not event timestamps" do
    {:ok, recent, 0} = DateTime.from_iso8601("2026-07-24T12:00:00.000000Z")
    {:ok, backdated, 0} = DateTime.from_iso8601("2001-01-01T00:00:00.000000Z")

    assert {:ok, first} = Chronicle.record("event.first", occurred_at: recent)
    assert {:ok, second} = Chronicle.record("event.appended_later", occurred_at: backdated)

    assert {:ok, page_one} = Chronicle.Query.timeline(limit: 1, kinds: [:event])
    assert [%{record: %{id: second_id}, ledger_sequence: 2}] = page_one.items
    assert second_id == second.id

    assert {:ok, page_two} =
             Chronicle.Query.timeline(
               limit: 1,
               kinds: [:event],
               cursor: page_one.next_cursor
             )

    assert [%{record: %{id: first_id}, ledger_sequence: 1}] = page_two.items
    assert first_id == first.id
    assert page_two.next_cursor == nil
  end

  test "query cursors do not skip children when one group spans several pages" do
    result =
      Chronicle.run("bulk.review", fn ->
        for index <- 1..5 do
          Chronicle.record!("item.reviewed", %{index: index})
        end
      end)

    assert is_list(result)

    fetch_pages = fn fetch_pages, cursor, accumulated ->
      opts =
        [limit: 2]
        |> then(fn opts -> if cursor, do: Keyword.put(opts, :cursor, cursor), else: opts end)

      assert {:ok, page} = Chronicle.Query.timeline(opts)
      accumulated = accumulated ++ page.items

      if page.next_cursor do
        fetch_pages.(fetch_pages, page.next_cursor, accumulated)
      else
        accumulated
      end
    end

    items = fetch_pages.(fetch_pages, nil, [])

    assert length(items) == 6
    assert Enum.count(items, &(&1.kind == :group)) == 1
    assert Enum.count(items, &(&1.kind == :event)) == 5
    assert items |> Enum.map(& &1.record.id) |> Enum.uniq() |> length() == 6
    assert Enum.map(items, & &1.child_sequence) == [5, 4, 3, 2, 1, 0]
  end

  test "query rejects misspelled and invalid filters instead of returning excess data" do
    assert {:error, %Chronicle.Error{cause: {:invalid_query_filter, :acotr}}} =
             Chronicle.Query.timeline(acotr: Chronicle.actor("user", "42"))

    assert {:error, %Chronicle.Error{cause: {:invalid_query_filter, :from}}} =
             Chronicle.Query.timeline(from: "yesterday")
  end

  test "a protected field is never reconstructed from a redaction placeholder" do
    changeset =
      Ecto.Changeset.cast(%ProtectedItem{}, %{name: "n", secret: "real-value"}, [:name, :secret])

    {:ok, item} = Chronicle.insert(changeset)
    {:ok, [version]} = Chronicle.history(item)

    refute version.restorable?
    assert version.missing_fields == [:secret]
    refute Chronicle.Version.snapshot(version)["fields"]["secret"] == "[REDACTED]"

    assert {:error, %Chronicle.Error{reason: :snapshot_incomplete}} =
             Chronicle.at(item, version: 1)

    assert {:error, %Chronicle.Error{reason: :snapshot_incomplete}} =
             Chronicle.revert(item, version: 1)
  end

  test "a protected field that is nil stays restorable and reverts to nil" do
    changeset = Ecto.Changeset.cast(%ProtectedItem{}, %{name: "first"}, [:name, :secret])
    {:ok, item} = Chronicle.insert(changeset)

    {:ok, item} =
      item
      |> Ecto.Changeset.cast(%{name: "second"}, [:name])
      |> Chronicle.update()

    {:ok, [_latest, original]} = Chronicle.history(item)

    assert original.restorable?
    assert original.missing_fields == []
    assert Chronicle.Version.snapshot(original)["fields"]["secret"] == nil

    assert {:ok, restored} = Chronicle.at(item, version: 1)
    assert restored.name == "first"
    assert restored.secret == nil

    assert {:ok, changeset} = Chronicle.revert(item, version: 1)
    assert changeset.changes == %{name: "first"}
  end

  test "record versions carry their ledger position and need no join to order" do
    {:ok, item} = Chronicle.insert(Ecto.Changeset.change(%Item{}, %{name: "one"}))

    {:ok, item} =
      item |> Ecto.Changeset.change(%{name: "two"}) |> Chronicle.update()

    rows = Repo.all(from event in Chronicle.Ecto.Schema.Event, select: event)
    assert Enum.all?(rows, &is_integer(&1.ledger_sequence))

    {:ok, versions} = Chronicle.history(item)
    assert Enum.map(versions, & &1.version) == [2, 1]

    ledger_sequences =
      Repo.all(from entry in Chronicle.Ecto.Schema.LedgerEntry, select: entry.sequence)

    assert Enum.sort(Enum.map(rows, & &1.ledger_sequence)) == Enum.sort(ledger_sequences)
    assert {:ok, _} = Chronicle.verify_all()
  end

  test "an update touching only excluded fields records nothing" do
    changeset =
      Ecto.Changeset.cast(%SelectiveItem{}, %{name: "first"}, [:name, :touched_at])

    {:ok, item} = Chronicle.insert(changeset)
    assert {:ok, [_insert]} = Chronicle.history(item)
    {:ok, before} = Chronicle.checkpoint()

    # Only the excluded field changes: no event, no ledger sequence consumed.
    {:ok, item} =
      item
      |> Ecto.Changeset.cast(%{touched_at: DateTime.utc_now()}, [:touched_at])
      |> Chronicle.update()

    assert {:ok, [_insert]} = Chronicle.history(item)
    assert {:ok, ^before} = Chronicle.checkpoint()

    # A tracked field changing is still audited.
    {:ok, item} =
      item |> Ecto.Changeset.cast(%{name: "second"}, [:name]) |> Chronicle.update()

    assert {:ok, [update, _insert]} = Chronicle.history(item)
    assert update.operation == :update
    assert [%{"field" => "name"}] = Chronicle.Version.changes(update)
    assert {:ok, _} = Chronicle.verify_all()
  end

  test "an explicit :data or :type still records an otherwise empty update" do
    {:ok, item} =
      Chronicle.insert(Ecto.Changeset.cast(%SelectiveItem{}, %{name: "n"}, [:name]))

    {:ok, item} =
      item
      |> Ecto.Changeset.cast(%{touched_at: DateTime.utc_now()}, [:touched_at])
      |> Chronicle.update(data: %{reason: "operator refresh"})

    assert {:ok, [recorded | _]} = Chronicle.history(item)
    assert recorded.operation == :update
    assert Chronicle.Version.changes(recorded) == []
    assert recorded.event.data["reason"] == "operator refresh"
  end

  test "excluding a field from diffs does not disable time travel" do
    {:ok, item} =
      Chronicle.insert(
        Ecto.Changeset.cast(
          %SelectiveItem{},
          %{name: "first", touched_at: ~U[2026-01-01 00:00:00.000000Z]},
          [:name, :touched_at]
        )
      )

    {:ok, item} =
      item |> Ecto.Changeset.cast(%{name: "second"}, [:name]) |> Chronicle.update()

    assert {:ok, [_latest, original]} = Chronicle.history(item)
    assert original.restorable?
    assert original.missing_fields == []

    # The excluded field is still captured, so the record reconstructs whole.
    assert {:ok, restored} = Chronicle.at(item, version: 1)
    assert restored.name == "first"
    assert restored.touched_at == ~U[2026-01-01 00:00:00.000000Z]
  end

  test "actor, tenant, and subject are all queryable with a composite identifier" do
    composite = %{"type" => "org", "id" => %{"region" => "eu", "org" => "org-1"}}
    simple = Chronicle.ref("org", "org-2")

    Chronicle.record!("scoped.fact", %{}, tenant: composite)
    Chronicle.record!("other.fact", %{}, tenant: simple)
    Chronicle.record!("acted.fact", %{}, actor: composite)
    Chronicle.record!("about.fact", %{}, subject: composite)

    # Previously these raised: the writer dropped a composite id to nil and the
    # reader called to_string/1 on the map.
    assert {:ok, page} = Chronicle.Query.for_tenant(composite)
    assert Enum.map(page.items, & &1.record.type) == ["scoped.fact"]

    assert {:ok, page} = Chronicle.Query.for_tenant(simple)
    assert Enum.map(page.items, & &1.record.type) == ["other.fact"]

    assert {:ok, page} = Chronicle.Query.for_actor(composite)
    assert Enum.map(page.items, & &1.record.type) == ["acted.fact"]

    assert {:ok, page} = Chronicle.Query.for_subject(composite)
    assert Enum.map(page.items, & &1.record.type) == ["about.fact"]

    assert {:ok, _} = Chronicle.verify_all()
  end

  test "doctor verifies a healthy store and rotation refuses a reused key id" do
    doctor_output = capture_io(fn -> Mix.Tasks.Chronicle.Doctor.run([]) end)
    assert doctor_output =~ "[OK] verification: 0 ledgers verified"
    assert doctor_output =~ "0 errors"

    assert {:ok, _event} = Chronicle.record("rotation.baseline")

    rotation_output =
      capture_io(fn ->
        Mix.Tasks.Chronicle.Keys.Rotate.run(["--key-id", "key-2"])
      end)

    assert rotation_output =~ "Verified 1 ledgers"
    assert rotation_output =~ "New key id: key-2"
    assert rotation_output =~ "New 256-bit Base64 key:"
    assert rotation_output =~ "No transition was appended"

    assert Repo.aggregate(Chronicle.Ecto.Schema.LedgerEntry, :count) == 1

    assert_raise Mix.Error, ~r/already appears in the ledger/, fn ->
      capture_io(fn -> Mix.Tasks.Chronicle.Keys.Rotate.run(["--key-id", "key-1"]) end)
    end
  end

  defp configure_store(key) do
    Application.put_env(:chronicle, :default_store, :primary)

    Application.put_env(
      :chronicle,
      :stores,
      primary: [
        provider: Chronicle.Provider.Ecto,
        repo: Repo,
        integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
      ]
    )
  end

  defp restore_env(key, :__missing__), do: Application.delete_env(:chronicle, key)
  defp restore_env(key, value), do: Application.put_env(:chronicle, key, value)
end
