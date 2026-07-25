if Code.ensure_loaded?(Ecto.Migration) do
  defmodule Chronicle.Ecto.Migration do
    @moduledoc """
    Reusable Ecto migration for the default audit store.

    Create a migration in the host application:

        defmodule MyApp.Repo.Migrations.CreateAuditTables do
          use Ecto.Migration

          def up, do: Chronicle.Ecto.Migration.up()
          def down, do: Chronicle.Ecto.Migration.down()
        end

    The functions accept `:prefix`, `:events_table`, `:ledger_heads_table`,
    and `:ledger_entries_table`.

    Groups and events share one table. A group root is a row with
    `kind = "group"` carrying the unit's type, outcome, timing, and child
    count; its children are rows with `kind = "event"` whose `group_id` points
    back at it.
    """

    use Ecto.Migration

    @spec up(keyword()) :: :ok
    def up(opts \\ []) do
      prefix = Keyword.get(opts, :prefix, Ecto.Migration.prefix())
      events = Keyword.get(opts, :events_table, "audit_events")
      ledger_heads = Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads")
      ledger_entries = Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries")

      create table(ledger_heads, primary_key: false, prefix: prefix) do
        add :ledger, :string, primary_key: true
        add :sequence, :bigint, null: false, default: 0
        add :digest, :string
        add :updated_at, :utc_datetime_usec, null: false
      end

      create table(events, primary_key: false, prefix: prefix) do
        add :id, :uuid, primary_key: true
        add :ledger, :string, null: false
        add :ledger_sequence, :bigint, null: false
        add :kind, :string, null: false, default: "event"
        add :event_count, :integer

        add :group_id,
            references(events, type: :uuid, on_delete: :restrict, prefix: prefix)

        add :sequence, :integer
        add :type, :string, null: false
        add :record_version, :boolean, null: false, default: false
        add :action, :string
        add :outcome, :string, null: false
        # A reference is exactly a type and an id, so the pair is the whole
        # value — there is no map to store alongside it.
        add :actor_type, :string
        add :actor_id, :string
        add :tenant_type, :string
        add :tenant_id, :string
        add :subject_type, :string
        add :subject_id, :string
        add :correlation_id, :string
        add :occurred_at, :utc_datetime_usec, null: false
        add :duration_us, :bigint
        add :error, :map
        add :data, :map, null: false, default: %{}
        add :metadata, :map, null: false, default: %{}
        add :inserted_at, :utc_datetime_usec, null: false
      end

      create unique_index(events, [:group_id, :sequence],
               prefix: prefix,
               where: "group_id IS NOT NULL"
             )

      create index(events, [:type, :occurred_at], prefix: prefix)
      create index(events, [:correlation_id], prefix: prefix)
      create index(events, [:actor_type, :actor_id, :occurred_at], prefix: prefix)
      create index(events, [:tenant_type, :tenant_id, :occurred_at], prefix: prefix)
      create index(events, [:subject_type, :subject_id, :occurred_at], prefix: prefix)
      # Ledger position is denormalized onto the record row so timeline and
      # history reads never join the ledger-entry table to establish order.
      create index(events, [:ledger, :ledger_sequence, :sequence, :id], prefix: prefix)

      # Group roots and standalone events are the ledger's own records; grouped
      # children are covered by their root's entry.
      create index(events, [:ledger, :kind], prefix: prefix)

      create index(
               events,
               [:record_version, :subject_type, :subject_id, :ledger_sequence],
               prefix: prefix
             )

      create table(ledger_entries, primary_key: false, prefix: prefix) do
        add :ledger, :string, primary_key: true
        add :sequence, :bigint, primary_key: true
        add :kind, :string, null: false
        add :record_id, :uuid, null: false
        add :previous_digest, :string
        add :content_digest, :string, null: false
        add :digest, :string, null: false
        add :signature, :string, null: false
        add :key_id, :string, null: false
        add :algorithm, :string, null: false
        add :canonical_version, :integer, null: false
        add :inserted_at, :utc_datetime_usec, null: false
      end

      create unique_index(ledger_entries, [:ledger, :kind, :record_id], prefix: prefix)
      :ok
    end

    @spec down(keyword()) :: :ok
    def down(opts \\ []) do
      prefix = Keyword.get(opts, :prefix, Ecto.Migration.prefix())
      events = Keyword.get(opts, :events_table, "audit_events")
      ledger_heads = Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads")
      ledger_entries = Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries")

      drop table(ledger_entries, prefix: prefix)
      drop table(events, prefix: prefix)
      drop table(ledger_heads, prefix: prefix)
      :ok
    end
  end
end
