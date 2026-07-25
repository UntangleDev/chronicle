if Code.ensure_loaded?(Ecto.Schema) do
  defmodule Chronicle.Ecto.Schema.Event do
    @moduledoc false

    # One table carries both arbitrary facts and Ecto record versions, and both
    # group roots and their children. A group root is a row with `kind: "group"`
    # holding the unit's outcome and child count; its children point back at it
    # through `group_id`. Keeping them in one table is what lets a single
    # ordered query produce a timeline, and what lets one ledger entry cover a
    # whole group.
    #
    # `content_fields/0` derives the signed column list from this schema instead
    # of repeating it, so the set of protected columns cannot drift from the set
    # of columns that exist. `:inserted_at` is subtracted deliberately: it is
    # stamped by the database on arrival and is ordering metadata rather than
    # evidence, which `Chronicle.Integrity.entry_row/1` says more about.

    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: false}
    schema "audit_events" do
      field :ledger, :string
      field :ledger_sequence, :integer
      field :kind, :string
      field :event_count, :integer
      field :group_id, :binary_id
      field :sequence, :integer
      field :type, :string
      field :record_version, :boolean
      field :action, :string
      field :outcome, :string
      field :actor_type, :string
      field :actor_id, :string
      field :tenant_type, :string
      field :tenant_id, :string
      field :subject_type, :string
      field :subject_id, :string
      field :correlation_id, :string
      field :occurred_at, :utc_datetime_usec
      field :duration_us, :integer
      field :error, :map
      field :data, :map
      field :metadata, :map
      field :inserted_at, :utc_datetime_usec
    end

    @content_fields Module.get_attribute(__MODULE__, :ecto_fields)
                    |> Enum.map(&elem(&1, 0))
                    |> Kernel.--([:inserted_at])

    @doc """
    Fields covered by the integrity signature, in one place.

    Writers build the signed payload from this list and the verifier selects
    exactly these columns, so the two cannot drift apart. Group roots and
    events share the row shape, so they share this list.
    """
    @spec content_fields() :: [atom()]
    def content_fields, do: @content_fields
  end

  defmodule Chronicle.Ecto.Schema.LedgerHead do
    @moduledoc false
    use Ecto.Schema

    @primary_key {:ledger, :string, autogenerate: false}
    schema "audit_ledger_heads" do
      field :sequence, :integer
      field :digest, :string
      field :updated_at, :utc_datetime_usec
    end
  end

  defmodule Chronicle.Ecto.Schema.LedgerEntry do
    @moduledoc false
    use Ecto.Schema

    @primary_key false
    schema "audit_ledger_entries" do
      field :ledger, :string
      field :sequence, :integer
      field :kind, :string
      field :record_id, :binary_id
      field :previous_digest, :string
      field :content_digest, :string
      field :digest, :string
      field :signature, :string
      field :key_id, :string
      field :algorithm, :string
      field :canonical_version, :integer
      field :inserted_at, :utc_datetime_usec
    end
  end
end
