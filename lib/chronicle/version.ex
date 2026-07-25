defmodule Chronicle.Version do
  @moduledoc """
  One immutable, signed version of an Ecto record.

  A version holds only what describes the version itself: where it sits in the
  record's history, what kind of change it was, and whether the record can be
  reconstructed from it.

      %Chronicle.Version{
        version: 3,
        operation: :update,
        schema: MyApp.Account,
        record: %MyApp.Account{},
        restorable?: true
      }

  `version` is the record-local, one-based position in committed ledger order.
  A deleted version is a tombstone: `operation` is `:delete` and `record` is
  `nil`.

  Everything describing the *event* — actor, subject, changes, timestamp,
  correlation id, group id, metadata — lives on `event`, and only there. No
  value appears in two places. `operation` and `schema` are typed readings of
  `event.action` and `event.subject`, not copies of them:

      version.event.actor
      version.event.changes
      version.event.occurred_at
      version.event.subject["id"]
  """

  @enforce_keys [:version, :operation, :schema, :event]
  defstruct [
    :version,
    :operation,
    :schema,
    :record,
    :reconstruction_error,
    :event,
    missing_fields: [],
    restorable?: false
  ]

  @type t :: %__MODULE__{
          version: pos_integer(),
          operation: :insert | :update | :delete,
          schema: module(),
          record: struct() | nil,
          reconstruction_error: term() | nil,
          event: Chronicle.Event.t(),
          missing_fields: [atom()],
          restorable?: boolean()
        }

  @doc """
  Returns the stored snapshot for a version.

  The snapshot is held once, inside the signed event payload.
  """
  @spec snapshot(t()) :: map() | nil
  def snapshot(%__MODULE__{} = version), do: ecto(version, "snapshot")

  @doc """
  Returns the field transitions recorded for a version.
  """
  @spec changes(t()) :: [map()]
  def changes(%__MODULE__{} = version), do: ecto(version, "changes") || []

  defp ecto(%__MODULE__{event: %Chronicle.Event{data: data}}, key) do
    case Map.get(data, "ecto") do
      ecto when is_map(ecto) -> Map.get(ecto, key)
      _other -> nil
    end
  end
end
