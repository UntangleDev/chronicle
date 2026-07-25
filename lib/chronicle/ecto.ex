if Code.ensure_loaded?(Ecto.Changeset) do
  defmodule Chronicle.Ecto do
    @moduledoc """
    Low-level conversion of completed Ecto operations into version events.

    Application code normally uses `Chronicle.insert/2`, `Chronicle.update/2`,
    `Chronicle.delete/2`, and `Chronicle.Multi`.
    """

    alias Chronicle.{Event, Redaction, Value}
    alias Chronicle.Ecto.Snapshot

    @type operation :: :insert | :update | :delete

    @doc """
    Builds an event for a completed Ecto operation.

    `result` is the inserted, updated, or deleted schema returned by the repo.
    Configure `:redact` with field atoms/strings or a `(field, value -> value)`
    function. Common credential fields are redacted by default.
    """
    @spec event(operation(), Ecto.Changeset.t(), struct(), keyword()) :: Event.t()
    def event(operation, %Ecto.Changeset{} = changeset, result, opts \\ [])
        when operation in [:insert, :update, :delete] and is_list(opts) do
      schema = result.__struct__
      source = schema.__schema__(:source)
      type = Keyword.get(opts, :type, "ecto.#{source}.#{operation}")
      subject = Snapshot.subject(result)

      # Everything the Ecto integration recorded, in one place. Identity,
      # schema, and operation are already first-class columns — `subject` and
      # `action` — so storing them again would put the same value in two places
      # and make it unclear which one is authoritative.
      ecto_data = %{
        # Already normalized and protected by `Snapshot.capture/3`. Its keys
        # are schema field names, so a second protection pass would replace
        # values the snapshot already reported as complete.
        "snapshot" => %Chronicle.Value.Raw{value: Snapshot.capture(operation, result, opts)},
        "changes" => %Chronicle.Value.Raw{
          value:
            Keyword.get_lazy(opts, :changes, fn ->
              changes(operation, changeset, result, opts)
            end)
        }
      }

      data =
        opts
        |> Keyword.get(:data, %{})
        |> Value.normalize()
        |> Map.put("ecto", ecto_data)

      event_opts =
        opts
        |> Keyword.drop([:data, :type, :redact, :changes])
        # Structural, like `:subject` and `:changes` below: `action` is where
        # the operation is read back from. Use `:type` to label an event.
        |> Keyword.put(:action, to_string(operation))
        |> Keyword.put_new(:outcome, :success)
        |> Keyword.put(:subject, subject)

      Event.new(type, data, event_opts)
    end

    @doc """
    Returns whether a completed operation has anything to audit.

    An update whose tracked field changes are empty records nothing. That
    covers a changeset with no changes at all, and an update touching only
    fields the schema policy excluded with `only` or `except` — by the
    application's own declaration, nothing auditable happened.

    A caller who supplied `:data` or `:type` is recording a semantic fact
    rather than a diff, so the event is kept. Inserts and deletes are always
    audited: creating or destroying the row is the fact, independent of which
    fields are tracked.
    """
    @spec auditable?(operation(), [map()], keyword()) :: boolean()
    def auditable?(operation, field_changes, opts \\ [])

    def auditable?(:update, [], opts),
      do: Keyword.has_key?(opts, :data) or Keyword.has_key?(opts, :type)

    def auditable?(_operation, _field_changes, _opts), do: true

    @doc """
    Returns normalized field transitions for a changeset.

    Only fields present in `changeset.changes` are included. Database-generated
    fields are therefore not misrepresented as user changes.
    """
    @spec changes(operation(), Ecto.Changeset.t(), struct(), keyword()) :: [map()]
    def changes(operation, %Ecto.Changeset{} = changeset, result, opts \\ [])
        when operation in [:insert, :update, :delete] do
      schema = result.__struct__
      policy = Chronicle.Ecto.Policy.get(schema)
      redactor = Redaction.ecto_redactor(schema, Keyword.put(opts, :record, result))
      value_policy = Redaction.compile(Keyword.put(opts, :schema, schema))

      changed_fields(operation, changeset, result)
      |> Enum.filter(fn {field, _value} -> Chronicle.Ecto.Policy.tracked?(policy, field) end)
      |> Enum.sort_by(fn {field, _value} -> to_string(field) end)
      |> Enum.map(fn {field, submitted_value} ->
        before =
          case operation do
            :insert -> nil
            _ -> Map.get(changeset.data, field)
          end

        after_value =
          case operation do
            :delete -> nil
            _ -> Map.get(result, field, submitted_value)
          end

        from = before |> redact(redactor, field) |> Value.normalize(value_policy)
        to = after_value |> redact(redactor, field) |> Value.normalize(value_policy)

        %{"field" => to_string(field)}
        |> put_unless_omitted("from", from)
        |> put_unless_omitted("to", to)
      end)
    end

    defp changed_fields(:delete, _changeset, result) do
      result.__struct__.__schema__(:fields)
      |> Map.new(&{&1, Map.get(result, &1)})
    end

    defp changed_fields(_operation, changeset, _result), do: changeset.changes

    defp redact(value, redactor, field), do: redactor.(field, value)
    defp put_unless_omitted(map, _key, :__audit_omit__), do: map
    defp put_unless_omitted(map, key, value), do: Map.put(map, key, value)
  end
end
