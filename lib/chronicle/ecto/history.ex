if Code.ensure_loaded?(Ecto.Query) do
  defmodule Chronicle.Ecto.History do
    @moduledoc false

    # Reads a record's past. Version numbers are record-local positions in
    # committed ledger order, computed by the database in the same statement
    # that returns the page — not counted in Elixir and not derived from
    # insertion order. That is what makes "version 3" mean the same thing to
    # two readers paginating concurrently while a third writes.
    #
    # Because the numbering comes from ledger order, it agrees with the chain by
    # construction: version N of a record is always the Nth entry that signed
    # it, and there is no second ordering to reconcile.
    #
    # Pages are bounded. An unbounded history read on a hot record is a slow
    # query holding a connection, and the caller who wants everything can ask
    # for it a page at a time.

    import Ecto.Query

    alias Chronicle.Ecto.{Schema, Snapshot}
    alias Chronicle.Version

    @max_page_size 1_000

    @spec history(Chronicle.Store.t(), module(), map(), keyword()) ::
            {:ok, [Version.t()]} | {:error, term()}
    def history(store, schema, subject, opts) do
      repo = Keyword.fetch!(store.options, :repo)
      limit = Keyword.get(opts, :limit, 50)
      offset = Keyword.get(opts, :offset, 0)

      with :ok <- valid_page(limit, offset) do
        # One windowed query: version numbers come from the database in the
        # same statement as the page, so a concurrent write cannot shift them.
        query =
          store.options
          |> base_query(subject)
          |> with_position()
          |> newest_first()
          |> limit(^limit)
          |> offset(^offset)

        repo
        |> then(& &1.all(query, repo_options(store.options)))
        |> Enum.reduce_while({:ok, []}, fn {row, version_number}, {:ok, versions} ->
          case build_version(schema, row, version_number) do
            {:ok, version} -> {:cont, {:ok, [version | versions]}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> reverse_versions()
      end
    rescue
      exception -> {:error, {:ecto_history, exception, __STACKTRACE__}}
    end

    @spec at(Chronicle.Store.t(), module(), map(), keyword()) ::
            {:ok, struct()} | {:error, term()}
    def at(store, schema, subject, opts) do
      with {:ok, version} <- find_version(store, schema, subject, opts) do
        cond do
          version.operation == :delete ->
            {:error, :record_deleted}

          version.restorable? ->
            {:ok, version.record}

          version.reconstruction_error ->
            {:error, version.reconstruction_error}

          true ->
            {:error, {:snapshot_incomplete, version.missing_fields}}
        end
      end
    end

    @spec revert(Chronicle.Store.t(), struct(), map(), keyword()) ::
            {:ok, Ecto.Changeset.t()} | {:error, term()}
    def revert(store, %schema{} = current, subject, opts) do
      with {:ok, version} <- find_version(store, schema, subject, opts),
           :ok <- restorable_version(version),
           {:ok, attributes} <- Snapshot.attributes(schema, Version.snapshot(version)) do
        primary_keys = schema.__schema__(:primary_key)
        changes = Map.drop(attributes, primary_keys)
        {:ok, Ecto.Changeset.change(current, changes)}
      end
    end

    defp find_version(store, schema, subject, opts) do
      repo = Keyword.fetch!(store.options, :repo)
      base = base_query(store.options, subject)

      with {:ok, selector} <- selector(opts),
           {:ok, row, version} <- select_version(repo, base, selector, store.options),
           {:ok, built} <- build_version(schema, row, version) do
        {:ok, built}
      end
    rescue
      exception -> {:error, {:ecto_history, exception, __STACKTRACE__}}
    end

    # Every selector reads one numbered row, so the returned version number is
    # always consistent with the row it describes.
    defp select_version(repo, base, selector, options) do
      numbered = with_position(base)

      case repo.one(narrow(numbered, selector), repo_options(options)) do
        {row, version} -> {:ok, row, version}
        nil -> {:error, missing(selector)}
      end
    end

    defp narrow(query, {:version, version}) do
      query
      |> oldest_first()
      |> offset(^(version - 1))
      |> limit(1)
    end

    defp narrow(query, {:event, event_id}) do
      query
      |> where([event: event], field(event, :id) == ^event_id)
      |> limit(1)
    end

    defp narrow(query, {:at, at}) do
      query
      |> where([event: event], field(event, :occurred_at) <= ^at)
      |> order_by([event: event], desc: field(event, :occurred_at))
      |> newest_first()
      |> limit(1)
    end

    defp narrow(query, :latest), do: query |> newest_first() |> limit(1)

    defp missing({:version, version}), do: {:version_not_found, version}
    defp missing({:event, event_id}), do: {:version_event_not_found, event_id}
    defp missing({:at, at}), do: {:record_state_not_found, at}
    defp missing(:latest), do: :record_history_not_found

    # Record-local version number: the row's one-based position in committed
    # ledger order, computed by the database in the same statement.
    defp with_position(query) do
      select(
        query,
        [event: event],
        {event,
         fragment(
           "ROW_NUMBER() OVER (ORDER BY ?, COALESCE(?, 0), ?)",
           field(event, :ledger_sequence),
           field(event, :sequence),
           field(event, :id)
         )}
      )
    end

    defp newest_first(query) do
      order_by(query, [event: event],
        desc: field(event, :ledger_sequence),
        desc: fragment("COALESCE(?, 0)", field(event, :sequence)),
        desc: field(event, :id)
      )
    end

    defp oldest_first(query) do
      order_by(query, [event: event],
        asc: field(event, :ledger_sequence),
        asc: fragment("COALESCE(?, 0)", field(event, :sequence)),
        asc: field(event, :id)
      )
    end

    defp base_query(options, subject) do
      ledger =
        options
        |> Chronicle.Ecto.Ledger.integrity_options!()
        |> Keyword.get(:ledger, "default")

      subject_type = Chronicle.Reference.type(subject)
      subject_id = Chronicle.Reference.id(subject)
      events = {Keyword.get(options, :events_table, "audit_events"), Schema.Event}

      events
      |> from(as: :event)
      |> where(
        [event: event],
        field(event, :ledger) == ^ledger and
          field(event, :record_version) == true and
          field(event, :subject_type) == ^subject_type and
          field(event, :subject_id) == ^subject_id
      )
    end

    # Identity, actor, and timing stay on the event. The version holds only
    # what describes the version: its position, its kind, and whether the
    # record reconstructs.
    defp build_version(schema, row, version_number) do
      event = Chronicle.Query.Ecto.to_event(row)
      snapshot = event.data |> map_value("ecto") |> map_value("snapshot")

      with true <- is_map(snapshot),
           {:ok, operation} <- operation(event.action) do
        missing_fields =
          snapshot
          |> map_value("missing_fields")
          |> List.wrap()
          |> Enum.map(&safe_field/1)

        state = if operation == :delete, do: :deleted, else: :present
        {record, reconstruction_error} = maybe_reify(schema, snapshot, state, missing_fields)

        {:ok,
         %Version{
           version: version_number,
           operation: operation,
           schema: schema,
           record: record,
           reconstruction_error: reconstruction_error,
           event: event,
           missing_fields: missing_fields,
           restorable?: is_nil(reconstruction_error)
         }}
      else
        false -> {:error, {:invalid_version_event, event.id}}
        {:error, reason} -> {:error, {:invalid_version_event, event.id, reason}}
      end
    end

    defp maybe_reify(_schema, _snapshot, :deleted, _missing_fields),
      do: {nil, :record_deleted}

    defp maybe_reify(_schema, _snapshot, :present, [_ | _] = missing_fields),
      do: {nil, {:snapshot_incomplete, missing_fields}}

    defp maybe_reify(schema, snapshot, :present, []) do
      case Snapshot.reify(schema, snapshot) do
        {:ok, record} -> {record, nil}
        {:error, reason} -> {nil, reason}
      end
    end

    defp selector(opts) do
      selectors =
        Enum.filter(
          [
            version: Keyword.get(opts, :version),
            event: Keyword.get(opts, :event),
            at: Keyword.get(opts, :at)
          ],
          fn {_key, value} -> not is_nil(value) end
        )

      case selectors do
        [] ->
          {:ok, :latest}

        [{:version, version}] when is_integer(version) and version > 0 ->
          {:ok, {:version, version}}

        [{:event, event_id}] when is_binary(event_id) and byte_size(event_id) > 0 ->
          {:ok, {:event, event_id}}

        [{:at, %DateTime{} = at}] ->
          {:ok, {:at, at}}

        [_invalid] ->
          {:error, {:invalid_version_selector, selectors}}

        _several ->
          {:error, {:conflicting_version_selectors, Keyword.keys(selectors)}}
      end
    end

    defp valid_page(limit, offset)
         when is_integer(limit) and limit > 0 and limit <= @max_page_size and
                is_integer(offset) and offset >= 0,
         do: :ok

    defp valid_page(limit, offset), do: {:error, {:invalid_history_page, limit, offset}}

    defp restorable_version(%Version{operation: :delete}), do: {:error, :record_deleted}
    defp restorable_version(%Version{restorable?: true}), do: :ok

    defp restorable_version(%Version{reconstruction_error: reason}) when not is_nil(reason),
      do: {:error, reason}

    defp restorable_version(%Version{missing_fields: fields}),
      do: {:error, {:snapshot_incomplete, fields}}

    defp operation("insert"), do: {:ok, :insert}
    defp operation("update"), do: {:ok, :update}
    defp operation("delete"), do: {:ok, :delete}
    defp operation(operation), do: {:error, {:invalid_version_operation, operation}}

    defp reverse_versions({:ok, versions}), do: {:ok, Enum.reverse(versions)}
    defp reverse_versions(error), do: error

    defp map_value(false, _key), do: nil
    defp map_value(nil, _key), do: nil

    defp map_value(map, key) do
      Map.get(map, key, Map.get(map, safe_existing_atom(key)))
    end

    defp safe_field(field) when is_atom(field), do: field

    defp safe_field(field) when is_binary(field) do
      String.to_existing_atom(field)
    rescue
      ArgumentError -> field
    end

    defp safe_existing_atom(value) do
      String.to_existing_atom(value)
    rescue
      ArgumentError -> nil
    end

    defp repo_options(options) do
      options
      |> Keyword.get(:repo_options, [])
      |> maybe_prefix(options)
    end

    defp maybe_prefix(repo_options, options) do
      case Keyword.fetch(options, :prefix) do
        {:ok, prefix} -> Keyword.put(repo_options, :prefix, prefix)
        :error -> repo_options
      end
    end
  end
end
