if Code.ensure_loaded?(Ecto.Query) do
  defmodule Chronicle.Query.Ecto do
    @moduledoc false

    # Timeline reads over the shared event table, paginated by cursor rather
    # than by offset. An offset shifts under concurrent writes, which on an
    # append-only table means a reader paging backwards through history sees
    # rows twice or not at all; a cursor names a position instead of counting
    # from the end.
    #
    # Cursors are checked against the ledger they were issued for. A cursor
    # carries a position, and a position only means something within one chain
    # — replaying one ledger's cursor against another would silently return a
    # window from the wrong history rather than failing.

    import Ecto.Query

    alias Chronicle.Query.{Item, Page}
    alias Chronicle.{Event, Group, Query}

    def timeline(store, filters, opts) do
      repo = Keyword.fetch!(store.options, :repo)
      limit = Keyword.get(opts, :limit, 50)
      kinds = Map.get(filters, :kinds, [:event, :group])
      ledger = ledger(store.options)

      with :ok <- valid_limit(limit),
           :ok <- valid_kinds(kinds),
           {:ok, cursor} <- Query.decode_cursor(opts[:cursor]),
           :ok <- cursor_matches_ledger(cursor, ledger) do
        # Groups and events share a table and a ledger position, so one ordered
        # query produces the timeline directly.
        query =
          store.options
          |> records_source()
          |> from(as: :record)
          |> where([record: record], field(record, :ledger) == ^ledger)
          |> where([record: record], field(record, :kind) in ^Enum.map(kinds, &to_string/1))
          |> apply_filters(filters)
          |> apply_cursor(cursor)
          |> order_by([record: record],
            desc: field(record, :ledger_sequence),
            desc: fragment("COALESCE(?, 0)", field(record, :sequence)),
            desc: field(record, :id)
          )
          |> limit(^(limit + 1))

        loaded = query |> repo.all(repo_options(store.options)) |> Enum.map(&to_item(&1, ledger))
        {items, overflow} = Enum.split(loaded, limit)
        next_cursor = if overflow == [], do: nil, else: encode_last(items)
        {:ok, %Page{items: items, next_cursor: next_cursor}}
      end
    rescue
      exception -> {:error, {:ecto_query, exception, __STACKTRACE__}}
    end

    def group(store, id, _opts) do
      repo = Keyword.fetch!(store.options, :repo)
      ledger = ledger(store.options)
      repo_opts = repo_options(store.options)

      records = records_source(store.options)

      group_query =
        from record in records,
          where:
            field(record, :id) == ^id and field(record, :ledger) == ^ledger and
              field(record, :kind) == "group",
          select: record

      events_query =
        from event in records,
          where: field(event, :group_id) == ^id and field(event, :ledger) == ^ledger,
          order_by: [asc: field(event, :sequence)]

      case repo.one(group_query, repo_opts) do
        nil ->
          {:error, {:audit_group_not_found, id}}

        group ->
          {:ok, {to_group(group), Enum.map(repo.all(events_query, repo_opts), &to_event/1)}}
      end
    rescue
      exception -> {:error, {:ecto_query, exception, __STACKTRACE__}}
    end

    defp records_source(options),
      do: {Keyword.get(options, :events_table, "audit_events"), Chronicle.Ecto.Schema.Event}

    defp to_item(row, ledger) do
      kind = if row.kind == "group", do: :group, else: :event

      %Item{
        kind: kind,
        ledger: ledger,
        ledger_sequence: row.ledger_sequence,
        child_sequence: row.sequence || 0,
        occurred_at: row.occurred_at,
        record: if(kind == :group, do: to_group(row), else: to_event(row))
      }
    end

    defp apply_filters(query, filters) do
      Enum.reduce(filters, query, fn
        {:actor, reference}, query ->
          reference_filter(query, :actor, reference)

        {:tenant, reference}, query ->
          reference_filter(query, :tenant, reference)

        {:subject, reference}, query ->
          reference_filter(query, :subject, reference)

        {:correlation_id, value}, query ->
          where(query, [record], field(record, :correlation_id) == ^to_string(value))

        {:type, value}, query ->
          where(query, [record], field(record, :type) == ^to_string(value))

        {:outcome, value}, query ->
          where(query, [record], field(record, :outcome) == ^to_string(value))

        {:from, %DateTime{} = value}, query ->
          where(query, [record], field(record, :occurred_at) >= ^value)

        {:to, %DateTime{} = value}, query ->
          where(query, [record], field(record, :occurred_at) <= ^value)

        {:kinds, _value}, query ->
          query

        {_unknown, _value}, query ->
          query
      end)
    end

    # Writers store reference identity through Chronicle.Reference, so readers
    # must resolve the filter the same way or composite keys will not match.
    defp reference_filter(query, prefix, reference) do
      type_field = :"#{prefix}_type"
      id_field = :"#{prefix}_id"
      type = Chronicle.Reference.type(reference)
      id = Chronicle.Reference.id(reference)

      query
      |> where([record], field(record, ^type_field) == ^type)
      |> where([record], field(record, ^id_field) == ^id)
    end

    defp apply_cursor(query, nil), do: query

    defp apply_cursor(query, {_ledger, ledger_sequence, child_sequence, kind, id}) do
      _ = kind

      where(
        query,
        [record: record],
        field(record, :ledger_sequence) < ^ledger_sequence or
          (field(record, :ledger_sequence) == ^ledger_sequence and
             (fragment("COALESCE(?, 0)", field(record, :sequence)) < ^child_sequence or
                (fragment("COALESCE(?, 0)", field(record, :sequence)) == ^child_sequence and
                   field(record, :id) < ^id)))
      )
    end

    defp encode_last([]), do: nil

    defp encode_last(items) do
      item = List.last(items)

      Query.encode_cursor({
        item.ledger,
        item.ledger_sequence,
        item.child_sequence,
        item.kind,
        item.record.id
      })
    end

    defp cursor_matches_ledger(nil, _ledger), do: :ok
    defp cursor_matches_ledger({ledger, _, _, _, _}, ledger), do: :ok

    defp cursor_matches_ledger({cursor_ledger, _, _, _, _}, ledger),
      do: {:error, {:cursor_ledger_mismatch, cursor_ledger, ledger}}

    defp valid_limit(limit) when is_integer(limit) and limit > 0 and limit <= 10_000, do: :ok
    defp valid_limit(limit), do: {:error, {:invalid_query_option, :limit, limit}}

    defp valid_kinds(kinds)
         when is_list(kinds) and kinds != [] do
      if Enum.all?(kinds, &(&1 in [:event, :group])) do
        :ok
      else
        {:error, {:invalid_query_option, :kinds, kinds}}
      end
    end

    defp valid_kinds(kinds), do: {:error, {:invalid_query_option, :kinds, kinds}}

    # The stored type/id pair is the whole reference.
    defp reference(nil, _id), do: nil
    defp reference(type, id), do: %{"type" => type, "id" => id}

    @doc false
    def to_event(row) do
      struct(Event, %{
        id: row.id,
        group_id: row.group_id,
        sequence: row.sequence,
        type: row.type,
        action: row.action,
        outcome: Event.normalize_outcome(row.outcome),
        actor: reference(row.actor_type, row.actor_id),
        tenant: reference(row.tenant_type, row.tenant_id),
        subject: reference(row.subject_type, row.subject_id),
        correlation_id: row.correlation_id,
        occurred_at: row.occurred_at,
        duration_us: row.duration_us,
        error: row.error,
        data: row.data,
        metadata: row.metadata
      })
    end

    defp to_group(row) do
      struct(Group, %{
        id: row.id,
        type: row.type,
        outcome: Event.normalize_outcome(row.outcome),
        actor: reference(row.actor_type, row.actor_id),
        tenant: reference(row.tenant_type, row.tenant_id),
        subject: reference(row.subject_type, row.subject_id),
        correlation_id: row.correlation_id,
        started_at: row.occurred_at,
        ended_at: Group.ended_at(row.occurred_at, row.duration_us),
        duration_us: row.duration_us,
        error: row.error,
        event_count: row.event_count,
        data: row.data,
        metadata: row.metadata
      })
    end

    defp ledger(options) do
      options
      |> Chronicle.Ecto.Ledger.integrity_options!()
      |> Keyword.get(:ledger, "default")
    end

    defp repo_options(options) do
      Keyword.get(options, :repo_options, [])
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
