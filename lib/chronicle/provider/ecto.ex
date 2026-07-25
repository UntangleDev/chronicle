if Code.ensure_loaded?(Ecto.Repo) do
  defmodule Chronicle.Provider.Ecto do
    @moduledoc """
    Stores audit groups and events in an Ecto repository.

    Required option:

      * `:repo` - the `Ecto.Repo` module

    Optional options:

      * `:events_table` - defaults to `"audit_events"`
      * `:ledger_heads_table` - defaults to `"audit_ledger_heads"`
      * `:ledger_entries_table` - defaults to `"audit_ledger_entries"`
      * `:prefix` - database prefix/schema
      * `:chunk_size` - event insert batch size, defaults to `500`
      * `:integrity` - HMAC ledger options; required

    A group and its events share the record table: the group is a row with
    `kind: "group"` carrying the unit's outcome, timing, and child count, and
    its children reference it by `group_id`. All of them are inserted in one
    repository transaction and covered by one ledger entry.
    If the caller is already inside a transaction on the same repo, Ecto uses
    that transaction. Integrity configuration is fail-closed: omit it and the
    write fails. The Ecto provider has no unsigned mode.

    ## The signature covers the row, not the intention

    Every write builds its ledger entry from `content_row/1` — a projection of
    the row as it is about to be stored — and does so before the insert. The
    ordering matters more than it looks. Signing the caller's original values
    and then storing a normalized version would produce a signature that
    verifies against something the database does not contain, and the mismatch
    would surface years later as an unexplained tamper alert.

    Which columns that projection covers is decided in exactly one place,
    `Chronicle.Ecto.Schema.Event.content_fields/0`, which derives the list from
    the schema's own fields rather than restating them. A new column is signed
    because it exists, not because someone remembered to add it twice, and the
    adversarial suite generates a tamper case per column from the same list —
    so new columns arrive with coverage already attached.

    The one deliberate exclusion is `inserted_at`, which is why it is subtracted
    explicitly and visibly there rather than simply left out.

    ## A group is signed as a unit

    One ledger entry covers a group and all its children. The root row carries
    the child count, and it is signed, so adding or removing a child is
    detectable even though the children themselves have no entries of their
    own. This is why the whole group is written in one transaction: a partially
    written group is a group whose signed count does not match reality.
    """

    @behaviour Chronicle.Provider

    alias Chronicle.{Event, Group, Reference}
    alias Chronicle.Ecto.Ledger
    alias Chronicle.Ecto.Schema

    @impl true
    def write_event(%Event{} = event, opts) do
      repo = fetch_repo!(opts)

      write(repo, opts, fn sequence, previous_digest, integrity_opts ->
        row = event_row(event, sequence, opts)

        with {:ok, entry} <-
               Chronicle.Integrity.build(
                 :event,
                 event.id,
                 content_row(row),
                 sequence,
                 previous_digest,
                 integrity_opts
               ) do
          insert_event!(repo, row, opts)
          {:ok, Ledger.commit(repo, entry, opts)}
        end
      end)
    end

    @impl true
    def write_group(%Group{} = group, events, opts) do
      repo = fetch_repo!(opts)

      write(repo, opts, fn sequence, previous_digest, integrity_opts ->
        group_row = group_row(group, sequence, opts)
        event_rows = Enum.map(events, &event_row(&1, sequence, opts))

        payload = %{
          "group" => content_row(group_row),
          "events" => Enum.map(event_rows, &content_row/1)
        }

        with {:ok, entry} <-
               Chronicle.Integrity.build(
                 :group,
                 group.id,
                 payload,
                 sequence,
                 previous_digest,
                 integrity_opts
               ) do
          insert_records!(repo, [group_row | event_rows], opts)
          {:ok, Ledger.commit(repo, entry, opts)}
        end
      end)
    end

    # Takes the ledger position first so every signed row commits to its own
    # place in the chain, and so reads never join to discover it.
    defp write(repo, opts, fun) do
      case repo.transaction(fn ->
             case Ledger.with_position(repo, opts, fun) do
               {:ok, checkpoint} -> checkpoint
               {:error, reason} -> repo.rollback(reason)
             end
           end) do
        {:ok, checkpoint} -> {:ok, checkpoint}
        {:error, reason} -> {:error, reason}
      end
    rescue
      exception -> {:error, {:ecto, exception, __STACKTRACE__}}
    end

    @doc false
    def write_key_transition(new_key_id, new_key_source, opts) do
      repo = fetch_repo!(opts)

      case repo.transaction(fn ->
             Ledger.with_position(repo, opts, fn sequence, previous_digest, integrity_opts ->
               ledger = Keyword.get(integrity_opts, :ledger, "default")

               with {:ok, current_key} <-
                      Chronicle.Keyring.current(ledger, sequence, integrity_opts),
                    {:ok, new_key} <- Chronicle.Integrity.resolve_key(new_key_source),
                    :ok <- distinct_key_id(current_key.id, new_key_id) do
                 activation = sequence + 1

                 proof =
                   Chronicle.Keys.transition_proof(
                     ledger,
                     current_key.id,
                     new_key_id,
                     sequence,
                     activation,
                     previous_digest,
                     new_key
                   )

                 event =
                   Event.new(
                     "chronicle.key_transition",
                     %{
                       from_key_id: current_key.id,
                       to_key_id: new_key_id,
                       transition_sequence: sequence,
                       activates_at_sequence: activation,
                       previous_digest: previous_digest,
                       new_key_proof: proof
                     },
                     action: "rotate_key",
                     outcome: :success,
                     subject: Chronicle.ref("audit_ledger", ledger)
                   )

                 row = event_row(event, sequence, opts)

                 with {:ok, entry} <-
                        Chronicle.Integrity.build(
                          :event,
                          event.id,
                          content_row(row),
                          sequence,
                          previous_digest,
                          integrity_opts
                        ) do
                   insert_event!(repo, row, opts)
                   checkpoint = Ledger.commit(repo, entry, opts)

                   {:ok,
                    %{
                      event: event,
                      ledger: ledger,
                      old_key_id: current_key.id,
                      new_key_id: new_key_id,
                      transition_sequence: sequence,
                      activates_at_sequence: activation,
                      checkpoint: checkpoint,
                      new_key_proof: proof
                    }}
                 end
               end
             end)
             |> case do
               {:ok, plan} -> plan
               {:error, reason} -> repo.rollback(reason)
             end
           end) do
        {:ok, plan} -> {:ok, plan}
        {:error, reason} -> {:error, reason}
      end
    rescue
      exception -> {:error, {:ecto, exception, __STACKTRACE__}}
    end

    defp insert_event(repo, row, opts) do
      case repo.insert_all(
             {Keyword.get(opts, :events_table, "audit_events"), Schema.Event},
             [row],
             insert_options(opts)
           ) do
        {1, _} -> :ok
        other -> {:error, {:unexpected_insert_result, other}}
      end
    end

    defp insert_event!(repo, row, opts) do
      case insert_event(repo, row, opts) do
        :ok -> :ok
        {:error, reason} -> repo.rollback(reason)
      end
    end

    defp insert_records!(repo, rows, opts) do
      table = {Keyword.get(opts, :events_table, "audit_events"), Schema.Event}
      chunk_size = Keyword.get(opts, :chunk_size, 500)

      rows
      |> Enum.chunk_every(chunk_size)
      |> Enum.each(fn rows ->
        case repo.insert_all(table, rows, insert_options(opts)) do
          {count, _} when count == length(rows) -> :ok
          other -> repo.rollback({:unexpected_event_insert_result, other})
        end
      end)

      :ok
    end

    defp event_row(event, ledger_sequence, opts) do
      %{
        id: event.id,
        ledger: ledger_name(opts),
        ledger_sequence: ledger_sequence,
        kind: "event",
        event_count: nil,
        group_id: event.group_id,
        sequence: event.sequence,
        type: event.type,
        record_version: record_version?(event),
        action: event.action,
        outcome: to_string(event.outcome),
        actor_type: Reference.type(event.actor),
        actor_id: Reference.id(event.actor),
        tenant_type: Reference.type(event.tenant),
        tenant_id: Reference.id(event.tenant),
        subject_type: Reference.type(event.subject),
        subject_id: Reference.id(event.subject),
        correlation_id: event.correlation_id,
        occurred_at: event.occurred_at,
        duration_us: event.duration_us,
        error: event.error,
        data: event.data,
        metadata: event.metadata,
        inserted_at: DateTime.utc_now()
      }
    end

    # A group root is stored as a record row like any other: same columns, with
    # `kind` marking it as the envelope and `event_count` fixing how many
    # children its signature covers.
    defp group_row(group, ledger_sequence, opts) do
      %{
        id: group.id,
        ledger: ledger_name(opts),
        ledger_sequence: ledger_sequence,
        kind: "group",
        event_count: group.event_count,
        group_id: nil,
        sequence: nil,
        type: group.type,
        record_version: false,
        action: nil,
        outcome: to_string(group.outcome),
        actor_type: Reference.type(group.actor),
        actor_id: Reference.id(group.actor),
        tenant_type: Reference.type(group.tenant),
        tenant_id: Reference.id(group.tenant),
        subject_type: Reference.type(group.subject),
        subject_id: Reference.id(group.subject),
        correlation_id: group.correlation_id,
        occurred_at: group.started_at,
        duration_us: group.duration_us,
        error: group.error,
        data: group.data,
        metadata: group.metadata,
        inserted_at: DateTime.utc_now()
      }
    end

    # Signed payload is exactly the columns the verifier reads back.
    defp content_row(row), do: Map.take(row, Schema.Event.content_fields())

    defp insert_options(opts) do
      case Keyword.fetch(opts, :prefix) do
        {:ok, prefix} -> [prefix: prefix]
        :error -> []
      end
    end

    defp fetch_repo!(opts) do
      Keyword.get(opts, :repo) ||
        raise ArgumentError, "Chronicle.Provider.Ecto requires the :repo option"
    end

    defp distinct_key_id(key_id, key_id), do: {:error, {:key_id_already_current, key_id}}
    defp distinct_key_id(_current, new) when is_binary(new) and byte_size(new) > 0, do: :ok
    defp distinct_key_id(_current, new), do: {:error, {:invalid_key_id, new}}

    defp ledger_name(opts) do
      case Keyword.get(opts, :integrity) do
        integrity when is_list(integrity) -> Keyword.get(integrity, :ledger, "default")
        _other -> nil
      end
    end

    # Carrying a snapshot is what makes a row a record version. Keying off the
    # category as well would let a caller-supplied label hide the row from
    # history.
    defp record_version?(%Event{data: data}) do
      case Map.get(data, "ecto", Map.get(data, :ecto)) do
        ecto when is_map(ecto) -> is_map(Map.get(ecto, "snapshot", Map.get(ecto, :snapshot)))
        _other -> false
      end
    end
  end
end
