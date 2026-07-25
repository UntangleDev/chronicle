if Code.ensure_loaded?(Ecto.Query) do
  defmodule Chronicle.Ecto.Integrity do
    @moduledoc """
    Verifies the Ecto audit ledger and returns an anchorable checkpoint.

    Verification recomputes every content digest from the stored audit rows,
    validates every chain link and HMAC, checks for sequence gaps, and compares
    the terminal entry with the mutable ledger head.

    ## Counting is doing security work here

    The chain proves that the entries which exist are mutually consistent. It
    cannot, on its own, prove that an entry exists for every audit row, or that
    no row was added without one — a fabricated row with no ledger entry breaks
    nothing, because there is no link for it to break.

    That is the gap `verify_coverage/3` closes, and why several of the checks in
    this module are `count` queries rather than cryptography:

      * an audit row with no ledger entry is an unsigned record, caught by
        comparing the two counts;
      * two entries naming the same record are caught by the duplicate query,
        since that would let one record's signature be quietly replaced while
        the original lingered;
      * a group child whose root no longer exists is caught as an orphan,
        because children are covered by their root's signature and a child
        without one is covered by nothing.

    A group's `event_count` is itself signed on the root, so removing or adding
    a child is detected when the payload is reassembled, not by a count query.

    ## Enumerating ledgers from three tables is deliberate

    `ledger_names/2` unions the ledger column across heads, entries, and events
    rather than reading whichever one seems authoritative. A ledger that exists
    in only one of them is precisely the interesting case: rows written under a
    ledger name that appears nowhere else would never be selected for
    verification, and so would never be checked at all. A `nil` ledger is
    rejected outright — a row belonging to no chain cannot be covered by one.

    `verify_all/2` additionally refuses to proceed if a checkpoint names a
    ledger that no longer exists. Without that, deleting an entire ledger would
    verify cleanly, since what remains is perfectly consistent with itself.

    ## Anchoring is positional, not "at least as far as"

    An external checkpoint passes only if the walk actually crossed the exact
    sequence it names *and found the digest it expected there*. Comparing
    current position against the anchor's would be satisfied by an attacker who
    truncated the ledger and rewrote forward past it, which is the specific
    attack anchoring exists to catch.
    """

    import Ecto.Query

    alias Chronicle.Ecto.Ledger
    alias Chronicle.Ecto.Schema
    alias Chronicle.Integrity, as: CoreIntegrity
    alias Chronicle.Integrity.Checkpoint

    @default_batch_size 500

    @spec verify(Ecto.Repo.t(), keyword()) :: {:ok, Checkpoint.t()} | {:error, term()}
    def verify(repo, opts \\ []) do
      integrity_opts = Ledger.integrity_options!(opts)
      ledger = Keyword.get(integrity_opts, :ledger, "default")

      with {:ok, head} <- Ledger.checkpoint(repo, opts),
           {:ok, final, anchored?} <-
             verify_entries(repo, ledger, integrity_opts, opts),
           :ok <- verify_head(head, final),
           :ok <- verify_external_checkpoint(opts[:checkpoint], anchored?) do
        {:ok, final}
      end
    rescue
      exception -> {:error, {:verification_failed, exception, __STACKTRACE__}}
    end

    @doc """
    Verifies every ledger and rejects unsigned or unowned audit rows.

    Use this for scheduled whole-store verification. `verify/2` intentionally
    verifies one named ledger so it can be used for sharded workloads.
    """
    @spec verify_all(Ecto.Repo.t(), keyword()) ::
            {:ok, %{String.t() => Checkpoint.t()}} | {:error, term()}
    def verify_all(repo, opts \\ []) do
      with {:ok, ledgers} <- ledger_names(repo, opts),
           :ok <- verify_checkpoint_ledgers(ledgers, opts[:checkpoints]) do
        Enum.reduce_while(ledgers, {:ok, %{}}, fn ledger, {:ok, checkpoints} ->
          integrity =
            opts
            |> Ledger.integrity_options!()
            |> Keyword.put(:ledger, ledger)

          checkpoint =
            case opts[:checkpoints] do
              external_checkpoints when is_map(external_checkpoints) ->
                Map.get(external_checkpoints, ledger) ||
                  Map.get(external_checkpoints, safe_existing_atom(ledger))

              _other ->
                nil
            end

          ledger_opts =
            opts
            |> Keyword.put(:integrity, integrity)
            |> Keyword.put(:checkpoint, checkpoint)

          case verify(repo, ledger_opts) do
            {:ok, verified} -> {:cont, {:ok, Map.put(checkpoints, ledger, verified)}}
            {:error, reason} -> {:halt, {:error, {:ledger_verification_failed, ledger, reason}}}
          end
        end)
      end
    end

    defp verify_checkpoint_ledgers(_ledgers, nil), do: :ok

    defp verify_checkpoint_ledgers(ledgers, checkpoints) when is_map(checkpoints) do
      expected = MapSet.new(Map.keys(checkpoints), &to_string/1)
      present = MapSet.new(ledgers)
      missing = expected |> MapSet.difference(present) |> MapSet.to_list() |> Enum.sort()

      if missing == [] do
        :ok
      else
        {:error, {:checkpoint_ledgers_missing, missing}}
      end
    end

    defp verify_checkpoint_ledgers(_ledgers, checkpoints),
      do: {:error, {:invalid_checkpoints, checkpoints}}

    @spec checkpoint(Ecto.Repo.t(), keyword()) ::
            {:ok, Checkpoint.t()} | {:error, term()}
    def checkpoint(repo, opts \\ []), do: Ledger.checkpoint(repo, opts)

    defp ledger_names(repo, opts) do
      sources = [
        {Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads"), Schema.LedgerHead},
        {Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries"), Schema.LedgerEntry},
        {Keyword.get(opts, :events_table, "audit_events"), Schema.Event}
      ]

      ledgers =
        sources
        |> Enum.flat_map(fn source ->
          query = from record in source, distinct: true, select: field(record, :ledger)
          repo.all(query, repo_options(opts))
        end)
        |> Enum.uniq()

      cond do
        nil in ledgers -> {:error, :unsigned_audit_records_present}
        ledgers == [] -> {:ok, []}
        true -> {:ok, Enum.sort(ledgers)}
      end
    end

    defp verify_entries(repo, ledger, integrity_opts, opts) do
      expected_checkpoint = normalize_checkpoint(opts[:checkpoint])
      initial = %Checkpoint{ledger: ledger, sequence: 0, digest: nil}
      anchored? = checkpoint_matches?(expected_checkpoint, initial)

      batch_size = Keyword.get(opts, :verification_batch_size, @default_batch_size)

      with :ok <- valid_batch_size(batch_size),
           {:ok, expected_count} <- verify_coverage(repo, ledger, opts) do
        verify_batches(
          repo,
          ledger,
          integrity_opts,
          expected_checkpoint,
          opts,
          batch_size,
          0,
          expected_count,
          {:ok, initial, anchored?, 0}
        )
      end
    end

    defp verify_batches(
           _repo,
           _ledger,
           _integrity_opts,
           _expected_checkpoint,
           _opts,
           _batch_size,
           _after_sequence,
           expected_count,
           {:ok, previous, anchored?, expected_count}
         ),
         do: {:ok, previous, anchored?}

    defp verify_batches(
           repo,
           ledger,
           integrity_opts,
           expected_checkpoint,
           opts,
           batch_size,
           after_sequence,
           expected_count,
           {:ok, previous, anchored?, verified_count}
         ) do
      rows = entry_batch(repo, ledger, after_sequence, batch_size, opts)

      case rows do
        [] ->
          if verified_count == expected_count do
            {:ok, previous, anchored?}
          else
            {:error,
             {:ledger_coverage_mismatch,
              %{expected_records: expected_count, ledger_records: verified_count}}}
          end

        rows ->
          entries = Enum.map(rows, &CoreIntegrity.entry_from_row/1)

          with {:ok, payloads} <- load_payloads(repo, ledger, entries, opts),
               {:ok, current, anchored?, verified_count} <-
                 verify_batch(
                   entries,
                   payloads,
                   integrity_opts,
                   expected_checkpoint,
                   previous,
                   anchored?,
                   verified_count
                 ) do
            verify_batches(
              repo,
              ledger,
              integrity_opts,
              expected_checkpoint,
              opts,
              batch_size,
              current.sequence,
              expected_count,
              {:ok, current, anchored?, verified_count}
            )
          end
      end
    end

    defp verify_batch(
           entries,
           payloads,
           integrity_opts,
           expected_checkpoint,
           previous,
           anchored?,
           verified_count
         ) do
      Enum.reduce_while(
        entries,
        {:ok, previous, anchored?, verified_count},
        fn entry, {:ok, previous, anchored?, count} ->
          with {:ok, payload} <- payload(payloads, entry),
               :ok <-
                 CoreIntegrity.verify_entry(
                   entry,
                   payload,
                   previous.digest,
                   previous.sequence + 1,
                   integrity_opts
                 ),
               :ok <- verify_semantics(entry, payload, integrity_opts) do
            current = %Checkpoint{
              ledger: entry.ledger,
              sequence: entry.sequence,
              digest: entry.digest
            }

            {:cont,
             {:ok, current, anchored? or checkpoint_matches?(expected_checkpoint, current),
              count + 1}}
          else
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end
      )
    end

    defp entry_batch(repo, ledger, after_sequence, batch_size, opts) do
      entries_source =
        {Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries"), Schema.LedgerEntry}

      query =
        from entry in entries_source,
          where: field(entry, :ledger) == ^ledger and field(entry, :sequence) > ^after_sequence,
          order_by: [asc: field(entry, :sequence)],
          limit: ^batch_size,
          select: %{
            ledger: field(entry, :ledger),
            sequence: field(entry, :sequence),
            kind: field(entry, :kind),
            record_id: field(entry, :record_id),
            previous_digest: field(entry, :previous_digest),
            content_digest: field(entry, :content_digest),
            digest: field(entry, :digest),
            signature: field(entry, :signature),
            key_id: field(entry, :key_id),
            algorithm: field(entry, :algorithm),
            canonical_version: field(entry, :canonical_version)
          }

      repo.all(query, repo_options(opts))
    end

    defp verify_semantics(
           entry,
           %{type: "chronicle.key_transition", data: data},
           integrity_opts
         )
         when is_map(data) do
      old_key_id = fetch_data(data, "from_key_id")
      new_key_id = fetch_data(data, "to_key_id")
      transition_sequence = fetch_data(data, "transition_sequence")
      activation_sequence = fetch_data(data, "activates_at_sequence")
      previous_digest = fetch_data(data, "previous_digest")
      proof = fetch_data(data, "new_key_proof")

      with :ok <-
             semantic_check(
               old_key_id == entry.key_id,
               {:old_key_id_mismatch, old_key_id, entry.key_id}
             ),
           :ok <-
             semantic_check(
               transition_sequence == entry.sequence,
               {:transition_sequence_mismatch, transition_sequence, entry.sequence}
             ),
           :ok <-
             semantic_check(
               activation_sequence == entry.sequence + 1,
               {:activation_sequence_mismatch, activation_sequence, entry.sequence + 1}
             ),
           :ok <-
             semantic_check(
               previous_digest == entry.previous_digest,
               :transition_previous_digest_mismatch
             ),
           true <- is_binary(new_key_id),
           true <- is_binary(proof),
           {:ok, new_key} <-
             CoreIntegrity.verification_key(new_key_id, activation_sequence, integrity_opts),
           expected <-
             Chronicle.Keys.transition_proof(
               entry.ledger,
               old_key_id,
               new_key_id,
               transition_sequence,
               activation_sequence,
               previous_digest,
               new_key
             ),
           :ok <- semantic_check(proof == expected, :new_key_proof_mismatch) do
        :ok
      else
        {:error, reason} -> {:error, {:invalid_key_transition, entry.sequence, reason}}
        false -> {:error, {:invalid_key_transition, entry.sequence, :invalid_transition_field}}
      end
    end

    defp verify_semantics(entry, %{"events" => events}, _integrity_opts)
         when is_list(events) do
      if Enum.any?(
           events,
           &(Map.get(&1, :type, Map.get(&1, "type")) == "chronicle.key_transition")
         ) do
        {:error, {:invalid_key_transition, entry.sequence, :transition_must_be_standalone}}
      else
        :ok
      end
    end

    defp verify_semantics(_entry, _payload, _integrity_opts), do: :ok

    defp semantic_check(true, _reason), do: :ok
    defp semantic_check(false, reason), do: {:error, reason}

    defp fetch_data(data, key), do: Map.get(data, key, Map.get(data, safe_existing_atom(key)))

    # Group roots and standalone events are exactly the rows the ledger signs;
    # both have a null group_id, so one count covers them. Grouped children are
    # covered by their root's entry and are checked for orphans instead.
    defp verify_coverage(repo, ledger, opts) do
      events_source = {Keyword.get(opts, :events_table, "audit_events"), Schema.Event}

      entries_source =
        {Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries"), Schema.LedgerEntry}

      signed_records_query =
        from event in events_source,
          where: field(event, :ledger) == ^ledger and is_nil(field(event, :group_id)),
          select: count(field(event, :id))

      ledger_count_query =
        from entry in entries_source,
          where: field(entry, :ledger) == ^ledger,
          select: count(field(entry, :sequence))

      duplicate_reference_query =
        from entry in entries_source,
          where: field(entry, :ledger) == ^ledger,
          group_by: [field(entry, :kind), field(entry, :record_id)],
          having: count(field(entry, :sequence)) > 1,
          limit: 1,
          select: count(field(entry, :sequence))

      orphan_child_query =
        from event in events_source,
          left_join: root in ^events_source,
          on:
            field(root, :id) == field(event, :group_id) and
              field(root, :ledger) == field(event, :ledger) and
              field(root, :kind) == "group",
          where:
            field(event, :ledger) == ^ledger and not is_nil(field(event, :group_id)) and
              is_nil(field(root, :id)),
          select: count(field(event, :id))

      repo_opts = repo_options(opts)
      expected_records = repo.one(signed_records_query, repo_opts)
      ledger_records = repo.one(ledger_count_query, repo_opts)
      duplicate? = not is_nil(repo.one(duplicate_reference_query, repo_opts))
      orphan_children = repo.one(orphan_child_query, repo_opts)

      cond do
        duplicate? ->
          {:error, :duplicate_ledger_record_reference}

        orphan_children > 0 ->
          {:error, :group_event_coverage_mismatch}

        expected_records != ledger_records ->
          {:error,
           {:ledger_coverage_mismatch,
            %{expected_records: expected_records, ledger_records: ledger_records}}}

        true ->
          {:ok, ledger_records}
      end
    end

    defp load_payloads(repo, ledger, entries, opts) do
      events_source = {Keyword.get(opts, :events_table, "audit_events"), Schema.Event}

      record_ids = for %{record_id: id} <- entries, do: id
      group_ids = for %{kind: :group, record_id: id} <- entries, do: id

      query =
        from event in events_source,
          where:
            field(event, :ledger) == ^ledger and
              (field(event, :id) in ^record_ids or field(event, :group_id) in ^group_ids),
          select: map(event, ^Schema.Event.content_fields())

      rows = repo.all(query, repo_options(opts))

      {:ok,
       %{
         records: Map.new(rows, &{&1.id, &1}),
         children:
           rows
           |> Enum.reject(&is_nil(&1.group_id))
           |> Enum.group_by(& &1.group_id)
           |> Map.new(fn {group_id, children} ->
             {group_id, Enum.sort_by(children, & &1.sequence)}
           end)
       }}
    end

    defp payload(payloads, %{kind: :event, record_id: id}),
      do: fetch_payload(payloads.records, :event, id)

    defp payload(payloads, %{kind: :group, record_id: id}) do
      with {:ok, root} <- fetch_payload(payloads.records, :group, id) do
        events = Map.get(payloads.children, id, [])

        if root.event_count == length(events) do
          {:ok, %{"group" => root, "events" => events}}
        else
          {:error, {:group_event_count_mismatch, id, root.event_count, length(events)}}
        end
      end
    end

    defp fetch_payload(map, _kind, id) when is_map_key(map, id), do: {:ok, Map.fetch!(map, id)}
    defp fetch_payload(_map, kind, id), do: {:error, {:audit_record_missing, kind, id}}

    # A ceiling, not a preference. Verification walks a ledger that grows
    # without bound, so batches are what keep peak memory a function of the
    # batch size rather than of how long the system has been running.
    defp valid_batch_size(size) when is_integer(size) and size > 0 and size <= 10_000, do: :ok

    defp valid_batch_size(size),
      do: {:error, {:invalid_verification_batch_size, size}}

    # The head row is mutable and the entries are not, so disagreement between
    # them means one of the two was edited. Checking it is what turns a forged
    # head into a detected forgery rather than a shortcut past the whole chain.
    defp verify_head(head, final) do
      if head.sequence == final.sequence and head.digest == final.digest do
        :ok
      else
        {:error,
         {:ledger_head_mismatch, %{sequence: head.sequence, digest: head.digest},
          %{sequence: final.sequence, digest: final.digest}}}
      end
    end

    defp verify_external_checkpoint(nil, _anchored?), do: :ok
    defp verify_external_checkpoint(_checkpoint, true), do: :ok

    defp verify_external_checkpoint(checkpoint, false),
      do: {:error, {:checkpoint_mismatch, checkpoint}}

    defp checkpoint_matches?(nil, _current), do: false

    defp checkpoint_matches?(expected, current) do
      expected.ledger == current.ledger and
        expected.sequence == current.sequence and
        expected.digest == current.digest
    end

    defp normalize_checkpoint(nil), do: nil
    defp normalize_checkpoint(%Checkpoint{} = checkpoint), do: checkpoint

    defp normalize_checkpoint(checkpoint) when is_map(checkpoint) do
      %Checkpoint{
        ledger: Map.get(checkpoint, :ledger, Map.get(checkpoint, "ledger")),
        sequence: Map.get(checkpoint, :sequence, Map.get(checkpoint, "sequence")),
        digest: Map.get(checkpoint, :digest, Map.get(checkpoint, "digest"))
      }
    end

    defp safe_existing_atom(value) do
      String.to_existing_atom(value)
    rescue
      ArgumentError -> nil
    end

    defp repo_options(opts) do
      case Keyword.fetch(opts, :prefix) do
        {:ok, prefix} -> [prefix: prefix]
        :error -> []
      end
    end
  end
end

defmodule Chronicle.IntegrityError do
  defexception [:message, :reason]

  @impl true
  def exception(reason) do
    %__MODULE__{
      message: "audit integrity verification failed: #{inspect(reason)}",
      reason: reason
    }
  end
end
