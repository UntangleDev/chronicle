if Code.ensure_loaded?(Ecto.Query) do
  defmodule Chronicle.Ecto.Ledger do
    @moduledoc false

    # Where total order comes from, and therefore where the chain stops being a
    # collection of signed rows and becomes a sequence.
    #
    # `with_position/3` locks the head row before the caller builds anything,
    # because the sequence number and the preceding digest are hashed into the
    # entry: a writer that took its position afterwards would be signing a
    # place in history it does not hold. Without the lock, two concurrent
    # writers read the same head, both build entry N+1 against the same
    # previous digest, and the result is two individually valid entries and no
    # chain. Nothing downstream can repair that, which is why the lock is taken
    # pessimistically rather than resolved by retrying on conflict.
    #
    # On PostgreSQL that lock is `SELECT ... FOR UPDATE`. SQLite permits one
    # writer at a time regardless, so it configures `lock: false` — correct
    # there, and the reason a SQLite-only test run proves nothing about this
    # file. See the `mix chronicle.doctor` ledger-lock check, which exists so an
    # operator can find out which of the two they are running on.
    #
    # `commit/3` calls `repo.rollback/1` rather than returning an error when a
    # write does not land exactly once. It runs inside the caller's
    # transaction, and an audit record that failed to commit has to take the
    # domain operation down with it — proceeding would leave the change without
    # the evidence that was supposed to accompany it.

    import Ecto.Query

    alias Chronicle.Integrity
    alias Chronicle.Ecto.Schema
    alias Chronicle.Integrity.{Checkpoint, Entry}

    @doc """
    Locks the ledger head and runs `fun` with the next position.

    Writers take the position before building the row so every signed record
    commits to its own place in the chain.
    """
    @spec with_position(
            Ecto.Repo.t(),
            keyword(),
            (pos_integer(), String.t() | nil, keyword() -> result)
          ) :: result | {:error, term()}
          when result: term()
    def with_position(repo, opts, fun) when is_function(fun, 3) do
      integrity_opts = integrity_options!(opts)
      ledger = Keyword.get(integrity_opts, :ledger, "default")

      with :ok <- ensure_head(repo, ledger, opts),
           {:ok, sequence, previous_digest} <- lock_head(repo, ledger, opts) do
        fun.(sequence + 1, previous_digest, integrity_opts)
      end
    end

    @spec commit(Ecto.Repo.t(), Entry.t(), keyword()) :: Checkpoint.t()
    def commit(repo, %Entry{} = entry, opts) do
      entries_table =
        {Keyword.get(opts, :ledger_entries_table, "audit_ledger_entries"), Schema.LedgerEntry}

      heads_table =
        {Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads"), Schema.LedgerHead}

      repo_opts = repo_options(opts)

      case repo.insert_all(entries_table, [Integrity.entry_row(entry)], repo_opts) do
        {1, _} -> :ok
        other -> repo.rollback({:unexpected_ledger_insert_result, other})
      end

      head_query =
        from head in heads_table,
          where: field(head, :ledger) == ^entry.ledger

      case repo.update_all(
             head_query,
             [
               set: [
                 sequence: entry.sequence,
                 digest: entry.digest,
                 updated_at: DateTime.utc_now()
               ]
             ],
             repo_opts
           ) do
        {1, _} -> :ok
        other -> repo.rollback({:unexpected_ledger_head_update_result, other})
      end

      %Checkpoint{ledger: entry.ledger, sequence: entry.sequence, digest: entry.digest}
    end

    @spec checkpoint(Ecto.Repo.t(), keyword()) ::
            {:ok, Checkpoint.t()} | {:error, :ledger_not_initialized}
    def checkpoint(repo, opts) do
      integrity_opts = integrity_options!(opts)
      ledger = Keyword.get(integrity_opts, :ledger, "default")

      heads_table =
        {Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads"), Schema.LedgerHead}

      query =
        from head in heads_table,
          where: field(head, :ledger) == ^ledger,
          select: {field(head, :sequence), field(head, :digest)}

      case repo.one(query, repo_options(opts)) do
        {sequence, digest} ->
          {:ok, %Checkpoint{ledger: ledger, sequence: sequence, digest: digest}}

        nil ->
          {:error, :ledger_not_initialized}
      end
    end

    @doc """
    Fetches the integrity options, raising if they are absent or disabled.

    `false` raises rather than returning an unsigned mode, because there isn't
    one. Every path that reaches this module produces a signed entry or fails
    the surrounding write; a caller asking to turn that off is asking for
    something the provider cannot do, and the useful answer is to say so
    loudly rather than to quietly write records nobody can later trust.
    """
    @spec integrity_options!(keyword()) :: keyword()
    def integrity_options!(opts) do
      case Keyword.get(opts, :integrity) do
        integrity when is_list(integrity) ->
          integrity

        false ->
          raise ArgumentError, "integrity is explicitly disabled"

        nil ->
          raise ArgumentError, "Chronicle.Provider.Ecto requires the :integrity option"

        other ->
          raise ArgumentError, "expected :integrity to be a keyword list, got: #{inspect(other)}"
      end
    end

    # Idempotent by design: `on_conflict: :nothing` means two writers racing to
    # initialise the same ledger both succeed, one having done nothing, and
    # both go on to contend for the lock properly. The alternative — checking
    # for the row and inserting if absent — is the same race with a window in
    # it. Sequence 0 with a null digest is the genesis position, and the only
    # legitimate way for a head to carry no digest.
    defp ensure_head(repo, ledger, opts) do
      table =
        {Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads"), Schema.LedgerHead}

      result =
        repo.insert_all(
          table,
          [
            %{
              ledger: ledger,
              sequence: 0,
              digest: nil,
              updated_at: DateTime.utc_now()
            }
          ],
          Keyword.merge(
            [on_conflict: :nothing, conflict_target: [:ledger]],
            repo_options(opts)
          )
        )

      case result do
        {count, _} when count in [0, 1] -> :ok
        other -> {:error, {:unexpected_ledger_head_insert_result, other}}
      end
    end

    defp lock_head(repo, ledger, opts) do
      table =
        {Keyword.get(opts, :ledger_heads_table, "audit_ledger_heads"), Schema.LedgerHead}

      lock? = Keyword.get(integrity_options!(opts), :lock, true)

      query =
        from head in table,
          where: field(head, :ledger) == ^ledger,
          select: {field(head, :sequence), field(head, :digest)}

      query = if lock?, do: from(head in query, lock: "FOR UPDATE"), else: query

      case repo.one(query, repo_options(opts)) do
        {sequence, digest} -> {:ok, sequence, digest}
        nil -> {:error, :ledger_head_missing}
      end
    end

    defp repo_options(opts) do
      case Keyword.fetch(opts, :prefix) do
        {:ok, prefix} -> [prefix: prefix]
        :error -> []
      end
    end
  end
end
