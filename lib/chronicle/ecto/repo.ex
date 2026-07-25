if Code.ensure_loaded?(Ecto.Multi) do
  defmodule Chronicle.Ecto.Repo do
    @moduledoc false

    # Mirrors `Ecto.Repo`'s write surface so adopting the library is a matter of
    # changing which module a call goes to, not of restructuring the code around
    # it. The names, arities, argument shapes and return values match
    # deliberately; anywhere they diverge, that divergence is the bug.
    #
    # Each operation runs the domain write and the audit write in one
    # transaction. That is the library's central bargain and its main cost: the
    # audit record cannot be lost independently of the change it describes, and
    # in exchange an audit failure fails the business operation. There is no
    # option to relax it, because an audit trail that is allowed to have gaps
    # under load is not evidence of anything.
    #
    # The bang variants raise where their siblings return an error tuple, and
    # exist only alongside them. They are a convenience for callers already
    # inside a transaction, where an exception is the idiomatic way to abort.

    alias Chronicle.Ecto.{History, Snapshot}

    @record_name :audit_record

    @spec insert(Ecto.Changeset.t(), keyword()) ::
            {:ok, struct()} | {:error, Ecto.Changeset.t() | Chronicle.Error.t()}
    def insert(%Ecto.Changeset{} = changeset, opts \\ []),
      do: operation(:insert, changeset, opts)

    @spec insert!(Ecto.Changeset.t(), keyword()) :: struct()
    def insert!(%Ecto.Changeset{} = changeset, opts \\ []),
      do: bang(:insert, insert(changeset, opts))

    @spec update(Ecto.Changeset.t(), keyword()) ::
            {:ok, struct()} | {:error, Ecto.Changeset.t() | Chronicle.Error.t()}
    def update(%Ecto.Changeset{} = changeset, opts \\ []),
      do: operation(:update, changeset, opts)

    @spec update!(Ecto.Changeset.t(), keyword()) :: struct()
    def update!(%Ecto.Changeset{} = changeset, opts \\ []),
      do: bang(:update, update(changeset, opts))

    @spec delete(Ecto.Changeset.t() | struct(), keyword()) ::
            {:ok, struct()} | {:error, Ecto.Changeset.t() | Chronicle.Error.t()}
    def delete(changeset_or_struct, opts \\ []),
      do: operation(:delete, changeset_or_struct, opts)

    @spec delete!(Ecto.Changeset.t() | struct(), keyword()) :: struct()
    def delete!(changeset_or_struct, opts \\ []),
      do: bang(:delete, delete(changeset_or_struct, opts))

    @spec transaction(String.t(), keyword(), (-> result)) ::
            {:ok, result} | {:error, term()}
          when result: term()
    def transaction(type, opts, fun)
        when is_binary(type) and is_list(opts) and is_function(fun, 0) do
      with {:ok, store} <- ecto_store(opts) do
        repo = Keyword.fetch!(store.options, :repo)
        transaction_options = Keyword.get(opts, :transaction_options, [])

        # Outcome classification falls through to Chronicle.Classifier's
        # `:default`, so a block returning an ordinary value is a success and
        # one returning `{:error, reason}` is a failure.
        audit_opts = Keyword.delete(opts, :transaction_options)

        repo.transaction(
          fn -> Chronicle.Scope.run(type, audit_opts, fun) end,
          transaction_options
        )
      else
        {:error, reason} ->
          {:error, Chronicle.Error.wrap(:configure, reason, store: opts[:store])}
      end
    end

    @spec history(struct(), keyword()) ::
            {:ok, [Chronicle.Version.t()]} | {:error, Chronicle.Error.t()}
    def history(%schema{} = record, opts) do
      history(schema, Snapshot.subject(record), opts)
    end

    @spec history(module(), term(), keyword()) ::
            {:ok, [Chronicle.Version.t()]} | {:error, Chronicle.Error.t()}
    def history(schema, id, opts) when is_atom(schema) and is_list(opts) do
      subject =
        if is_map(id) and Map.has_key?(id, "type"), do: id, else: Snapshot.subject(schema, id)

      with {:ok, store} <- ecto_store(opts),
           {:ok, versions} <- History.history(store, schema, subject, opts) do
        {:ok, versions}
      else
        {:error, reason} -> {:error, Chronicle.Error.wrap(:history, reason, store: opts[:store])}
      end
    rescue
      exception ->
        {:error,
         Chronicle.Error.new(:history, {:provider_exception, exception, __STACKTRACE__},
           store: opts[:store]
         )}
    end

    @spec at(struct(), keyword()) :: {:ok, struct()} | {:error, Chronicle.Error.t()}
    def at(%schema{} = record, opts), do: at(schema, Snapshot.subject(record), opts)

    @spec at(module(), term(), keyword()) :: {:ok, struct()} | {:error, Chronicle.Error.t()}
    def at(schema, id, opts) when is_atom(schema) and is_list(opts) do
      subject =
        if is_map(id) and Map.has_key?(id, "type"), do: id, else: Snapshot.subject(schema, id)

      with {:ok, store} <- ecto_store(opts),
           {:ok, historical} <- History.at(store, schema, subject, opts) do
        {:ok, historical}
      else
        {:error, reason} ->
          {:error, Chronicle.Error.wrap(:time_travel, reason, store: opts[:store])}
      end
    rescue
      exception ->
        {:error,
         Chronicle.Error.new(:time_travel, {:provider_exception, exception, __STACKTRACE__},
           store: opts[:store]
         )}
    end

    @spec revert(struct(), keyword()) :: {:ok, Ecto.Changeset.t()} | {:error, Chronicle.Error.t()}
    def revert(%_schema{} = current, opts) do
      subject = Snapshot.subject(current)

      with {:ok, store} <- ecto_store(opts),
           {:ok, changeset} <- History.revert(store, current, subject, opts) do
        {:ok, changeset}
      else
        {:error, reason} ->
          {:error, Chronicle.Error.wrap(:revert, reason, store: opts[:store])}
      end
    rescue
      exception ->
        {:error,
         Chronicle.Error.new(:revert, {:provider_exception, exception, __STACKTRACE__},
           store: opts[:store]
         )}
    end

    defp operation(operation, changeset_or_struct, opts) do
      with {:ok, store} <- ecto_store(opts) do
        repo = Keyword.fetch!(store.options, :repo)
        transaction_options = Keyword.get(opts, :transaction_options, [])

        audit_opts =
          opts
          |> Keyword.delete(:transaction_options)
          |> Keyword.put_new(:store, store.name)

        multi =
          case operation do
            :insert ->
              Chronicle.Multi.insert(
                Ecto.Multi.new(),
                @record_name,
                changeset_or_struct,
                audit_opts
              )

            :update ->
              Chronicle.Multi.update(
                Ecto.Multi.new(),
                @record_name,
                changeset_or_struct,
                audit_opts
              )

            :delete ->
              Chronicle.Multi.delete(
                Ecto.Multi.new(),
                @record_name,
                changeset_or_struct,
                audit_opts
              )
          end

        case repo.transaction(multi, transaction_options) do
          {:ok, changes} ->
            {:ok, Map.fetch!(changes, @record_name)}

          {:error, @record_name, %Ecto.Changeset{} = changeset, _changes} ->
            {:error, changeset}

          {:error, {:chronicle, @record_name}, %Chronicle.Error{} = error, _changes} ->
            {:error, error}

          {:error, failed_operation, reason, _changes} ->
            {:error,
             Chronicle.Error.new(:write, {:transaction_failed, failed_operation, reason},
               store: store.name
             )}
        end
      else
        {:error, reason} ->
          {:error, Chronicle.Error.wrap(:configure, reason, store: opts[:store])}
      end
    rescue
      exception ->
        {:error,
         Chronicle.Error.new(:write, {:provider_exception, exception, __STACKTRACE__},
           store: opts[:store]
         )}
    end

    defp ecto_store(opts) do
      with {:ok, store} <- Chronicle.Config.fetch_store(opts[:store]) do
        if store.provider == Chronicle.Provider.Ecto do
          {:ok, store}
        else
          {:error, {:ecto_store_required, store.name}}
        end
      end
    end

    defp bang(_operation, {:ok, record}), do: record

    defp bang(operation, {:error, %Ecto.Changeset{} = changeset}) do
      raise Ecto.InvalidChangesetError, action: operation, changeset: changeset
    end

    defp bang(_operation, {:error, %Chronicle.Error{} = error}), do: raise(error)
  end
end
