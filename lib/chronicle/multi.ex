if Code.ensure_loaded?(Ecto.Multi) do
  defmodule Chronicle.Multi do
    @moduledoc """
    Audited operations for an ordinary `Ecto.Multi`.

    Each helper adds the requested Ecto operation followed by an audit step in
    the same repository transaction. No wrapper struct or special transaction
    function is involved.

    What goes in is an `Ecto.Multi` and what comes out is an `Ecto.Multi`, so
    everything that already works on one keeps working: inspecting the
    operations, appending to it, merging it, running it with the repo's own
    `transaction/2`. A wrapper type would have to re-expose all of that, would
    drift from `Ecto.Multi` as it gained features, and would buy nothing — the
    audit step is just another named operation, which is what `Ecto.Multi` is
    already for.
    """

    alias Chronicle.Ecto, as: AuditEcto
    alias Elixir.Ecto.Multi, as: EMulti

    @spec insert(EMulti.t(), EMulti.name(), Ecto.Changeset.t(), keyword()) :: EMulti.t()
    def insert(%EMulti{} = multi, name, changeset, opts \\ []) do
      multi
      |> EMulti.insert(name, changeset, Keyword.get(opts, :ecto_options, []))
      |> audit_operation(:insert, name, changeset, opts)
    end

    @spec update(EMulti.t(), EMulti.name(), Ecto.Changeset.t(), keyword()) :: EMulti.t()
    def update(%EMulti{} = multi, name, changeset, opts \\ []) do
      multi
      |> EMulti.update(name, changeset, Keyword.get(opts, :ecto_options, []))
      |> audit_operation(:update, name, changeset, opts)
    end

    @spec delete(EMulti.t(), EMulti.name(), Ecto.Changeset.t() | struct(), keyword()) ::
            EMulti.t()
    def delete(%EMulti{} = multi, name, changeset_or_struct, opts \\ []) do
      changeset = changeset(changeset_or_struct)

      multi
      |> EMulti.delete(name, changeset, Keyword.get(opts, :ecto_options, []))
      |> audit_operation(:delete, name, changeset, opts)
    end

    @doc """
    Adds an arbitrary audit fact built from preceding Multi results.

    The builder may return an `Chronicle.Event`, an event type, `{type, data}`,
    or `{type, data, options}`.
    """
    @spec record(
            EMulti.t(),
            EMulti.name(),
            (map() -> Chronicle.Event.t() | String.t() | tuple()),
            keyword()
          ) :: EMulti.t()
    def record(%EMulti{} = multi, name, builder, opts \\ []) when is_function(builder, 1) do
      audit(multi, name, fn changes -> normalize_event(builder.(changes), opts) end, opts)
    end

    @doc """
    Adds one audit step. Audit failures abort the surrounding transaction.
    """
    @spec audit(EMulti.t(), EMulti.name(), (map() -> Chronicle.Event.t()), keyword()) ::
            EMulti.t()
    def audit(%EMulti{} = multi, name, builder, opts \\ []) when is_function(builder, 1) do
      EMulti.run(multi, audit_name(name), fn repo, changes ->
        changes
        |> builder.()
        |> persist(repo, opts)
      end)
    end

    @doc false
    def audit_name(name), do: {:chronicle, name}

    defp audit_operation(multi, operation, name, changeset, opts) do
      event_opts = Keyword.drop(opts, [:ecto_options, :transaction_options])

      EMulti.run(multi, audit_name(name), fn repo, changes ->
        result = Map.fetch!(changes, name)
        field_changes = AuditEcto.changes(operation, changeset, result, event_opts)

        if AuditEcto.auditable?(operation, field_changes, event_opts) do
          operation
          |> AuditEcto.event(changeset, result, Keyword.put(event_opts, :changes, field_changes))
          |> persist(repo, opts)
        else
          {:ok, :not_audited}
        end
      end)
    end

    defp persist(%Chronicle.Event{} = event, repo, opts) do
      provider_options =
        opts
        |> Keyword.get(:provider_options, [])
        |> Keyword.put(:repo, repo)

      persist_opts = Keyword.put(opts, :provider_options, provider_options)

      case Chronicle.persist(event, persist_opts) do
        {:ok, persisted} -> {:ok, persisted}
        {:error, reason} -> {:error, reason}
      end
    end

    defp normalize_event(%Chronicle.Event{} = event, _opts), do: event

    defp normalize_event(type, opts) when is_binary(type),
      do: Chronicle.Event.new(type, %{}, opts)

    defp normalize_event({type, data}, opts), do: Chronicle.Event.new(type, data, opts)

    defp normalize_event({type, data, event_opts}, opts),
      do: Chronicle.Event.new(type, data, Keyword.merge(opts, event_opts))

    defp changeset(%Ecto.Changeset{} = changeset), do: changeset
    defp changeset(%_{} = schema), do: Ecto.Changeset.change(schema)
  end
end
