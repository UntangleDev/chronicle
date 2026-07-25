defmodule Mix.Tasks.Chronicle.Doctor do
  use Mix.Task

  @shortdoc "Checks audit configuration, storage, signing, and ledger integrity"

  @moduledoc """
  Starts the application and checks a configured named audit store.

      mix chronicle.doctor
      mix chronicle.doctor --store security
  """

  @switches [store: :string]

  @impl true
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches)

    if positional != [] or invalid != [] do
      Mix.raise("invalid arguments; run `mix help chronicle.doctor`")
    end

    Mix.Task.run("app.start")
    store = parse_store(Keyword.get(opts, :store))

    {checks, store_config} = configuration_checks(store)
    checks = checks ++ storage_checks(store, store_config) ++ schema_checks()

    Enum.each(checks, &print_check/1)

    errors = Enum.count(checks, fn {_name, status, _detail} -> status == :error end)
    warnings = Enum.count(checks, fn {_name, status, _detail} -> status == :warning end)

    Mix.shell().info("")
    Mix.shell().info("#{length(checks)} checks: #{errors} errors, #{warnings} warnings")
    if errors > 0, do: Mix.raise("audit doctor found #{errors} failing checks")
  end

  defp configuration_checks(store) do
    case Chronicle.Config.fetch_store(store) do
      {:ok, config} ->
        provider_status =
          if config.provider == Chronicle.Provider.Ecto do
            {:provider, :ok, inspect(config.provider)}
          else
            {:provider, :warning,
             "#{inspect(config.provider)} does not provide the built-in tamper-evident ledger"}
          end

        repo_status =
          case Keyword.get(config.options, :repo) do
            repo when is_atom(repo) -> {:repo, :ok, inspect(repo)}
            _other -> {:repo, :error, "missing :repo"}
          end

        integrity_status =
          case Keyword.get(config.options, :integrity) do
            integrity when is_list(integrity) ->
              ledger = Keyword.get(integrity, :ledger, "default")

              with {:ok, descriptor} <- Chronicle.Keyring.current(ledger, 1, integrity),
                   {:ok, key} <- Chronicle.Integrity.resolve_key(descriptor.source) do
                {:signing_key, :ok,
                 "#{byte_size(key) * 8} bits; key id #{inspect(descriptor.id)}"}
              else
                {:error, reason} -> {:signing_key, :error, inspect(reason)}
              end

            _other ->
              {:signing_key, :error, "missing :integrity configuration"}
          end

        key_epoch_status =
          case Keyword.get(config.options, :integrity) do
            integrity when is_list(integrity) ->
              if Chronicle.Keyring.epoch_policy?(integrity) do
                {:key_epochs, :ok, "sequence-bounded key policy enabled"}
              else
                {:key_epochs, :warning,
                 "key is unbounded; configure :key_epochs or a custom :keyring before rotation"}
              end

            _other ->
              {:key_epochs, :error, "cannot evaluate without :integrity configuration"}
          end

        checkpoint_status =
          case Keyword.get(config.options, :checkpoint_store) do
            nil ->
              {:checkpoint_anchor, :warning,
               "configure Chronicle.Verifier with storage outside the audit database"}

            Chronicle.CheckpointStore.Memory ->
              {:checkpoint_anchor, :warning, "in-memory checkpoints are not a durable anchor"}

            module when is_atom(module) ->
              if Code.ensure_loaded?(module) and function_exported?(module, :load, 1) and
                   function_exported?(module, :save, 2) do
                {:checkpoint_anchor, :ok, inspect(module)}
              else
                {:checkpoint_anchor, :error,
                 "#{inspect(module)} does not implement load/1 and save/2"}
              end

            other ->
              {:checkpoint_anchor, :error, "invalid checkpoint store #{inspect(other)}"}
          end

        {[
           {:store, :ok, inspect(store)},
           provider_status,
           repo_status,
           integrity_status,
           key_epoch_status,
           checkpoint_status
         ], config}

      {:error, reason} ->
        {[{:store, :error, inspect(reason)}], nil}
    end
  end

  defp storage_checks(_store, nil), do: []

  defp storage_checks(store, config) do
    repo = config.options[:repo]

    if is_atom(repo) and config.provider == Chronicle.Provider.Ecto do
      table_checks =
        for {label, option, default} <- [
              {:events_table, :events_table, "audit_events"},
              {:ledger_heads_table, :ledger_heads_table, "audit_ledger_heads"},
              {:ledger_entries_table, :ledger_entries_table, "audit_ledger_entries"}
            ] do
          table = Keyword.get(config.options, option, default)

          try do
            if apply(Ecto.Adapters.SQL, :table_exists?, [
                 repo,
                 table,
                 Keyword.take(config.options, [:prefix])
               ]) do
              {label, :ok, table}
            else
              {label, :error, "#{table} does not exist"}
            end
          rescue
            exception -> {label, :error, Exception.message(exception)}
          end
        end

      table_errors? = Enum.any?(table_checks, fn {_name, status, _detail} -> status == :error end)

      verification =
        if table_errors? do
          {:verification, :error, "not run because required tables are missing"}
        else
          case Chronicle.verify_all(store) do
            {:ok, checkpoints} ->
              {:verification, :ok, "#{map_size(checkpoints)} ledgers verified"}

            {:error, error} ->
              {:verification, :error, Exception.message(error)}
          end
        end

      [lock_check(repo, config.options) | table_checks] ++ [verification]
    else
      []
    end
  end

  defp lock_check(repo, options) do
    adapter = if function_exported?(repo, :__adapter__, 0), do: repo.__adapter__()
    integrity = Keyword.get(options, :integrity, [])
    lock? = Keyword.get(integrity, :lock, true)

    cond do
      adapter == Ecto.Adapters.SQLite3 and not lock? ->
        {:ledger_lock, :ok, "SQLite transaction serialization; FOR UPDATE disabled"}

      adapter == Ecto.Adapters.SQLite3 ->
        {:ledger_lock, :error,
         "SQLite does not support FOR UPDATE; configure integrity: [lock: false]"}

      lock? ->
        {:ledger_lock, :ok, "FOR UPDATE enabled"}

      true ->
        {:ledger_lock, :error, "FOR UPDATE is disabled; concurrent commits can fork the chain"}
    end
  end

  # Protection and reconstruction pull in opposite directions: a protected
  # field cannot be restored. Report it so that trade-off is a decision rather
  # than a surprise the first time someone calls `Chronicle.at/2`. Excluded
  # fields are reported separately because they only narrow diffs.
  defp schema_checks do
    case audited_schemas() do
      :unknown ->
        [
          {:snapshot_coverage, :warning,
           "could not determine which application to scan, so no schema was checked; " <>
             "run this from an application, not an umbrella root"}
        ]

      [] ->
        [{:snapshot_coverage, :ok, "no audited Ecto schemas found"}]

      schemas ->
        checks =
          Enum.flat_map(schemas, fn schema ->
            protected = Chronicle.Redaction.protected_fields(schema)
            excluded = excluded_fields(schema)

            protected_check(schema, protected) ++ excluded_check(schema, excluded)
          end)

        if checks == [],
          do: [{:snapshot_coverage, :ok, "every audited schema is fully restorable"}],
          else: checks
    end
  end

  defp protected_check(_schema, []), do: []

  defp protected_check(schema, fields) do
    [
      {:snapshot_coverage, :warning,
       "#{inspect(schema)} protects #{inspect(fields)}; versions of it are not restorable " <>
         "by Chronicle.at/2 or Chronicle.revert/2"}
    ]
  end

  defp excluded_check(_schema, []), do: []

  defp excluded_check(schema, fields) do
    [
      {:change_selection, :ok,
       "#{inspect(schema)} excludes #{inspect(fields)} from diffs; an update touching only " <>
         "those fields records nothing. Versions remain restorable."}
    ]
  end

  defp excluded_fields(schema) do
    if Code.ensure_loaded?(Chronicle.Ecto.Policy) do
      policy = Chronicle.Ecto.Policy.get(schema)
      Enum.reject(schema.__schema__(:fields), &Chronicle.Ecto.Policy.tracked?(policy, &1))
    else
      []
    end
  end

  # Reports `:unknown` rather than an empty list when there is no application
  # to scan, so "nothing to check" is never mistaken for "everything is fine".
  defp audited_schemas do
    case Mix.Project.config()[:app] do
      nil ->
        :unknown

      app ->
        case :application.get_key(app, :modules) do
          {:ok, modules} -> Enum.filter(modules, &ecto_schema?/1)
          :undefined -> :unknown
        end
    end
  end

  defp ecto_schema?(module) do
    Code.ensure_loaded?(module) and function_exported?(module, :__schema__, 1) and
      is_list(module.__schema__(:fields))
  rescue
    _exception -> false
  end

  defp print_check({name, status, detail}) do
    label = status |> Atom.to_string() |> String.upcase()
    Mix.shell().info("[#{label}] #{name}: #{detail}")
  end

  defp parse_store(nil), do: Chronicle.Config.default_store()

  defp parse_store(name) do
    configured = Chronicle.Config.store_names()

    Enum.find(configured, &(Atom.to_string(&1) == name)) ||
      Mix.raise("unknown audit store #{inspect(name)}; configured stores: #{inspect(configured)}")
  end
end
