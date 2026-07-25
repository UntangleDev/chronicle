defmodule Chronicle.Config do
  @moduledoc """
  Resolves named audit stores.
  """

  alias Chronicle.Store

  @app :chronicle

  @doc false
  @spec get_env(atom(), term()) :: term()
  def get_env(key, default \\ nil), do: Application.get_env(@app, key, default)

  @spec default_store() :: atom()
  def default_store, do: get_env(:default_store, :primary)

  @doc """
  Returns the store named by call options, falling back to the default store.
  """
  @spec store_name(keyword()) :: atom()
  def store_name(opts), do: Keyword.get(opts, :store) || default_store()

  @spec fetch_store(atom() | nil) :: {:ok, Store.t()} | {:error, term()}
  def fetch_store(name \\ nil) do
    name = name || default_store()
    stores = get_env(:stores, [])

    case fetch_named(stores, name) do
      {:ok, config} ->
        build_store(name, config)

      :error ->
        simple_store(name)
    end
  end

  @spec store_names() :: [atom()]
  def store_names do
    case get_env(:stores, []) do
      [_ | _] = stores -> Keyword.keys(stores)
      _none -> if(get_env(:repo), do: [default_store()], else: [])
    end
  end

  @spec provider(keyword()) :: {:ok, module(), keyword(), atom() | nil} | {:error, term()}
  def provider(call_opts) do
    call_provider = Keyword.get(call_opts, :provider)
    call_provider_opts = Keyword.get(call_opts, :provider_options, [])

    cond do
      call_provider ->
        with {:ok, module, configured_opts} <- parse_provider(call_provider) do
          {:ok, module, Keyword.merge(configured_opts, call_provider_opts), call_opts[:store]}
        end

      true ->
        store_name = Keyword.get(call_opts, :store)

        with {:ok, store} <- fetch_store(store_name) do
          {:ok, store.provider, Keyword.merge(store.options, call_provider_opts), store.name}
        end
    end
  end

  defp fetch_named(stores, name) when is_list(stores), do: Keyword.fetch(stores, name)

  defp simple_store(name) do
    if name == default_store() and get_env(:repo) do
      integrity =
        get_env(
          :integrity,
          ledger: to_string(name),
          key_id: get_env(:key_id, "audit-met-primary"),
          key: get_env(:signing_key),
          lock: default_lock(get_env(:repo))
        )

      options =
        [
          repo: get_env(:repo),
          integrity: integrity
        ]
        |> maybe_put(:prefix, get_env(:prefix))

      {:ok, %Store{name: name, provider: Chronicle.Provider.Ecto, options: options}}
    else
      {:error, {:store_not_configured, name}}
    end
  end

  defp build_store(name, config) when is_list(config) do
    case Keyword.fetch(config, :provider) do
      {:ok, provider} ->
        with {:ok, module, provider_opts} <- parse_provider(provider) do
          options =
            config
            |> Keyword.delete(:provider)
            |> Keyword.merge(provider_opts)

          {:ok, %Store{name: name, provider: module, options: options}}
        end

      :error ->
        {:error, {:store_provider_missing, name}}
    end
  end

  defp build_store(name, config), do: {:error, {:invalid_store_configuration, name, config}}

  defp parse_provider(module) when is_atom(module), do: {:ok, module, []}

  defp parse_provider({module, options}) when is_atom(module) and is_list(options),
    do: {:ok, module, options}

  defp parse_provider(other), do: {:error, {:invalid_provider, other}}

  defp maybe_put(options, _key, nil), do: options
  defp maybe_put(options, key, value), do: Keyword.put(options, key, value)

  defp default_lock(repo) do
    adapter = if function_exported?(repo, :__adapter__, 0), do: repo.__adapter__()
    adapter != Ecto.Adapters.SQLite3
  rescue
    UndefinedFunctionError -> true
  end
end
