defmodule Chronicle.ErasureKeyring do
  @moduledoc """
  Behaviour and dispatcher for destroyable data-encryption keys.

  The keyring owns the key lifecycle; Chronicle owns only ciphertext and an
  opaque identifier. Configure one implementation globally:

      config :chronicle,
        erasure: [
          keyring: {MyApp.PrivacyKeys, vault: MyApp.Vault}
        ]

  Implementations must return exactly 32 bytes from `fetch/2`. `destroy/2`
  must return `:ok` only after future fetches of that identifier can no longer
  recover the key, including from replicas or provider-managed recovery
  windows. Backup and legal-hold policy remain the application's
  responsibility.

  Key identifiers are signed into the ledger. They must be stable, opaque, and
  contain no personal data.
  """

  @type options :: keyword()
  @type result :: {:ok, binary()} | {:error, term()}

  @callback fetch(String.t(), options()) :: result()
  @callback destroy(String.t(), options()) :: :ok | {:error, term()}

  @key_bytes 32

  @doc false
  @spec fetch(String.t()) :: result()
  def fetch(key_id) do
    with :ok <- valid_key_id(key_id),
         {:ok, module, options} <- implementation(),
         :ok <- callback(module, :fetch),
         result <- module.fetch(key_id, options),
         {:ok, key} <- normalize_fetch(result, key_id),
         :ok <- valid_key(key, key_id) do
      {:ok, key}
    end
  rescue
    exception -> {:error, {:erasure_keyring_failure, :fetch, exception.__struct__}}
  end

  @doc false
  @spec destroy(String.t()) :: :ok | {:error, term()}
  def destroy(key_id) do
    with :ok <- valid_key_id(key_id),
         {:ok, module, options} <- implementation(),
         :ok <- callback(module, :destroy),
         result <- module.destroy(key_id, options),
         :ok <- normalize_destroy(result, key_id) do
      :ok
    end
  rescue
    exception -> {:error, {:erasure_keyring_failure, :destroy, exception.__struct__}}
  end

  @doc """
  Returns whether an erasure keyring is configured.
  """
  @spec configured?() :: boolean()
  def configured?, do: match?({:ok, _module, _options}, implementation())

  defp implementation do
    case Chronicle.Config.get_env(:erasure, []) |> Keyword.get(:keyring) do
      {module, options} when is_atom(module) and is_list(options) ->
        {:ok, module, options}

      module when is_atom(module) and not is_nil(module) ->
        {:ok, module, []}

      nil ->
        {:error, :erasure_keyring_not_configured}

      _other ->
        {:error, :invalid_erasure_keyring_configuration}
    end
  end

  defp callback(module, function) do
    if Code.ensure_loaded?(module) and function_exported?(module, function, 2) do
      :ok
    else
      {:error, {:erasure_keyring_missing_callback, module, function}}
    end
  end

  defp normalize_fetch({:ok, key}, _key_id) when is_binary(key), do: {:ok, key}

  defp normalize_fetch({:error, _reason}, key_id),
    do: {:error, {:erasure_key_unavailable, key_id}}

  defp normalize_fetch(_other, _key_id),
    do: {:error, {:invalid_erasure_keyring_result, :fetch}}

  defp normalize_destroy(:ok, _key_id), do: :ok

  defp normalize_destroy({:error, _reason}, key_id),
    do: {:error, {:erasure_key_destruction_failed, key_id}}

  defp normalize_destroy(_other, _key_id),
    do: {:error, {:invalid_erasure_keyring_result, :destroy}}

  defp valid_key(key, _key_id) when byte_size(key) == @key_bytes, do: :ok

  defp valid_key(key, key_id),
    do: {:error, {:invalid_erasure_key_length, key_id, byte_size(key), @key_bytes}}

  defp valid_key_id(key_id) when is_binary(key_id) and byte_size(key_id) > 0, do: :ok
  defp valid_key_id(_key_id), do: {:error, :invalid_erasure_key_id}
end
