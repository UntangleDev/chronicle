defmodule Chronicle.Erasure.Error do
  @moduledoc false

  defexception [:reason]

  @impl true
  def message(%__MODULE__{reason: reason}),
    do: "Chronicle could not protect an erasable value: #{inspect(reason)}"
end

defmodule Chronicle.Erasure do
  @moduledoc """
  Authenticated encryption for data that may later become unrecoverable.

  Chronicle encrypts the normalized value with AES-256-GCM under a
  keyring-managed data-encryption key. The signed ledger stores the ciphertext,
  authentication tag, nonce, format, and opaque key identifier—never the
  plaintext or key. Ledger verification therefore continues to authenticate
  the exact stored evidence after `destroy/1` makes the value unrecoverable.

  This control applies only to values marked before they are written. It cannot
  remove plaintext already committed to an older entry. Destroying a key is
  irreversible and is appropriate only after the application has applied its
  retention and legal-hold policy.
  """

  alias Chronicle.{Canonical, ErasureKeyring}

  @format "erasable-aes-256-gcm-v1"
  @nonce_bytes 12
  @tag_bytes 16

  @type envelope :: %{
          required(String.t()) => String.t()
        }

  @doc false
  @spec encrypt!(term(), String.t()) :: envelope()
  def encrypt!(value, key_id) do
    case encrypt(value, key_id) do
      {:ok, envelope} -> envelope
      {:error, reason} -> raise Chronicle.Erasure.Error, reason: reason
    end
  end

  @doc """
  Encrypts a value under the destroyable key named by `key_id`.

  Application code normally uses `Chronicle.erasable/2`, which defers this
  operation until Chronicle normalizes the surrounding event or snapshot.
  """
  @spec encrypt(term(), String.t()) :: {:ok, envelope()} | {:error, term()}
  def encrypt(value, key_id) do
    with {:ok, key} <- ErasureKeyring.fetch(key_id) do
      plaintext = value |> Chronicle.Value.canonical() |> Canonical.encode()
      nonce = :crypto.strong_rand_bytes(@nonce_bytes)
      aad = associated_data(key_id)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, aad, true)

      {:ok,
       %{
         "$chronicle" => @format,
         "key_id" => key_id,
         "nonce" => encode64(nonce),
         "ciphertext" => encode64(ciphertext),
         "tag" => encode64(tag)
       }}
    end
  end

  @doc """
  Decrypts one Chronicle erasable envelope while its key remains available.

  After successful key destruction this returns
  `{:error, {:erasure_key_unavailable, key_id}}`. Authentication failure is
  reported separately; no unauthenticated plaintext is returned.
  """
  @spec decrypt(envelope()) :: {:ok, term()} | {:error, term()}
  def decrypt(
        %{
          "$chronicle" => @format,
          "key_id" => key_id,
          "nonce" => encoded_nonce,
          "ciphertext" => encoded_ciphertext,
          "tag" => encoded_tag
        } = envelope
      )
      when is_binary(key_id) and map_size(envelope) == 5 do
    with {:ok, nonce} <- decode64(encoded_nonce, :nonce),
         :ok <- exact_size(nonce, @nonce_bytes, :nonce),
         {:ok, ciphertext} <- decode64(encoded_ciphertext, :ciphertext),
         {:ok, tag} <- decode64(encoded_tag, :tag),
         :ok <- exact_size(tag, @tag_bytes, :tag),
         {:ok, key} <- ErasureKeyring.fetch(key_id),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key,
             nonce,
             ciphertext,
             associated_data(key_id),
             tag,
             false
           ),
         {:ok, value} <- Canonical.decode(plaintext) do
      {:ok, value}
    else
      :error -> {:error, :erasable_value_authentication_failed}
      {:error, _reason} = error -> error
    end
  end

  def decrypt(_value), do: {:error, :invalid_erasable_envelope}

  @doc """
  Irreversibly destroys the key named by `key_id` through the configured
  erasure keyring.

  The keyring must not report success while a provider recovery window or
  replica can still resolve the key.
  """
  @spec destroy(String.t()) :: :ok | {:error, term()}
  def destroy(key_id), do: ErasureKeyring.destroy(key_id)

  @doc false
  @spec envelope?(term()) :: boolean()
  def envelope?(%{"$chronicle" => @format}), do: true
  def envelope?(_value), do: false

  # The AAD is part of the cipher format, so it is pinned to the encoder that
  # created version 1 rather than following Chronicle.Canonical's current
  # writer. Changing the current canonical version must not make old
  # ciphertext impossible to authenticate.
  defp associated_data(key_id),
    do: Chronicle.Canonical.V1.encode({:chronicle_erasable_v1, key_id})

  defp encode64(value), do: Base.url_encode64(value, padding: false)

  defp decode64(value, field) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, {:invalid_erasable_envelope_encoding, field}}
    end
  end

  defp decode64(_value, field), do: {:error, {:invalid_erasable_envelope_encoding, field}}

  defp exact_size(value, expected, _field) when byte_size(value) == expected, do: :ok

  defp exact_size(_value, _expected, field),
    do: {:error, {:invalid_erasable_envelope_size, field}}
end
