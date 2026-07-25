defmodule Chronicle.Keyring do
  @moduledoc """
  Behaviour and dispatcher for versioned audit signing keys.

  A keyring returns descriptors, not only secret bytes. Each descriptor carries
  the inclusive ledger sequence range in which the key is valid. Custom
  keyrings can resolve secrets from KMS, Vault, PKCS#11, or another secret
  manager without exposing that integration to the rest of Chronicle.

  Configure a module or `{module, options}`:

      integrity: [
        ledger: "primary",
        keyring: {MyApp.AuditKeyring, vault: MyApp.Vault}
      ]

  The built-in `Chronicle.Keyring.Config` is used when `:keyring` is omitted.

  ## Exactly one key, or an error

  `current/3` requires precisely one key to be valid at a given sequence. No
  key is an error, and so is more than one — reported as
  `:overlapping_key_epochs` rather than resolved by preferring the newest or
  the first match.

  That refusal is the point. If two keys are both acceptable at a position,
  then compromising either one is enough to write history that verifies, and
  the ledger can no longer say which key was supposed to have signed. An
  ambiguous signing policy is not a smaller version of a correct one; it is
  the vulnerability. Overlap is a configuration mistake, and guessing would
  hide it until it mattered.

  ## A keyring is somebody else's code

  Custom implementations reach secret managers over the network and can fail
  in ways this module cannot anticipate, so results are treated as untrusted
  input: the return value must be a `Chronicle.Key`, `fetch/4` confirms the
  descriptor carries the id that was actually requested, and exceptions are
  converted into `{:error, {:keyring_failure, exception_module}}` rather than
  escaping into the middle of a domain transaction. Exception messages and
  fields are discarded because secret-manager clients may put key material in
  them.
  """

  alias Chronicle.Key

  @type options :: keyword()
  @type result :: {:ok, Key.t()} | {:error, term()}

  @callback current(String.t(), pos_integer(), options()) :: result()
  @callback fetch(String.t(), String.t(), options()) :: result()

  @spec current(String.t(), pos_integer(), keyword()) :: result()
  def current(ledger, sequence, integrity_opts) do
    {module, options} = implementation(integrity_opts)

    with {:ok, key} <- module.current(ledger, sequence, options),
         {:ok, key} <- normalize_key(key),
         :ok <- valid_at(key, sequence) do
      {:ok, key}
    end
  rescue
    exception -> {:error, {:keyring_failure, exception.__struct__}}
  end

  @spec fetch(String.t(), String.t(), pos_integer() | nil, keyword()) :: result()
  def fetch(ledger, key_id, sequence, integrity_opts) do
    {module, options} = implementation(integrity_opts)

    with {:ok, key} <- module.fetch(ledger, key_id, options),
         {:ok, key} <- normalize_key(key),
         :ok <- matching_id(key, key_id),
         :ok <- valid_at(key, sequence) do
      {:ok, key}
    end
  rescue
    exception -> {:error, {:keyring_failure, exception.__struct__}}
  end

  @doc """
  Returns whether explicit epoch policy is configured.

  This is useful for operational diagnostics. A single unbounded key remains
  supported for initial deployments, but it cannot enforce a rotation boundary.
  """
  @spec epoch_policy?(keyword()) :: boolean()
  def epoch_policy?(integrity_opts) do
    Keyword.has_key?(integrity_opts, :keyring) or
      not is_nil(Keyword.get(integrity_opts, :key_epochs))
  end

  defp implementation(opts) do
    case Keyword.get(opts, :keyring, Chronicle.Keyring.Config) do
      {module, options} when is_atom(module) and is_list(options) ->
        {module, options}

      module when is_atom(module) ->
        {module, Keyword.get(opts, :keyring_options, opts)}

      other ->
        raise ArgumentError, "invalid audit keyring: #{inspect(other)}"
    end
  end

  defp normalize_key(%Key{} = key), do: {:ok, key}
  defp normalize_key(other), do: {:error, {:invalid_keyring_result, other}}

  defp matching_id(%Key{id: key_id}, key_id), do: :ok
  defp matching_id(%Key{id: actual}, expected), do: {:error, {:key_id_mismatch, expected, actual}}

  # A nil sequence skips the epoch check deliberately, for callers asking
  # "can this key be resolved at all" rather than "may it sign here" —
  # `Chronicle.Keys` uses it to report unresolvable historical keys. Any caller
  # that knows a position should pass it, because without one this answers a
  # strictly weaker question.
  defp valid_at(_key, nil), do: :ok

  defp valid_at(%Key{} = key, sequence) do
    if Key.valid_at?(key, sequence) do
      :ok
    else
      {:error, {:key_not_valid_at_sequence, key.id, sequence, {key.from, key.through}}}
    end
  end
end

defmodule Chronicle.Keyring.Config do
  @moduledoc """
  Keyring backed by the audit store's integrity keyword configuration.

  The compact single-key form is valid before the first rotation:

      [key_id: "key-1", key: {:system, "AUDIT_KEY", :base64}]

  For enforceable rotation boundaries, configure all key sources and epochs:

      [
        keys: %{
          "key-1" => {:system, "AUDIT_KEY_1", :base64},
          "key-2" => {:system, "AUDIT_KEY_2", :base64}
        },
        key_epochs: %{
          "key-1" => [from: 1, through: 10_000],
          "key-2" => [from: 10_001]
        }
      ]

  New writes automatically select the sole key valid at the next sequence.

  The two forms are capability tiers rather than two spellings of one thing.
  The compact form has no epoch to enforce, so it cannot express a rotation
  boundary at all — every key is valid everywhere, and a retired key stays as
  powerful as it ever was. That is acceptable before the first rotation and
  not afterwards, which is why `Chronicle.Keyring.epoch_policy?/1` exists: an
  operator needs to be able to ask which of the two they are actually running.
  """

  @behaviour Chronicle.Keyring

  alias Chronicle.Key

  @impl true
  def current(_ledger, sequence, opts) do
    case Keyword.get(opts, :key_epochs) do
      nil ->
        descriptor(Keyword.get(opts, :key_id), Keyword.get(opts, :key), nil)

      epochs ->
        epochs
        |> entries()
        |> Enum.reduce([], fn {key_id, epoch}, matches ->
          with {:ok, key} <- descriptor(to_string(key_id), key_source(opts, key_id), epoch),
               true <- Key.valid_at?(key, sequence) do
            [key | matches]
          else
            _ -> matches
          end
        end)
        |> case do
          [key] -> {:ok, key}
          [] -> {:error, {:no_signing_key_for_sequence, sequence}}
          keys -> {:error, {:overlapping_key_epochs, sequence, Enum.map(keys, & &1.id)}}
        end
    end
  end

  @impl true
  def fetch(_ledger, key_id, opts) do
    epochs = Keyword.get(opts, :key_epochs)
    epoch = fetch_value(epochs, key_id)
    source = key_source(opts, key_id)

    cond do
      not is_nil(epochs) and is_nil(epoch) ->
        {:error, {:key_epoch_not_found, key_id}}

      is_nil(source) ->
        {:error, {:verification_key_not_found, key_id}}

      true ->
        descriptor(key_id, source, epoch)
    end
  end

  defp descriptor(key_id, source, epoch)
       when is_binary(key_id) and byte_size(key_id) > 0 and not is_nil(source) do
    with {:ok, first, last} <- normalize_epoch(epoch) do
      {:ok, %Key{id: key_id, source: source, from: first, through: last}}
    end
  end

  defp descriptor(key_id, _source, _epoch),
    do: {:error, {:invalid_integrity_option, :key_id, key_id}}

  defp normalize_epoch(nil), do: {:ok, 1, nil}

  defp normalize_epoch(epoch) when is_list(epoch) do
    first = Keyword.get(epoch, :from, 1)
    last = Keyword.get(epoch, :through)

    cond do
      not is_integer(first) or first < 1 ->
        {:error, {:invalid_key_epoch, epoch}}

      not is_nil(last) and (not is_integer(last) or last < first) ->
        {:error, {:invalid_key_epoch, epoch}}

      true ->
        {:ok, first, last}
    end
  end

  defp normalize_epoch(other), do: {:error, {:invalid_key_epoch, other}}

  defp key_source(opts, key_id) do
    from_keys = fetch_value(Keyword.get(opts, :keys), key_id)

    cond do
      not is_nil(from_keys) ->
        from_keys

      to_string(Keyword.get(opts, :key_id)) == to_string(key_id) ->
        Keyword.get(opts, :key)

      true ->
        nil
    end
  end

  defp fetch_value(nil, _key), do: nil

  defp fetch_value(values, key) when is_map(values) do
    Enum.find_value(values, fn {candidate, value} ->
      if to_string(candidate) == to_string(key), do: value
    end)
  end

  defp entries(values) when is_map(values), do: Map.to_list(values)
end
