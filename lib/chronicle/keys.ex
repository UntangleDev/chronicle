defmodule Chronicle.Keys do
  @moduledoc """
  Reports the signing keys required to verify a named audit store.

  Key material is never read back or returned. The result contains only key
  identifiers that are present in the ledger and the identifier configured for
  new writes. This module is reached by operators and by `mix` tasks, so it is
  assumed its output will end up in a terminal, a log, or a screenshot.
  """

  alias Chronicle.{Config, Error}

  @spec status(atom()) :: {:ok, map()} | {:error, Error.t()}
  def status(store \\ Config.default_store()) do
    if Code.ensure_loaded?(Chronicle.Keys.Ecto) do
      apply(Chronicle.Keys.Ecto, :status, [store])
    else
      {:error, Error.new(:keys, :ecto_not_available, store: store)}
    end
  rescue
    exception ->
      {:error, Error.new(:keys, {:provider_exception, exception, __STACKTRACE__}, store: store)}
  end

  @spec generate() :: String.t()
  def generate, do: 32 |> :crypto.strong_rand_bytes() |> Base.encode64()

  @doc """
  Low-level operation that verifies the store, then appends a transition signed
  by the old key and proven with the new key.

  This function cannot coordinate application nodes. The caller must drain
  writers and apply the returned epoch boundary and both keys across all nodes:
  the old key is valid through `transition_sequence`; the new key begins at
  `activates_at_sequence`. Prefer the non-mutating
  `mix chronicle.keys.rotate` planning workflow first.

  The whole store is verified before anything is written, and that ordering is
  not politeness. Rotation appends a transition entry signed by the outgoing
  key, so performing one over a chain that is already broken would anchor a
  fresh epoch onto corrupt history and lend it the new key's authority. If the
  ledger cannot be verified, there is nothing here worth rotating onto.

  A key id is refused if it already appears in the ledger. Entries name their
  signer by id, so reusing one makes two different keys indistinguishable in
  the historical record — and a verifier reading that record has no way to
  tell which of them it should be holding.
  """
  @spec rotate(atom(), String.t(), Chronicle.Key.source()) ::
          {:ok, map()} | {:error, Error.t()}
  def rotate(store, new_key_id, new_key_source) do
    with {:ok, status} <- status(store),
         :ok <- unused_key_id(new_key_id, status),
         {:ok, _new_key} <- Chronicle.Integrity.resolve_key(new_key_source),
         {:ok, _checkpoints} <- Chronicle.verify_all(store),
         {:ok, config} <- Config.fetch_store(store),
         :ok <- ecto_provider(config),
         {:ok, plan} <-
           apply(Chronicle.Provider.Ecto, :write_key_transition, [
             new_key_id,
             new_key_source,
             config.options
           ]) do
      {:ok, plan}
    else
      {:error, %Error{} = error} -> {:error, error}
      {:error, reason} -> {:error, Error.wrap(:keys, reason, store: store)}
    end
  rescue
    exception ->
      {:error, Error.new(:keys, {:rotation_exception, exception, __STACKTRACE__}, store: store)}
  end

  # Signed with the *new* key over a tuple naming both keys, both sequence
  # boundaries, and the digest it follows. Signing with the outgoing key would
  # only restate what the outgoing key could already say; signing with the
  # incoming one proves whoever performed the rotation actually held the key
  # they were rotating to, at a position bound to the existing chain. Without
  # that, an attacker holding the old key could announce a handover to a key
  # of their own choosing and have it verify.
  @doc false
  def transition_proof(
        ledger,
        old_key_id,
        new_key_id,
        transition_sequence,
        activation_sequence,
        previous_digest,
        new_key
      ) do
    {:audit_key_transition_v1, ledger, old_key_id, new_key_id, transition_sequence,
     activation_sequence, previous_digest}
    |> Chronicle.Canonical.encode()
    |> then(&Chronicle.Digest.hmac_sha256(new_key, &1))
  end

  defp unused_key_id(key_id, status)
       when is_binary(key_id) and byte_size(key_id) > 0 do
    if key_id == status.current or key_id in status.required do
      {:error, {:key_id_already_used, key_id}}
    else
      :ok
    end
  end

  defp unused_key_id(key_id, _status), do: {:error, {:invalid_key_id, key_id}}

  defp ecto_provider(%{provider: Chronicle.Provider.Ecto}), do: :ok
  defp ecto_provider(%{provider: provider}), do: {:error, {:rotation_not_supported, provider}}
end

if Code.ensure_loaded?(Ecto.Query) do
  defmodule Chronicle.Keys.Ecto do
    @moduledoc false

    # Compiled only when Ecto is present, which is why it is reached through
    # `Code.ensure_loaded?/1` from `Chronicle.Keys` rather than aliased directly:
    # the library is usable without Ecto, and a missing optional dependency
    # should produce a clear error rather than an undefined-module crash.

    import Ecto.Query

    alias Chronicle.{Config, Error}

    @spec status(atom()) :: {:ok, map()} | {:error, Error.t()}
    def status(store) do
      with {:ok, store_config} <- Config.fetch_store(store),
           {:ok, repo} <- fetch_repo(store_config.options) do
        entries_table =
          Keyword.get(store_config.options, :ledger_entries_table, "audit_ledger_entries")

        query =
          from entry in {entries_table, Chronicle.Ecto.Schema.LedgerEntry},
            distinct: true,
            select: entry.key_id

        required =
          repo.all(query, repo_options(store_config.options))
          |> Enum.reject(&is_nil/1)
          |> Enum.sort()

        integrity = Chronicle.Ecto.Ledger.integrity_options!(store_config.options)
        next_sequence = next_sequence(repo, entries_table, integrity, store_config.options)

        # Two independent questions. `missing` is about reading history: keys
        # that signed existing entries but can no longer be resolved. `signing`
        # is about writing: whether the next entry can be signed at all. A
        # store with no history yet can have nothing missing and still be
        # unable to accept a single write.
        {current, signing} =
          signing_status(Keyword.get(integrity, :ledger, "default"), next_sequence, integrity)

        {:ok,
         %{
           store: store,
           current: current,
           signing: signing,
           next_sequence: next_sequence,
           epoch_policy?: Chronicle.Keyring.epoch_policy?(integrity),
           required: required,
           missing: missing_keys(required, store_config.options)
         }}
      else
        {:error, reason} -> {:error, Error.wrap(:keys, reason, store: store)}
      end
    end

    defp signing_status(ledger, sequence, integrity) do
      with {:ok, key} <- Chronicle.Keyring.current(ledger, sequence, integrity),
           {:ok, _material} <- Chronicle.Integrity.resolve_key(key.source) do
        {key.id, :ok}
      else
        {:error, reason} -> {nil, {:error, reason}}
      end
    end

    defp fetch_repo(options) do
      case Keyword.fetch(options, :repo) do
        {:ok, repo} -> {:ok, repo}
        :error -> {:error, :repo_not_configured}
      end
    end

    defp missing_keys(required, options) do
      integrity = Chronicle.Ecto.Ledger.integrity_options!(options)

      Enum.reject(required, fn key_id ->
        match?({:ok, _key}, Chronicle.Integrity.verification_key(key_id, integrity))
      end)
    end

    defp next_sequence(repo, entries_table, integrity, options) do
      ledger = Keyword.get(integrity, :ledger, "default")

      query =
        from entry in {entries_table, Chronicle.Ecto.Schema.LedgerEntry},
          where: entry.ledger == ^ledger,
          select: max(entry.sequence)

      repo.one(query, repo_options(options))
      |> Kernel.||(0)
      |> Kernel.+(1)
    end

    defp repo_options(options) do
      options
      |> Keyword.get(:repo_options, [])
      |> then(fn repo_options ->
        case Keyword.fetch(options, :prefix) do
          {:ok, prefix} -> Keyword.put(repo_options, :prefix, prefix)
          :error -> repo_options
        end
      end)
    end
  end
end
