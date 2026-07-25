defmodule Chronicle.CheckpointStore do
  @moduledoc """
  Persistence boundary for independently anchored verification checkpoints.

  Production implementations should write to a different trust boundary from
  the audit database. Returning `:not_found` is valid only before the first
  successful verification.

  ## What "separate trust boundary" has to mean

  Separate credentials, separate administrators, separate failure domain. A
  file written by the same host, with the same credentials, as the database it
  is meant to police is not an independent witness — it falls to whoever the
  database falls to, in the same breath, and its presence makes the property
  look available when it is not.

  What is anchored here is only a position and a digest. Nothing about a
  checkpoint proves the ledger it came from was *correct* at that point; it
  proves the ledger has not been shortened or rewritten *since*. The chain
  supplies the rest.

  ## Checkpoints come back as untrusted input

  `decode/1` raises on anything malformed rather than working around it,
  because a checkpoint arrives from storage this library does not control and
  cannot vouch for. It insists that a checkpoint's own `ledger` matches the key
  it was filed under — otherwise one ledger's position could be presented as
  another's, and a rollback would be compared against a boundary from an
  entirely different chain, which it would clear easily.

  Digests must be exactly 64 lowercase hex characters, matching what
  `Chronicle.Digest` produces. A sequence of `0` paired with no digest is the
  one legitimate degenerate case: a ledger verified while still empty.

  The integrity of the checkpoint storage itself is assumed, not checked. An
  attacker who can write there can retire the anchor, and nothing in this
  module will notice.
  """

  alias Chronicle.Integrity.Checkpoint

  @callback load(store :: atom()) ::
              {:ok, %{optional(String.t()) => Checkpoint.t() | map()}}
              | :not_found
              | {:error, term()}
  @callback save(store :: atom(), checkpoints :: %{String.t() => Checkpoint.t()}) ::
              :ok | {:error, term()}

  @spec encode(map()) :: map()
  def encode(checkpoints) when is_map(checkpoints) do
    Map.new(checkpoints, fn {ledger, checkpoint} ->
      checkpoint = if is_struct(checkpoint), do: Map.from_struct(checkpoint), else: checkpoint
      {to_string(ledger), Chronicle.Value.canonical(checkpoint)}
    end)
  end

  @spec decode(map()) :: map()
  def decode(checkpoints) when is_map(checkpoints) do
    Map.new(checkpoints, fn {ledger, checkpoint} ->
      ledger = ledger_name!(ledger)
      checkpoint_ledger = checkpoint |> fetch!(:ledger) |> ledger_name!()
      sequence = fetch!(checkpoint, :sequence)
      digest = fetch!(checkpoint, :digest)

      unless checkpoint_ledger == ledger do
        raise ArgumentError,
              "checkpoint ledger #{inspect(checkpoint_ledger)} does not match key #{inspect(ledger)}"
      end

      unless is_integer(sequence) and sequence >= 0 do
        raise ArgumentError, "invalid checkpoint sequence for #{inspect(ledger)}"
      end

      unless valid_digest?(sequence, digest) do
        raise ArgumentError, "invalid checkpoint digest for #{inspect(ledger)}"
      end

      {ledger, %Checkpoint{ledger: ledger, sequence: sequence, digest: digest}}
    end)
  end

  defp fetch!(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.fetch!(map, Atom.to_string(key))
    end
  end

  defp ledger_name!(ledger) when is_atom(ledger), do: Atom.to_string(ledger)
  defp ledger_name!(ledger) when is_binary(ledger) and byte_size(ledger) > 0, do: ledger

  defp ledger_name!(ledger),
    do: raise(ArgumentError, "invalid checkpoint ledger #{inspect(ledger)}")

  defp valid_digest?(0, nil), do: true

  defp valid_digest?(sequence, digest) when sequence > 0 and is_binary(digest),
    do: String.match?(digest, ~r/\A[0-9a-f]{64}\z/)

  defp valid_digest?(_sequence, _digest), do: false
end
