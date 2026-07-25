defmodule Chronicle.Health do
  @moduledoc """
  On-demand operational health for one named audit store.

  Health checks signing-key availability, the latest background-verifier
  result, and the distance from the independently stored checkpoint to the
  current ledger head. It performs only bounded reads: health endpoints never
  trigger a complete ledger verification or advance a checkpoint.

  That restraint is deliberate twice over. A health endpoint that walked the
  ledger would hand anyone who can reach it an unbounded query, and one that
  advanced a checkpoint would let a liveness probe anchor history nobody had
  verified.

  `healthy?` requires that the next write could actually be signed, not merely
  that past writes verify. Those are different questions, and answering only
  the second produces the worst possible report: a store whose history is
  intact, whose signing key cannot be resolved, and which therefore fails every
  write while reporting itself well. Distance from the last checkpoint is
  reported rather than judged, because how far behind is too far is an
  operational decision this library cannot make.
  """

  alias Chronicle.{CheckpointStore, Config, Error}

  @spec check(atom(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def check(store \\ Config.default_store(), opts \\ []) do
    checked_at = DateTime.utc_now()

    with {:ok, config} <- Config.fetch_store(store),
         {:ok, keys} <- Chronicle.Keys.status(store),
         {:ok, current} <- current_checkpoints(store) do
      verifier = verifier_status(config, store, opts)
      {anchor_status, anchored, lag} = anchor(config, store, current, opts)

      # Being able to sign the next entry is a precondition, not a detail: the
      # provider fails closed, so an unusable signing key stops the domain
      # operation too.
      healthy? =
        keys.signing == :ok and keys.missing == [] and verifier.last_result == :ok and
          verifier.store == store and anchor_status == :ok

      {:ok,
       %{
         store: store,
         healthy?: healthy?,
         checked_at: checked_at,
         keys: keys,
         verifier: verifier,
         checkpoints: current,
         anchor: %{status: anchor_status, checkpoints: anchored, lag: lag}
       }}
    else
      {:error, %Error{} = error} -> {:error, error}
      {:error, reason} -> {:error, Error.wrap(:health, reason, store: store)}
    end
  end

  defp current_checkpoints(store) do
    case Chronicle.checkpoint(store) do
      {:ok, checkpoint} -> {:ok, %{checkpoint.ledger => checkpoint}}
      {:error, %Error{reason: :ledger_not_initialized}} -> {:ok, %{}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp verifier_status(config, store, opts) do
    case Keyword.get(opts, :verifier, Keyword.get(config.options, :verifier)) do
      nil ->
        %{store: store, last_result: :not_running, last_checked_at: nil, checkpoints: %{}}

      server ->
        Chronicle.Verifier.status(server)
    end
  catch
    :exit, reason ->
      %{
        store: store,
        last_result: {:unavailable, reason},
        last_checked_at: nil,
        checkpoints: %{}
      }
  end

  defp anchor(config, store, current, opts) do
    case Keyword.get(opts, :checkpoint_store, Keyword.get(config.options, :checkpoint_store)) do
      nil ->
        {:not_configured, %{}, unknown_lag(current)}

      module ->
        case module.load(store) do
          {:ok, encoded} ->
            anchored = CheckpointStore.decode(encoded)
            lag = sequence_lag(current, anchored)

            status = anchor_status(lag)

            {status, anchored, lag}

          :not_found ->
            {:not_initialized, %{}, unknown_lag(current)}

          {:error, reason} ->
            {:error, %{error: reason}, unknown_lag(current)}
        end
    end
  rescue
    exception -> {:error, %{error: exception}, unknown_lag(current)}
  end

  defp sequence_lag(current, anchored) do
    current
    |> Map.keys()
    |> Kernel.++(Map.keys(anchored))
    |> Enum.uniq()
    |> Map.new(fn ledger ->
      current_sequence = current |> Map.get(ledger, %{sequence: 0}) |> Map.get(:sequence, 0)
      anchor_sequence = anchored |> Map.get(ledger, %{sequence: 0}) |> Map.get(:sequence, 0)
      {ledger, current_sequence - anchor_sequence}
    end)
  end

  defp anchor_status(lag) do
    cond do
      Enum.any?(lag, fn {_ledger, value} -> value < 0 end) -> :ahead_of_database
      Enum.any?(lag, fn {_ledger, value} -> value > 0 end) -> :behind
      true -> :ok
    end
  end

  defp unknown_lag(current),
    do: Map.new(current, fn {ledger, _checkpoint} -> {ledger, :unknown} end)
end
