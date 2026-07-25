defmodule Chronicle.CheckpointStore.Memory do
  @moduledoc """
  In-memory checkpoint store for tests and local development.

  It does not provide an independent durable anchor and must not be used as the
  production tamper-resistance boundary.
  """

  use Agent
  @behaviour Chronicle.CheckpointStore

  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts \\ []) do
    Agent.start_link(fn -> %{} end, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def load(store) do
    Agent.get(__MODULE__, fn state ->
      case Map.fetch(state, store) do
        {:ok, checkpoints} -> {:ok, checkpoints}
        :error -> :not_found
      end
    end)
  catch
    :exit, {:noproc, _reason} -> {:error, :checkpoint_store_not_started}
  end

  @impl true
  def save(store, checkpoints) do
    Agent.update(__MODULE__, &Map.put(&1, store, checkpoints))
  catch
    :exit, {:noproc, _reason} -> {:error, :checkpoint_store_not_started}
  end

  @spec reset() :: :ok | {:error, term()}
  def reset do
    Agent.update(__MODULE__, fn _state -> %{} end)
  catch
    :exit, {:noproc, _reason} -> {:error, :checkpoint_store_not_started}
  end
end
