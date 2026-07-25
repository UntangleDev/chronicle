defmodule Chronicle.Provider.Memory do
  @moduledoc """
  An in-memory provider intended for tests and local development.
  """

  @behaviour Chronicle.Provider

  @type entry ::
          {:event, Chronicle.Event.t()}
          | {:group, Chronicle.Group.t(), [Chronicle.Event.t()]}

  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :name, __MODULE__),
      start: {__MODULE__, :start_link, [opts]},
      restart: :temporary
    }
  end

  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts \\ []) do
    Agent.start_link(fn -> [] end, Keyword.take(opts, [:name]))
  end

  @spec entries(Agent.agent()) :: [entry()]
  def entries(server), do: Agent.get(server, &Enum.reverse/1)

  @spec clear(Agent.agent()) :: :ok
  def clear(server), do: Agent.update(server, fn _ -> [] end)

  @impl true
  def write_event(event, opts) do
    Agent.update(fetch_server!(opts), &[{:event, event} | &1])
  end

  @impl true
  def write_group(group, events, opts) do
    Agent.update(fetch_server!(opts), &[{:group, group, events} | &1])
  end

  defp fetch_server!(opts) do
    Keyword.get(opts, :server) ||
      raise ArgumentError, "Chronicle.Provider.Memory requires the :server option"
  end
end
