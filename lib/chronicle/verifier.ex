defmodule Chronicle.Verifier do
  @moduledoc """
  Periodically verifies a named store against independently persisted anchors.

  A checkpoint is advanced only after the entire store verifies. Configure an
  `Chronicle.CheckpointStore` whose storage is outside the audit database's trust
  boundary.

  ## Load, verify, then save — in that order and no other

  Anchors are read before verification and fed into it as expectations; new
  checkpoints are written only once the whole store has verified. Advancing an
  anchor before or during the walk would permanently bless whatever history
  happened to be there, including history an attacker had just rewritten. The
  anchor is the only thing standing between this library and an undetectable
  rollback, so an anchor advanced over corrupt data is worse than no anchor at
  all — it converts a detectable attack into a signed-off one.

  A failed run therefore leaves the previous checkpoints in place. It does not
  advance them partially, and it does not clear them.

  ## Why a process, and why it does not crash

  This is one of the few places in the library that genuinely needs its own
  lifecycle: it owns a timer, it carries the last result between runs, and it
  must serialise verification so two overlapping runs cannot race to advance
  the same anchor.

  A verification failure is reported and scheduled again rather than raised.
  Crashing would hand a supervisor an invalid state to restart into, and the
  next run would fail identically — a restart loop rather than resilience.
  Misconfiguration is treated as the opposite case and raises in `init/1`: a
  verifier with no checkpoint store cannot do the one job it exists for, and
  discovering that at boot is far better than appearing healthy while
  anchoring nothing.
  """

  use GenServer
  require Logger

  alias Chronicle.{CheckpointStore, Config, Error}

  @default_interval :timer.minutes(5)

  @type status :: %{
          store: atom(),
          last_result: :not_run | :ok | {:error, Error.t()},
          last_checked_at: DateTime.t() | nil,
          checkpoints: map()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    {genserver_opts, opts} =
      Keyword.split(opts, [:name, :debug, :timeout, :spawn_opt, :hibernate_after])

    GenServer.start_link(__MODULE__, opts, genserver_opts)
  end

  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :id, {__MODULE__, Keyword.get(opts, :store, Config.default_store())}),
      start: {__MODULE__, :start_link, [opts]}
    }
  end

  @doc """
  Runs a verification immediately and returns its result.

  The `:infinity` timeout is deliberate rather than inherited. Verification
  walks the entire ledger, so its duration grows with history and has no
  bound worth guessing at. Under the five-second default a caller would give
  up while the work continued behind it, and a retry would stack a second
  walk on top of the first.
  """
  @spec verify_now(GenServer.server()) :: {:ok, map()} | {:error, Error.t()}
  def verify_now(server \\ __MODULE__), do: GenServer.call(server, :verify_now, :infinity)

  @spec status(GenServer.server()) :: status()
  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(opts) do
    store = Keyword.get(opts, :store, Config.default_store())

    checkpoint_store =
      Keyword.get(opts, :checkpoint_store) ||
        configured_checkpoint_store(store) ||
        raise ArgumentError,
              "Chronicle.Verifier requires :checkpoint_store on the child or named store"

    unless is_atom(checkpoint_store) and
             function_exported?(checkpoint_store, :load, 1) and
             function_exported?(checkpoint_store, :save, 2) do
      raise ArgumentError,
            ":checkpoint_store must implement Chronicle.CheckpointStore, got: #{inspect(checkpoint_store)}"
    end

    interval = Keyword.get(opts, :interval, @default_interval)

    unless interval == :manual or (is_integer(interval) and interval > 0) do
      raise ArgumentError, ":interval must be :manual or a positive number of milliseconds"
    end

    state = %{
      store: store,
      checkpoint_store: checkpoint_store,
      interval: interval,
      on_failure: Keyword.get(opts, :on_failure),
      verify_opts: Keyword.get(opts, :verify_options, []),
      last_result: :not_run,
      last_checked_at: nil,
      checkpoints: %{},
      timer: nil
    }

    if Keyword.get(opts, :verify_on_start, true) do
      send(self(), :verify)
      {:ok, state}
    else
      {:ok, schedule(state)}
    end
  end

  @impl true
  def handle_call(:verify_now, _from, state) do
    {result, state} = verify(state)
    {:reply, result, state}
  end

  def handle_call(:status, _from, state) do
    {:reply, Map.take(state, [:store, :last_result, :last_checked_at, :checkpoints]), state}
  end

  @impl true
  def handle_info(:verify, state) do
    {_result, state} = verify(%{state | timer: nil})
    {:noreply, schedule(state)}
  end

  defp verify(state) do
    started = System.monotonic_time()

    result =
      with {:ok, anchors} <- load_checkpoints(state),
           {:ok, checkpoints} <-
             Chronicle.verify_all(
               state.store,
               Keyword.put(state.verify_opts, :checkpoints, anchors)
             ),
           :ok <- save_checkpoints(state, checkpoints) do
        {:ok, checkpoints}
      else
        {:error, %Error{} = error} -> {:error, error}
        {:error, reason} -> {:error, Error.wrap(:verify, reason, store: state.store)}
      end

    duration =
      System.monotonic_time()
      |> Kernel.-(started)
      |> System.convert_time_unit(:native, :microsecond)

    checked_at = DateTime.utc_now()

    case result do
      {:ok, checkpoints} ->
        :telemetry.execute(
          [:chronicle, :verification, :success],
          %{duration_us: duration, ledger_count: map_size(checkpoints)},
          %{store: state.store, checkpoints: checkpoints}
        )

        {result,
         %{state | last_result: :ok, last_checked_at: checked_at, checkpoints: checkpoints}}

      {:error, error} ->
        :telemetry.execute(
          [:chronicle, :verification, :failure],
          %{duration_us: duration},
          %{store: state.store, error: error}
        )

        notify_failure(state.on_failure, error)
        {result, %{state | last_result: {:error, error}, last_checked_at: checked_at}}
    end
  end

  defp load_checkpoints(state) do
    case state.checkpoint_store.load(state.store) do
      {:ok, checkpoints} when is_map(checkpoints) -> {:ok, CheckpointStore.decode(checkpoints)}
      :not_found -> {:ok, %{}}
      {:error, reason} -> {:error, {:checkpoint_load_failed, reason}}
      other -> {:error, {:invalid_checkpoint_load_result, other}}
    end
  rescue
    exception -> {:error, {:checkpoint_load_failed, exception}}
  end

  defp save_checkpoints(state, checkpoints) do
    case state.checkpoint_store.save(state.store, checkpoints) do
      :ok -> :ok
      {:error, reason} -> {:error, {:checkpoint_save_failed, reason}}
      other -> {:error, {:invalid_checkpoint_save_result, other}}
    end
  rescue
    exception -> {:error, {:checkpoint_save_failed, exception}}
  end

  # Callbacks are application code and are rescued for a specific reason: a
  # crashing alerter would take the verifier down with it, losing both the
  # alert and every future run. The failure that most needs reporting is
  # exactly the one where the reporting path is also broken.
  defp notify_failure(nil, error) do
    Logger.error("audit verification failed: #{Exception.message(error)}")
  end

  defp notify_failure(function, error) when is_function(function, 1) do
    function.(error)
  rescue
    exception ->
      Logger.error("audit verification failure callback crashed: #{Exception.message(exception)}")
  end

  defp notify_failure({module, function, arguments}, error)
       when is_atom(module) and is_atom(function) and is_list(arguments) do
    apply(module, function, [error | arguments])
  rescue
    exception ->
      Logger.error("audit verification failure callback crashed: #{Exception.message(exception)}")
  end

  defp notify_failure(other, _error) do
    Logger.error("invalid audit verifier :on_failure callback: #{inspect(other)}")
  end

  defp schedule(%{interval: :manual} = state), do: state

  defp schedule(state) do
    if state.timer, do: Process.cancel_timer(state.timer)
    %{state | timer: Process.send_after(self(), :verify, state.interval)}
  end

  defp configured_checkpoint_store(store) do
    case Config.fetch_store(store) do
      {:ok, store_config} -> Keyword.get(store_config.options, :checkpoint_store)
      {:error, _reason} -> nil
    end
  end
end
