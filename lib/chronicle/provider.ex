defmodule Chronicle.Provider do
  @moduledoc """
  Behaviour implemented by audit storage providers.

  `write_group/3` must make the group and its events visible atomically whenever
  the underlying store supports transactions.

  A behaviour rather than a bare module because there are genuinely two
  implementations with different guarantees: the Ecto provider, which is
  transactional and signs everything, and the in-memory one, which exists for
  tests. Only the first is a place to keep an audit trail — the memory provider
  has no chain, no persistence, and nothing to verify.
  """

  alias Chronicle.{Event, Group}

  @type options :: keyword()
  @type result :: :ok | {:ok, term()} | {:error, term()}

  @callback write_event(Event.t(), options()) :: result()
  @callback write_group(Group.t(), [Event.t()], options()) :: result()

  @spec write_event(Event.t(), keyword()) :: result()
  def write_event(%Event{} = event, opts \\ []) do
    with {:ok, provider, provider_opts} <- resolve(opts) do
      invoke(provider, :write_event, [event, provider_opts])
    end
  end

  @spec write_group(Group.t(), [Event.t()], keyword()) :: result()
  def write_group(%Group{} = group, events, opts \\ []) when is_list(events) do
    with {:ok, provider, provider_opts} <- resolve(opts) do
      invoke(provider, :write_group, [group, events, provider_opts])
    end
  end

  @spec resolve(keyword()) :: {:ok, module(), keyword()} | {:error, term()}
  def resolve(opts) do
    case Chronicle.Config.provider(opts) do
      {:ok, module, provider_opts, _store} -> {:ok, module, provider_opts}
      {:error, reason} -> {:error, reason}
    end
  end

  defp invoke(provider, function, arguments) do
    unless Code.ensure_loaded?(provider) and
             function_exported?(provider, function, length(arguments)) do
      return_error = {:provider_missing_callback, provider, function}
      throw({__MODULE__, return_error})
    end

    case apply(provider, function, arguments) do
      :ok -> :ok
      {:ok, _value} = ok -> ok
      {:error, _reason} = error -> error
      other -> {:error, {:invalid_provider_return, provider, function, other}}
    end
  rescue
    exception ->
      {:error, {:provider_exception, exception, __STACKTRACE__}}
  catch
    {__MODULE__, reason} -> {:error, reason}
    kind, reason -> {:error, {:provider_throw, kind, reason}}
  end
end
