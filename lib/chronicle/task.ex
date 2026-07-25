defmodule Chronicle.Task do
  @moduledoc """
  `Task` helpers that propagate the current audit context and active group.

  Tasks started inside a group must be awaited before the group function
  returns. A task cannot append to a group after that group has closed.
  """

  alias Chronicle.Context

  @spec wrap((-> result)) :: (-> result) when result: term()
  def wrap(fun) when is_function(fun, 0) do
    context = Context.capture()
    fn -> Context.with(context, fun) end
  end

  @spec async((-> result)) :: Task.t() when result: term()
  def async(fun) when is_function(fun, 0), do: fun |> wrap() |> Task.async()

  @spec start((-> result)) :: {:ok, pid()} | {:error, term()} when result: term()
  def start(fun) when is_function(fun, 0), do: fun |> wrap() |> Task.start()

  @spec start_link((-> result)) :: {:ok, pid()} | {:error, term()} when result: term()
  def start_link(fun) when is_function(fun, 0), do: fun |> wrap() |> Task.start_link()

  @spec async_stream(Enumerable.t(), (term() -> term()), keyword()) :: Enumerable.t()
  def async_stream(enumerable, fun, opts \\ []) when is_function(fun, 1) and is_list(opts) do
    context = Context.capture()
    Task.async_stream(enumerable, &Context.with(context, fn -> fun.(&1) end), opts)
  end

  @spec async_stream(
          Supervisor.supervisor(),
          Enumerable.t(),
          (term() -> term()),
          keyword()
        ) :: Enumerable.t()
  def async_stream(supervisor, enumerable, fun, opts)
      when is_function(fun, 1) and is_list(opts) do
    context = Context.capture()

    Task.Supervisor.async_stream(
      supervisor,
      enumerable,
      &Context.with(context, fn -> fun.(&1) end),
      opts
    )
  end
end
