defmodule Chronicle.Oban do
  @moduledoc """
  Propagates audit context through Oban-compatible job arguments.

  This module deliberately has no Oban dependency. Use `attach/2` while
  building a job and `with_context/2` in `perform/1`.

      %{account_id: account.id}
      |> Chronicle.Oban.attach()
      |> MyWorker.new()
      |> Oban.insert()

      def perform(job) do
        Chronicle.Oban.with_context job do
          Chronicle.run "account.reconcile" do
            ...
          end
        end
      end

  Only context values are serialized. A live group is process-local and is
  never propagated through a durable job.
  """

  alias Chronicle.Context

  @context_key "_audit_context"

  def attach(value, opts \\ [])

  if Code.ensure_loaded?(Ecto.Changeset) do
    @spec attach(Ecto.Changeset.t(), keyword()) :: Ecto.Changeset.t()
    def attach(%Ecto.Changeset{} = changeset, opts) do
      args = Ecto.Changeset.get_field(changeset, :args) || %{}
      Ecto.Changeset.put_change(changeset, :args, attach(args, opts))
    end
  end

  @spec attach(map(), keyword()) :: map()
  def attach(args, opts) when is_map(args) and is_list(opts) do
    context =
      Context.get()
      |> Map.merge(opts |> Keyword.get(:context, %{}) |> Map.new())
      |> Chronicle.Value.normalize()

    Map.put(args, @context_key, context)
  end

  @doc """
  Restores serialized audit context for the duration of a block.

  Takes a `do` block or a zero-arity function, like `Chronicle.transaction/3`.
  """
  defmacro with_context(job_or_args, fun) do
    {rest, fun} = Chronicle.__split_block__(fun, nil, "Chronicle.Oban.with_context")

    unless rest == [] do
      raise ArgumentError,
            "Chronicle.Oban.with_context/2 takes no options, got: #{inspect(Keyword.keys(rest))}"
    end

    quote do
      Chronicle.Oban.__with_context__(unquote(job_or_args), unquote(fun))
    end
  end

  @doc false
  @spec __with_context__(map(), (-> result)) :: result when result: term()
  def __with_context__(job_or_args, fun) when is_map(job_or_args) and is_function(fun, 0) do
    args = Map.get(job_or_args, :args, Map.get(job_or_args, "args", job_or_args))
    context = Map.get(args, @context_key, Map.get(args, :_audit_context, %{}))
    Context.with(context, fun)
  end
end
