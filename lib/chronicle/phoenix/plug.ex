if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule Chronicle.Phoenix.Plug do
    @moduledoc """
    Adds request, actor, and correlation information to `Chronicle.Context`.

    Add it after authentication if `:actor_assign` should resolve a user:

        plug Chronicle.Phoenix.Plug,
          actor_assign: :current_user,
          actor_mapper: &MyApp.Chronicle.actor/1

    Phoenix handles each request in its own process, so the context naturally
    ends with the request process.
    """

    @behaviour Plug

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts), do: Chronicle.Phoenix.put_context(conn, opts)
  end
end
