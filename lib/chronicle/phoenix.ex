if Code.ensure_loaded?(Plug.Conn) do
  defmodule Chronicle.Phoenix do
    @moduledoc """
    Builds audit context from a `Plug.Conn`.

    The default actor mapper records only a type and id; it never serializes the
    entire user struct. Use `:actor` or `:actor_mapper` for application-specific
    identity.

    Request provenance — method, path, remote IP, request id — is contextual
    data, so it lands under `metadata["http"]` rather than in a column nothing
    queries.
    """

    alias Chronicle.Context

    @spec context(Plug.Conn.t(), keyword()) :: map()
    def context(%Plug.Conn{} = conn, opts \\ []) do
      http = %{
        "method" => conn.method,
        "path" => conn.request_path,
        "remote_ip" => format_ip(conn.remote_ip),
        "request_id" => request_id(conn)
      }

      http =
        if Keyword.get(opts, :include_query_string, false) do
          Map.put(http, "query_string", empty_to_nil(conn.query_string))
        else
          http
        end

      metadata =
        case Keyword.get(opts, :metadata, %{}) do
          function when is_function(function, 1) -> function.(conn)
          map when is_map(map) -> map
        end

      %{
        actor: actor(conn, opts),
        tenant: tenant(conn, opts),
        correlation_id: Keyword.get(opts, :correlation_id, request_id(conn)),
        metadata: Map.put(metadata, "http", http)
      }
    end

    @spec put_context(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
    def put_context(%Plug.Conn{} = conn, opts \\ []) do
      Context.merge(context(conn, opts))
      conn
    end

    @doc """
    Runs a block with request audit context without leaking it to subsequent
    work in the same process.

    Takes a `do` block or a zero-arity function, like `Chronicle.transaction/3`:

        Chronicle.Phoenix.with_context conn do
          Accounts.disable(account)
        end
    """
    defmacro with_context(conn, opts \\ [], fun \\ nil) do
      {opts, fun} = Chronicle.__split_block__(opts, fun, "Chronicle.Phoenix.with_context")

      quote do
        Chronicle.Phoenix.__with_context__(unquote(conn), unquote(opts), unquote(fun))
      end
    end

    @doc false
    @spec __with_context__(Plug.Conn.t(), keyword(), (-> result)) :: result when result: term()
    def __with_context__(conn, opts, fun) when is_list(opts) and is_function(fun, 0) do
      merged = Map.merge(Context.get(), context(conn, opts))
      Context.with(merged, fun)
    end

    @doc """
    Runs one Phoenix request action as an audited group.

    Takes a `do` block or a zero-arity function. Option values for `:actor`,
    `:subject`, `:data`, and `:metadata` may be one-argument functions that
    receive the connection.
    """
    defmacro run(conn, type, opts \\ [], fun \\ nil) do
      {opts, fun} = Chronicle.__split_block__(opts, fun, "Chronicle.Phoenix.run")

      quote do
        Chronicle.Phoenix.__run__(unquote(conn), unquote(type), unquote(opts), unquote(fun))
      end
    end

    @doc false
    @spec __run__(Plug.Conn.t(), String.t(), keyword(), (-> result)) :: result
          when result: term()
    def __run__(%Plug.Conn{} = conn, type, opts, fun)
        when is_binary(type) and is_list(opts) and is_function(fun, 0) do
      opts = resolve_options(conn, opts)

      __with_context__(conn, opts, fn ->
        Chronicle.Scope.run(type, Keyword.put_new(opts, :classify, :http_status), fun)
      end)
    end

    defp actor(conn, opts) do
      case Keyword.get(opts, :actor) do
        function when is_function(function, 1) ->
          function.(conn)

        nil ->
          assign = Keyword.get(opts, :actor_assign, :current_user)
          mapper = Keyword.get(opts, :actor_mapper, &default_actor/1)
          mapper.(Map.get(conn.assigns, assign))

        actor ->
          actor
      end
    end

    defp default_actor(nil), do: nil

    defp default_actor(%{__struct__: module} = actor) do
      %{"type" => inspect(module), "id" => Map.get(actor, :id)}
    end

    defp default_actor(actor) when is_map(actor) do
      %{"type" => Map.get(actor, :type, "actor"), "id" => Map.get(actor, :id)}
    end

    defp default_actor(actor), do: %{"type" => "actor", "id" => to_string(actor)}

    defp tenant(conn, opts) do
      case Keyword.get(opts, :tenant) do
        function when is_function(function, 1) ->
          function.(conn)

        nil ->
          case Keyword.get(opts, :tenant_assign) do
            nil ->
              nil

            assign ->
              Keyword.get(opts, :tenant_mapper, &default_tenant/1).(Map.get(conn.assigns, assign))
          end

        tenant ->
          tenant
      end
    end

    defp default_tenant(nil), do: nil

    defp default_tenant(%{__struct__: module} = tenant) do
      %{"type" => inspect(module), "id" => Map.get(tenant, :id)}
    end

    defp default_tenant(tenant) when is_map(tenant) do
      %{"type" => Map.get(tenant, :type, "tenant"), "id" => Map.get(tenant, :id)}
    end

    defp default_tenant(tenant), do: %{"type" => "tenant", "id" => to_string(tenant)}

    defp request_id(conn) do
      case Plug.Conn.get_req_header(conn, "x-request-id") do
        [request_id | _] -> request_id
        [] -> Map.get(conn.assigns, :request_id)
      end
    end

    defp format_ip(nil), do: nil

    defp format_ip(ip) do
      ip |> :inet.ntoa() |> to_string()
    rescue
      ArgumentError -> inspect(ip)
    end

    defp empty_to_nil(""), do: nil
    defp empty_to_nil(value), do: value

    defp resolve_options(conn, opts) do
      Enum.map(opts, fn
        {key, function}
        when key in [:actor, :tenant, :subject, :data, :metadata] and is_function(function, 1) ->
          {key, function.(conn)}

        option ->
          option
      end)
    end
  end
end
