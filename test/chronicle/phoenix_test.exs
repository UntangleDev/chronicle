defmodule Chronicle.PhoenixTest do
  use ExUnit.Case, async: true

  use Chronicle

  import Plug.Conn
  import Plug.Test

  alias Chronicle.{Context, Phoenix}
  alias Chronicle.Provider.Memory

  setup do
    {:ok, store} = start_supervised(Memory)
    on_exit(fn -> Context.put(%{}) end)
    %{store: store}
  end

  test "plug attributes later events to the request and actor", %{store: store} do
    conn =
      :get
      |> conn("/admin/users?state=locked")
      |> put_req_header("x-request-id", "req-123")
      |> assign(:current_user, %{id: "user-7", role: "admin"})
      |> Phoenix.Plug.call(Phoenix.Plug.init(include_query_string: true))

    assert conn.method == "GET"

    assert {:ok, event} =
             Chronicle.record("admin.user_listed", %{}, provider: {Memory, server: store})

    assert event.actor == %{"type" => "actor", "id" => "user-7"}
    assert event.metadata["http"] != nil
    assert event.metadata["http"]["method"] == "GET"
    assert event.metadata["http"]["path"] == "/admin/users"
    assert event.metadata["http"]["query_string"] == "state=locked"
    assert event.correlation_id == "req-123"
  end

  test "with_context restores an existing context" do
    Context.put(actor: %{id: "system"})
    conn = conn(:post, "/orders?token=must-not-be-audited")

    Phoenix.with_context(conn, fn ->
      assert Context.get().metadata["http"]["path"] == "/orders"
      refute Map.has_key?(Context.get().metadata["http"], "query_string")
    end)

    assert Context.get() == %{actor: %{id: "system"}}
  end
end
