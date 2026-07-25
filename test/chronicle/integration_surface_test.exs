defmodule Chronicle.IntegrationSurfaceTest do
  @moduledoc """
  The Phoenix, Oban, checkpoint, and scope surfaces, including the failure
  paths an application only meets in production.
  """

  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.{CheckpointStore, Context, Phoenix, Scope, Test}
  alias Chronicle.Integrity.Checkpoint

  defmodule User do
    @moduledoc false
    defstruct [:id]
  end

  defp conn(opts \\ []) do
    :get
    |> Plug.Test.conn(Keyword.get(opts, :path, "/orders"))
    |> Map.put(:assigns, Keyword.get(opts, :assigns, %{}))
  end

  describe "Phoenix actor and tenant resolution" do
    test "defaults to the current_user assign and its module name" do
      context = Phoenix.context(conn(assigns: %{current_user: %User{id: 7}}))
      assert context.actor == %{"type" => inspect(User), "id" => 7}
    end

    test "an explicit actor wins over the assign" do
      context =
        Phoenix.context(conn(assigns: %{current_user: %User{id: 7}}),
          actor: Chronicle.actor("service", "batch")
        )

      assert context.actor == %{"type" => "service", "id" => "batch"}
    end

    test "a one-argument actor is called with the connection" do
      context =
        Phoenix.context(conn(path: "/x"),
          actor: fn c -> Chronicle.ref("path", c.request_path) end
        )

      assert context.actor == %{"type" => "path", "id" => "/x"}
    end

    test "a custom mapper receives the assign" do
      context =
        Phoenix.context(conn(assigns: %{me: %{id: 9}}),
          actor_assign: :me,
          actor_mapper: fn user -> Chronicle.actor("user", user.id) end
        )

      assert context.actor == %{"type" => "user", "id" => 9}
    end

    test "no actor assign yields no actor" do
      assert Phoenix.context(conn()).actor == nil
    end

    test "tenant resolves from an assign, a function, or an explicit value" do
      assert Phoenix.context(conn(), tenant: Chronicle.ref("org", "o-1")).tenant ==
               %{"type" => "org", "id" => "o-1"}

      assert Phoenix.context(conn(assigns: %{org: %{id: 3}}), tenant_assign: :org).tenant ==
               %{"type" => "tenant", "id" => 3}

      assert Phoenix.context(conn(), tenant: fn _c -> Chronicle.ref("org", "fn") end).tenant ==
               %{"type" => "org", "id" => "fn"}

      assert Phoenix.context(conn()).tenant == nil
    end

    test "a struct tenant falls back to its module name" do
      assert Phoenix.context(conn(assigns: %{org: %User{id: 1}}), tenant_assign: :org).tenant ==
               %{"type" => inspect(User), "id" => 1}
    end

    test "metadata may be a map or a function of the connection" do
      assert Phoenix.context(conn(), metadata: %{"a" => 1}).metadata["a"] == 1

      assert Phoenix.context(conn(), metadata: fn c -> %{"m" => c.method} end).metadata["m"] ==
               "GET"
    end

    test "records request provenance under metadata" do
      http = Phoenix.context(conn(path: "/orders")).metadata["http"]

      assert http["method"] == "GET"
      assert http["path"] == "/orders"
      assert http["remote_ip"] == "127.0.0.1"
      refute Map.has_key?(http, "query_string")
    end

    test "falls back to the request_id assign when there is no header" do
      given = %{conn() | assigns: %{request_id: "assigned"}}
      assert Phoenix.context(given).correlation_id == "assigned"
    end

    test "an explicit correlation id wins over the request id" do
      assert Phoenix.context(conn(), correlation_id: "explicit").correlation_id == "explicit"
    end

    test "an x-request-id header is used as the correlation id" do
      given = Plug.Conn.put_req_header(conn(), "x-request-id", "from-header")
      assert Phoenix.context(given).correlation_id == "from-header"
    end

    test "records the query string only when asked" do
      given = Plug.Test.conn(:get, "/orders?token=secret")

      refute Phoenix.context(given).metadata["http"]["query_string"]

      assert Phoenix.context(given, include_query_string: true).metadata["http"]["query_string"] ==
               "token=secret"

      empty = Plug.Test.conn(:get, "/orders")

      assert Phoenix.context(empty, include_query_string: true).metadata["http"]["query_string"] ==
               nil
    end

    test "handles a connection with no remote address" do
      given = %{conn() | remote_ip: nil}
      assert Phoenix.context(given).metadata["http"]["remote_ip"] == nil
    end

    test "a non-map actor value is still given a stable reference" do
      context = Phoenix.context(conn(assigns: %{current_user: "u-1"}))
      assert context.actor == %{"type" => "actor", "id" => "u-1"}
    end

    test "a map actor without a type gets the default" do
      context = Phoenix.context(conn(assigns: %{current_user: %{id: 3}}))
      assert context.actor == %{"type" => "actor", "id" => 3}
    end

    test "run/4 audits a request action as a group classified by status" do
      {result, entries} =
        Test.capture(fn opts ->
          Phoenix.run(conn(), "admin.action", opts, fn -> %{status: 200} end)
        end)

      assert result == %{status: 200}
      assert [{:group, group, _}] = entries
      assert group.type == "admin.action"
      assert group.outcome == :success
    end

    test "run/4 records a failure for an error status" do
      {_result, entries} =
        Test.capture(fn opts ->
          Phoenix.run(conn(), "admin.action", opts, fn -> %{status: 500} end)
        end)

      assert [{:group, %{outcome: :failure}, _}] = entries
    end

    test "run/4 resolves function options against the connection" do
      {_result, entries} =
        Test.capture(fn opts ->
          Phoenix.run(
            conn(),
            "admin.action",
            opts ++ [subject: fn c -> Chronicle.ref("path", c.request_path) end],
            fn -> %{status: 200} end
          )
        end)

      assert [{:group, group, _}] = entries
      assert group.subject == %{"type" => "path", "id" => "/orders"}
    end

    test "put_context/2 merges into the process and returns the connection" do
      given = conn()
      assert ^given = Phoenix.put_context(given)
      assert Context.get().metadata["http"]["path"] == "/orders"
    end
  end

  describe "Oban context" do
    test "round-trips through serializable job args" do
      args =
        Context.with(%{actor: Chronicle.actor("service", "sched"), correlation_id: "c-1"}, fn ->
          Chronicle.Oban.attach(%{account_id: "a-1"})
        end)

      # attach/2 leaves the caller's args untouched; only the context is added.
      assert args[:account_id] == "a-1"

      restored = Chronicle.Oban.with_context(%{args: args}, fn -> Context.get() end)
      assert restored.actor == %{"type" => "service", "id" => "sched"}
      assert restored.correlation_id == "c-1"
    end

    test "accepts a bare args map and string-keyed args" do
      args = Context.with(%{correlation_id: "c-2"}, fn -> Chronicle.Oban.attach(%{}) end)

      assert Chronicle.Oban.with_context(args, fn -> Context.get().correlation_id end) == "c-2"

      assert Chronicle.Oban.with_context(%{"args" => args}, fn -> Context.get().correlation_id end) ==
               "c-2"
    end

    test "extra context can be supplied at attach time" do
      args = Chronicle.Oban.attach(%{}, context: %{correlation_id: "explicit"})

      assert Chronicle.Oban.with_context(args, fn -> Context.get().correlation_id end) ==
               "explicit"
    end

    test "a job with no attached context runs with an empty one" do
      assert Chronicle.Oban.with_context(%{args: %{"x" => 1}}, fn -> Context.get() end) == %{}
    end

    test "protects sensitive context values on the way into durable job args" do
      args =
        Context.with(%{metadata: %{"api_token" => "secret"}}, fn -> Chronicle.Oban.attach(%{}) end)

      assert args["_audit_context"]["metadata"]["api_token"] == "[REDACTED]"
    end
  end

  describe "CheckpointStore encoding" do
    test "round-trips a checkpoint" do
      checkpoint = %Checkpoint{ledger: "primary", sequence: 3, digest: String.duplicate("a", 64)}

      assert %{"primary" => decoded} =
               CheckpointStore.decode(CheckpointStore.encode(%{"primary" => checkpoint}))

      assert decoded == checkpoint
    end

    test "accepts an empty ledger at sequence zero" do
      assert %{"primary" => %Checkpoint{sequence: 0, digest: nil}} =
               CheckpointStore.decode(%{
                 "primary" => %{ledger: "primary", sequence: 0, digest: nil}
               })
    end

    test "refuses a checkpoint whose ledger does not match its key" do
      assert_raise ArgumentError, ~r/does not match key/, fn ->
        CheckpointStore.decode(%{"primary" => %{ledger: "other", sequence: 0, digest: nil}})
      end
    end

    test "refuses a malformed sequence or digest" do
      base = %{ledger: "primary", sequence: 1, digest: String.duplicate("a", 64)}

      assert_raise ArgumentError, ~r/invalid checkpoint sequence/, fn ->
        CheckpointStore.decode(%{"primary" => %{base | sequence: -1}})
      end

      assert_raise ArgumentError, ~r/invalid checkpoint digest/, fn ->
        CheckpointStore.decode(%{"primary" => %{base | digest: "not-a-digest"}})
      end

      assert_raise ArgumentError, ~r/invalid checkpoint digest/, fn ->
        CheckpointStore.decode(%{"primary" => %{base | digest: nil}})
      end
    end

    test "refuses an unusable ledger name" do
      assert_raise ArgumentError, ~r/invalid checkpoint ledger/, fn ->
        CheckpointStore.decode(%{1 => %{ledger: 1, sequence: 0, digest: nil}})
      end
    end
  end

  describe "scope failure paths" do
    test "a span records a failure and re-raises the original exception" do
      {_result, entries} =
        Test.capture(fn opts ->
          assert_raise RuntimeError, "boom", fn ->
            Scope.span("op", opts, fn -> raise "boom" end)
          end
        end)

      assert [%{type: "op", outcome: :failure} = event] = Test.events(entries)
      assert event.error["type"] == "RuntimeError"
      assert event.error["message"] =~ "boom"
    end

    test "a span records a failure for a throw and re-raises it" do
      {_result, entries} =
        Test.capture(fn opts ->
          catch_throw(Scope.span("op", opts, fn -> throw(:nope) end))
        end)

      assert [%{outcome: :failure, error: %{"kind" => "throw"}}] = Test.events(entries)
    end

    test "a group records a failure and keeps the events buffered before it" do
      {_result, entries} =
        Test.capture(fn opts ->
          assert_raise RuntimeError, fn ->
            Scope.group("unit", opts, fn ->
              Chronicle.record!("step.one", %{}, opts)
              raise "boom"
            end)
          end
        end)

      assert [{:group, group, events}] = entries
      assert group.outcome == :failure
      assert group.error["type"] == "RuntimeError"
      assert Enum.map(events, & &1.type) == ["step.one"]
    end

    test "groups cannot nest, because a group is one signed unit" do
      Test.capture(fn opts ->
        assert_raise ArgumentError, ~r/cannot be nested/, fn ->
          Scope.group("outer", opts, fn -> Scope.group("inner", opts, fn -> :ok end) end)
        end
      end)
    end

    test "an event raised after its group closed is refused, not silently dropped" do
      {buffer, opts} =
        Test.capture(fn opts ->
          Scope.group("unit", opts, fn -> {Context.current_group(), opts} end)
        end)
        |> elem(0)

      assert {:error, %Chronicle.Error{}} =
               Context.with_group(buffer, fn -> Chronicle.record("late.event", %{}, opts) end)
    end
  end

  describe "Chronicle.Test helpers" do
    test "separate events from groups" do
      {_result, entries} =
        Test.capture(fn opts ->
          Chronicle.record!("standalone", %{}, opts)
          Scope.group("unit", opts, fn -> Chronicle.record!("child", %{}, opts) end)
        end)

      assert Enum.map(Test.events(entries), & &1.type) == ["standalone", "child"]
      assert Enum.map(Test.groups(entries), & &1.type) == ["unit"]

      assert Test.event?(entries, "standalone")
      assert Test.event?(entries, "child", &(&1.sequence == 1))
      refute Test.event?(entries, "missing")

      assert Test.group?(entries, "unit")
      assert Test.group?(entries, "unit", &(&1.event_count == 1))
      refute Test.group?(entries, "missing")
    end
  end
end
