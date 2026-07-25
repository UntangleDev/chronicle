defmodule Chronicle.ApiContractTest do
  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.Provider.Memory

  setup do
    {:ok, server} = Memory.start_link()
    %{opts: [provider: {Memory, server: server}], server: server}
  end

  describe "option validation" do
    test "a keyword list passed where data belongs is reported, not dropped" do
      assert_raise ArgumentError, ~r/unknown option\(s\) \[:user_id, :amount\]/, fn ->
        Chronicle.record("thing.happened", user_id: 7, amount: 100)
      end
    end

    test "the message points at the correct call shape" do
      error =
        assert_raise ArgumentError, fn -> Chronicle.record("x", nonsense: true) end

      assert Exception.message(error) =~ "Audit data must be a map"
    end

    test "known options still pass through", %{opts: opts} do
      assert {:ok, event} =
               Chronicle.record("x", %{a: 1}, opts ++ [correlation_id: "abc"])

      assert event.correlation_id == "abc"
    end
  end

  describe "default outcome classification" do
    test "an error tuple is recorded as a failure" do
      {_result, entries} =
        Chronicle.Test.capture(fn opts ->
          Chronicle.Scope.span("op", opts, fn -> {:error, :nope} end)
        end)

      assert [{"op", :failure}] =
               entries |> Chronicle.Test.events() |> Enum.map(&{&1.type, &1.outcome})
    end

    test "a bare :error is recorded as a failure" do
      {_result, entries} =
        Chronicle.Test.capture(fn opts ->
          Chronicle.Scope.span("op", opts, fn -> :error end)
        end)

      assert [{"op", :failure}] =
               entries |> Chronicle.Test.events() |> Enum.map(&{&1.type, &1.outcome})
    end

    test "an ordinary return value is still a success" do
      {_result, entries} =
        Chronicle.Test.capture(fn opts ->
          Chronicle.Scope.span("op", opts, fn -> %{id: 1} end)
        end)

      assert [{"op", :success}] =
               entries |> Chronicle.Test.events() |> Enum.map(&{&1.type, &1.outcome})
    end
  end

  describe "block syntax" do
    test "span accepts a do block", %{opts: opts} do
      assert {:ok, :charged} = Chronicle.span("payment.authorize", opts, do: {:ok, :charged})
    end

    test "span accepts a do block without options" do
      {result, entries} =
        Chronicle.Test.capture(fn opts ->
          Chronicle.span "noop", opts do
            :fine
          end
        end)

      assert result == :fine
      assert Chronicle.Test.event?(entries, "noop")
    end

    test "span still accepts an explicit function", %{opts: opts} do
      assert :done = Chronicle.span("op", opts, fn -> :done end)
    end

    test "run and group take a block like their siblings", %{opts: opts} do
      assert :block = Chronicle.run("unit", opts, do: :block)
      assert :fun = Chronicle.run("unit", opts, fn -> :fun end)
      assert :block = Chronicle.group("unit", opts, do: :block)
      assert :fun = Chronicle.group("unit", opts, fn -> :fun end)
    end

    test "Phoenix.with_context takes a block, a block with options, or a function" do
      conn =
        :post
        |> Plug.Test.conn("/orders?token=secret")
        |> Plug.Conn.put_req_header("x-request-id", "req-1")

      assert %{correlation_id: "req-1"} =
               Chronicle.Phoenix.with_context(conn, do: Chronicle.Context.get())

      assert %{correlation_id: "req-1"} =
               Chronicle.Phoenix.with_context(conn, [], fn -> Chronicle.Context.get() end)

      assert %{metadata: %{"http" => %{"query_string" => "token=secret"}}} =
               Chronicle.Phoenix.with_context(conn, [include_query_string: true],
                 do: Chronicle.Context.get()
               )

      # The block form must still restore the previous context.
      assert Chronicle.Context.get() == %{}
    end

    test "Oban.with_context takes a block or a function" do
      args =
        Chronicle.Context.with(%{actor: Chronicle.actor("service", "sched")}, fn ->
          Chronicle.Oban.attach(%{account_id: "a-1"})
        end)

      job = %{args: args}
      expected = %{"id" => "sched", "type" => "service"}

      assert %{actor: ^expected} = Chronicle.Oban.with_context(job, do: Chronicle.Context.get())

      assert %{actor: ^expected} =
               Chronicle.Oban.with_context(job, fn -> Chronicle.Context.get() end)
    end
  end

  describe "reference identity" do
    setup %{opts: opts} do
      %{composite: %{"type" => "org", "id" => %{"region" => "eu", "org" => "org-1"}}, opts: opts}
    end

    test "a composite identifier resolves to a stable, prefixed digest", %{composite: composite} do
      digest = Chronicle.Reference.id(composite)

      assert "sha256:" <> _ = digest
      assert digest == Chronicle.Reference.id(composite)

      # Key order must not change identity.
      reordered = %{"type" => "org", "id" => %{"org" => "org-1", "region" => "eu"}}
      assert Chronicle.Reference.id(reordered) == digest
    end

    test "a scalar identifier is stored as itself" do
      assert Chronicle.Reference.id(Chronicle.ref("org", "org-1")) == "org-1"
      assert Chronicle.Reference.id(Chronicle.ref("org", 42)) == "42"
    end

    test "type is unchanged by identifier shape", %{composite: composite} do
      assert Chronicle.Reference.type(composite) == "org"
      assert Chronicle.Reference.type(Chronicle.ref("org", "org-1")) == "org"
      assert Chronicle.Reference.type(nil) == nil
      assert Chronicle.Reference.id(nil) == nil
    end

    test "distinct references do not collide", %{composite: composite} do
      other = %{"type" => "org", "id" => %{"region" => "us", "org" => "org-1"}}
      assert Chronicle.Reference.id(other) != Chronicle.Reference.id(composite)

      # Type participates in identity.
      assert Chronicle.Reference.id(%{composite | "type" => "team"}) !=
               Chronicle.Reference.id(composite)
    end

    test "a composite identifier resolves to its digest on every reference", %{
      composite: composite,
      opts: opts
    } do
      digest = Chronicle.Reference.id(composite)

      for key <- [:actor, :tenant, :subject] do
        assert {:ok, event} = Chronicle.record("x", %{}, [{key, composite} | opts])

        # A reference is a type and an id, nothing else, and it is what gets
        # stored — the struct cannot disagree with the row.
        assert Map.fetch!(event, key) == %{"type" => "org", "id" => digest}
      end
    end
  end

  describe "structured errors" do
    test "an unknown store is reported as configuration, not a generic failure" do
      assert {:error, %Chronicle.Error{reason: :store_not_configured}} =
               Chronicle.record("x", %{}, store: :does_not_exist)
    end

    test "lifecycle calls on a non-Ecto store name the actual problem", %{server: server} do
      previous = Application.get_env(:chronicle, :stores, :__missing__)

      Application.put_env(:chronicle, :stores, memory_only: [provider: Memory, server: server])

      on_exit(fn ->
        case previous do
          :__missing__ -> Application.delete_env(:chronicle, :stores)
          value -> Application.put_env(:chronicle, :stores, value)
        end
      end)

      assert {:error, %Chronicle.Error{reason: :ecto_store_required} = error} =
               Chronicle.verify(:memory_only)

      assert error.store == :memory_only
      refute match?(%KeyError{}, error.cause)

      assert {:error, %Chronicle.Error{reason: :ecto_store_required}} =
               Chronicle.checkpoint(:memory_only)
    end
  end
end
