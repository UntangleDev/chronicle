defmodule Chronicle.ErgonomicsTest do
  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.Provider.Memory

  defmodule Principal do
    defstruct [:id, :email]
  end

  defimpl Chronicle.Identity, for: Principal do
    def audit_identity(principal), do: %{type: "principal", id: principal.id}
  end

  setup do
    saved =
      for key <- [:provider, :stores, :default_store, :redaction], into: %{} do
        {key, Application.get_env(:chronicle, key, :__missing__)}
      end

    on_exit(fn ->
      Enum.each(saved, fn
        {key, :__missing__} -> Application.delete_env(:chronicle, key)
        {key, value} -> Application.put_env(:chronicle, key, value)
      end)

      Chronicle.Context.put(%{})
    end)

    :ok
  end

  test "named stores select a destination and default without call-site provider plumbing" do
    {:ok, primary} = start_supervised({Memory, name: :ergonomic_primary})
    {:ok, security} = start_supervised({Memory, name: :ergonomic_security})

    Application.put_env(:chronicle, :default_store, :primary)

    Application.put_env(
      :chronicle,
      :stores,
      primary: [provider: {Memory, server: primary}],
      security: [provider: {Memory, server: security}]
    )

    assert {:ok, primary_event} = Chronicle.record("account.viewed")
    assert {:ok, security_event} = Chronicle.record("access.denied", store: :security)

    assert [{:event, ^primary_event}] = Memory.entries(primary)
    assert [{:event, ^security_event}] = Memory.entries(security)
  end

  test "run establishes identity context and commits one semantic group" do
    {:ok, store} = start_supervised(Memory)
    principal = %Principal{id: "p-7", email: "not-serialized@example.test"}

    assert {:ok, :updated} =
             Chronicle.run(
               "account.email_change",
               [
                 provider: {Memory, server: store},
                 actor: principal,
                 subject: Chronicle.ref("account", "a-1"),
                 data: %{request: "self-service"},
                 classify: :result_tuple
               ],
               fn ->
                 Chronicle.record!("authorization.allowed", %{policy: "owner"})
                 {:ok, :updated}
               end
             )

    assert [{:group, group, [event]}] = Memory.entries(store)
    assert group.outcome == :success
    assert group.actor == %{"id" => "p-7", "type" => "principal"}
    assert group.subject == %{"id" => "a-1", "type" => "account"}
    assert group.data == %{"request" => "self-service"}
    assert event.actor == group.actor
    refute Map.has_key?(event.actor, "email")
  end

  test "built-in classifiers make result conventions explicit" do
    {:ok, store} = start_supervised(Memory)
    opts = [provider: {Memory, server: store}]

    assert {:error, :declined} =
             Chronicle.span("payment", opts ++ [classify: :result_tuple], fn ->
               {:error, :declined}
             end)

    assert false == Chronicle.span("policy", opts ++ [classify: :boolean], fn -> false end)

    assert %{status: 503} =
             Chronicle.span("request", opts ++ [classify: :http_status], fn -> %{status: 503} end)

    assert Enum.map(Memory.entries(store), fn {:event, event} -> event.outcome end) ==
             [:failure, :failure, :failure]
  end

  test "central redaction supports redact, hash, omit, and explicit markers" do
    {:ok, store} = start_supervised(Memory)

    Application.put_env(
      :chronicle,
      :redaction,
      fields: [:credential],
      hash_fields: [:email],
      omit_fields: [:raw_payload]
    )

    assert {:ok, event} =
             Chronicle.record(
               "profile.changed",
               %{
                 credential: "secret",
                 email: "person@example.test",
                 raw_payload: "discard",
                 explicit: Chronicle.secret("hidden"),
                 fingerprint: Chronicle.hash("stable"),
                 nested: %{discard: Chronicle.omit(), keep: true}
               },
               provider: {Memory, server: store}
             )

    assert event.data["credential"] == "[REDACTED]"
    assert event.data["explicit"] == "[REDACTED]"
    assert event.data["email"] =~ ~r/^sha256:[0-9a-f]{64}$/
    assert event.data["fingerprint"] =~ ~r/^sha256:[0-9a-f]{64}$/
    refute Map.has_key?(event.data, "raw_payload")
    assert event.data["nested"] == %{"keep" => true}
  end

  test "Chronicle.Task propagates context and an active group" do
    {:ok, store} = start_supervised(Memory)

    Chronicle.run(
      "bulk.review",
      [provider: {Memory, server: store}, actor: Chronicle.actor("service", "reviewer")],
      fn ->
        task = Chronicle.Task.async(fn -> Chronicle.record!("account.reviewed") end)
        assert %Chronicle.Event{} = Task.await(task)
      end
    )

    assert [{:group, group, [event]}] = Memory.entries(store)
    assert event.group_id == group.id
    assert event.actor == %{"id" => "reviewer", "type" => "service"}
  end

  test "Oban helpers persist serializable context and restore the worker context" do
    Chronicle.Context.put(actor: Chronicle.actor("service", "scheduler"), correlation_id: "job-1")
    args = Chronicle.Oban.attach(%{"account_id" => "a-1"})

    assert args["_audit_context"]["actor"] == %{"id" => "scheduler", "type" => "service"}
    assert args["_audit_context"]["correlation_id"] == "job-1"

    Chronicle.Context.put(actor: Chronicle.actor("service", "worker"))

    Chronicle.Oban.with_context(%{args: args}, fn ->
      assert Chronicle.Context.get().actor == %{"id" => "scheduler", "type" => "service"}
    end)

    assert Chronicle.Context.get().actor == %{"id" => "worker", "type" => "service"}
  end

  test "external checkpoint decoding rejects malformed anchors instead of weakening them" do
    assert_raise ArgumentError, ~r/checkpoint ledger/, fn ->
      Chronicle.CheckpointStore.decode(%{
        "primary" => %{
          "ledger" => "different",
          "sequence" => 1,
          "digest" => String.duplicate("a", 64)
        }
      })
    end

    assert_raise ArgumentError, ~r/checkpoint digest/, fn ->
      Chronicle.CheckpointStore.decode(%{
        "primary" => %{"ledger" => "primary", "sequence" => 1, "digest" => nil}
      })
    end
  end
end
