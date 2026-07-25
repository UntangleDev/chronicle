defmodule Chronicle.RedactionTest do
  use ExUnit.Case, async: false

  alias Chronicle.Provider.Memory

  setup do
    previous = Application.get_env(:chronicle, :redaction, :__missing__)

    on_exit(fn ->
      case previous do
        :__missing__ -> Application.delete_env(:chronicle, :redaction)
        value -> Application.put_env(:chronicle, :redaction, value)
      end
    end)

    {:ok, server} = Memory.start_link()
    %{opts: [provider: {Memory, server: server}]}
  end

  describe "built-in protection" do
    test "covers credential-shaped names, not just exact matches" do
      for name <- ~w(
            password password_hash password_confirmation current_password
            token secret_token api_token access_token refresh_token session_token
            secret client_secret otp_secret aws_secret_access_key
            api_key access_key encryption_key signing_key
            ssn social_security_number card_number credit_card account_number
            routing_number cvv cvc iban pin pin_code salt jwt
          ) do
        assert Chronicle.Redaction.builtin?(name), "expected #{name} to be protected"
      end
    end

    test "leaves ordinary field names alone" do
      for name <- ~w(key_id sort_key partition_key monkey keyboard description
                     title body email name status inserted_at pinned_at) do
        refute Chronicle.Redaction.builtin?(name), "expected #{name} to be untouched"
      end
    end

    test "applies recursively to nested event data", %{opts: opts} do
      {:ok, event} =
        Chronicle.record(
          "integration.called",
          %{request: %{headers: %{authorization: "Bearer abc"}, api_token: "t"}},
          opts
        )

      assert %{
               "request" => %{
                 "headers" => %{"authorization" => "[REDACTED]"},
                 "api_token" => "[REDACTED]"
               }
             } = event.data
    end
  end

  describe "configuration" do
    test "configured fields extend rather than replace the built-in list", %{opts: opts} do
      Application.put_env(:chronicle, :redaction, fields: [:internal_note])

      {:ok, event} =
        Chronicle.record("x", %{password: "p", internal_note: "n", title: "t"}, opts)

      assert event.data == %{
               "password" => "[REDACTED]",
               "internal_note" => "[REDACTED]",
               "title" => "t"
             }
    end

    test "builtin: false hands the policy entirely to the application", %{opts: opts} do
      Application.put_env(:chronicle, :redaction, builtin: false, fields: [:internal_note])

      {:ok, event} = Chronicle.record("x", %{password: "p", internal_note: "n"}, opts)

      assert event.data == %{"password" => "p", "internal_note" => "[REDACTED]"}
    end

    test "hash and omit strategies apply by name", %{opts: opts} do
      Application.put_env(:chronicle, :redaction, hash_fields: [:email], omit_fields: [:blob])

      {:ok, event} = Chronicle.record("x", %{email: "a@b.c", blob: "big", title: "t"}, opts)

      assert %{"email" => "sha256:" <> _, "title" => "t"} = event.data
      refute Map.has_key?(event.data, "blob")
    end
  end
end
