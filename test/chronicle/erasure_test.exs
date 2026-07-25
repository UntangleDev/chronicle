defmodule Chronicle.ErasureTest do
  use ExUnit.Case, async: false

  alias Chronicle.Test.Databases

  defmodule MemoryKeys do
    @moduledoc false
    @behaviour Chronicle.ErasureKeyring

    @impl true
    def fetch(key_id, opts) do
      case Agent.get(Keyword.fetch!(opts, :agent), &Map.fetch(&1, key_id)) do
        {:ok, key} -> {:ok, key}
        :error -> {:error, :not_found}
      end
    end

    @impl true
    def destroy(key_id, opts) do
      Agent.get_and_update(Keyword.fetch!(opts, :agent), fn keys ->
        case Map.pop(keys, key_id) do
          {nil, unchanged} -> {{:error, :not_found}, unchanged}
          {_key, remaining} -> {:ok, remaining}
        end
      end)
    end
  end

  defmodule RaisingKeys do
    @moduledoc false
    @behaviour Chronicle.ErasureKeyring

    @impl true
    def fetch(_key_id, _opts), do: raise("provider response contained SECRET-PROBE")

    @impl true
    def destroy(_key_id, _opts), do: raise("provider response contained SECRET-PROBE")
  end

  defmodule MissingCallbacks do
    @moduledoc false
  end

  defmodule InvalidResults do
    @moduledoc false
    @behaviour Chronicle.ErasureKeyring

    @impl true
    def fetch(_key_id, _opts), do: :invalid

    @impl true
    def destroy(_key_id, _opts), do: :invalid
  end

  defmodule InvalidKey do
    @moduledoc false
    @behaviour Chronicle.ErasureKeyring

    @impl true
    def fetch(_key_id, _opts), do: {:ok, "short"}

    @impl true
    def destroy(_key_id, _opts), do: {:error, :provider_refused}
  end

  defmodule Account do
    use Ecto.Schema
    use Chronicle.Schema, erasable: [email: :privacy_key_id]

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "erasure_accounts" do
      field :email, :string
      field :privacy_key_id, :string
    end
  end

  setup do
    previous = Application.get_env(:chronicle, :erasure, :__missing__)
    {:ok, keys} = start_supervised({Agent, fn -> %{"subject-1" => random_key()} end})
    Application.put_env(:chronicle, :erasure, keyring: {MemoryKeys, agent: keys})

    on_exit(fn ->
      case previous do
        :__missing__ -> Application.delete_env(:chronicle, :erasure)
        value -> Application.put_env(:chronicle, :erasure, value)
      end
    end)

    %{keys: keys}
  end

  test "an erasable marker stores authenticated ciphertext and remains decryptable" do
    normalized =
      Chronicle.Value.normalize(%{email: Chronicle.erasable("person@example.test", "subject-1")})

    envelope = normalized["email"]

    assert Chronicle.Erasure.envelope?(envelope)
    refute inspect(envelope) =~ "person@example.test"
    assert {:ok, "person@example.test"} = Chronicle.Erasure.decrypt(envelope)

    ciphertext =
      envelope["ciphertext"]
      |> Base.url_decode64!(padding: false)
      |> then(fn <<first, rest::binary>> -> <<Bitwise.bxor(first, 1), rest::binary>> end)
      |> Base.url_encode64(padding: false)

    assert {:error, :erasable_value_authentication_failed} =
             envelope
             |> Map.put("ciphertext", ciphertext)
             |> Chronicle.Erasure.decrypt()
  end

  test "destroying a data key removes plaintext access but not ledger verification" do
    signing_key = random_key()
    integrity_opts = [ledger: "primary", key_id: "signing", key: signing_key]

    payload =
      Chronicle.Value.normalize(%{
        subject: "opaque-reference",
        email: Chronicle.erasable("person@example.test", "subject-1")
      })

    assert {:ok, entry} =
             Chronicle.Integrity.build(:event, "event-1", payload, 1, nil, integrity_opts)

    assert :ok = Chronicle.Integrity.verify_entry(entry, payload, nil, 1, integrity_opts)
    assert :ok = Chronicle.Erasure.destroy("subject-1")

    assert {:error, {:erasure_key_unavailable, "subject-1"}} =
             Chronicle.Erasure.decrypt(payload["email"])

    assert :ok = Chronicle.Integrity.verify_entry(entry, payload, nil, 1, integrity_opts)
  end

  test "Ecto history reconstructs while the key exists and fails closed after destruction" do
    {repo, prefix} = Databases.start!(:sqlite)
    Databases.configure!(repo, prefix)

    Databases.create_table!(
      repo,
      prefix,
      "erasure_accounts",
      "id TEXT PRIMARY KEY, email TEXT, privacy_key_id TEXT"
    )

    assert {:ok, account} =
             %Account{}
             |> Ecto.Changeset.change(
               email: "person@example.test",
               privacy_key_id: "subject-1"
             )
             |> Chronicle.insert()

    assert {:ok, [before_erasure]} = Chronicle.history(account)
    assert before_erasure.restorable?
    assert before_erasure.record.email == "person@example.test"

    snapshot = Chronicle.Version.snapshot(before_erasure)
    assert Chronicle.Erasure.envelope?(snapshot["fields"]["email"])
    refute inspect(before_erasure.event.data) =~ "person@example.test"

    assert :ok = Chronicle.Erasure.destroy("subject-1")
    assert {:ok, [after_erasure]} = Chronicle.history(account)
    refute after_erasure.restorable?

    assert after_erasure.reconstruction_error == {:erasure_key_unavailable, "subject-1"}

    assert {:error, %Chronicle.Error{reason: :erasure_key_unavailable}} =
             Chronicle.at(account, version: 1)

    assert {:error, %Chronicle.Error{reason: :erasure_key_unavailable}} =
             Chronicle.revert(account, version: 1)

    assert {:ok, %{"primary" => %{sequence: 1}}} = Chronicle.verify_all()
  end

  test "resolver exceptions expose only their class" do
    Application.put_env(:chronicle, :erasure, keyring: RaisingKeys)

    fetch_result = Chronicle.Erasure.encrypt("private", "subject-1")
    destroy_result = Chronicle.Erasure.destroy("subject-1")

    assert fetch_result == {:error, {:erasure_keyring_failure, :fetch, RuntimeError}}
    assert destroy_result == {:error, {:erasure_keyring_failure, :destroy, RuntimeError}}
    refute inspect({fetch_result, destroy_result}) =~ "SECRET-PROBE"
  end

  test "a failed non-bang write returns a structured error and stores no plaintext" do
    Application.delete_env(:chronicle, :erasure)

    assert {:error, %Chronicle.Error{reason: :erasure_key_unavailable}} =
             Chronicle.record("personal.changed", %{
               email: Chronicle.erasable("person@example.test", "subject-1")
             })
  end

  test "invalid envelopes fail with a precise field error" do
    assert {:ok, envelope} = Chronicle.Erasure.encrypt("private", "subject-1")

    assert {:error, :invalid_erasable_envelope} = Chronicle.Erasure.decrypt(%{})

    assert {:error, :invalid_erasable_envelope} =
             envelope
             |> Map.put("extra", "value")
             |> Chronicle.Erasure.decrypt()

    assert {:error, {:invalid_erasable_envelope_encoding, :nonce}} =
             envelope
             |> Map.put("nonce", "!")
             |> Chronicle.Erasure.decrypt()

    assert {:error, {:invalid_erasable_envelope_encoding, :ciphertext}} =
             envelope
             |> Map.put("ciphertext", nil)
             |> Chronicle.Erasure.decrypt()

    assert {:error, {:invalid_erasable_envelope_size, :nonce}} =
             envelope
             |> Map.put("nonce", Base.url_encode64("short", padding: false))
             |> Chronicle.Erasure.decrypt()

    assert {:error, {:invalid_erasable_envelope_size, :tag}} =
             envelope
             |> Map.put("tag", Base.url_encode64("short", padding: false))
             |> Chronicle.Erasure.decrypt()

    refute Chronicle.Erasure.envelope?(%{})
  end

  test "keyring configuration and provider contracts fail closed" do
    Application.delete_env(:chronicle, :erasure)
    refute Chronicle.ErasureKeyring.configured?()

    assert {:error, :erasure_keyring_not_configured} =
             Chronicle.ErasureKeyring.fetch("subject-1")

    Application.put_env(:chronicle, :erasure, keyring: "not-a-keyring")

    assert {:error, :invalid_erasure_keyring_configuration} =
             Chronicle.ErasureKeyring.fetch("subject-1")

    Application.put_env(:chronicle, :erasure, keyring: MissingCallbacks)

    assert {:error, {:erasure_keyring_missing_callback, MissingCallbacks, :fetch}} =
             Chronicle.ErasureKeyring.fetch("subject-1")

    Application.put_env(:chronicle, :erasure, keyring: InvalidResults)

    assert {:error, {:invalid_erasure_keyring_result, :fetch}} =
             Chronicle.ErasureKeyring.fetch("subject-1")

    assert {:error, {:invalid_erasure_keyring_result, :destroy}} =
             Chronicle.ErasureKeyring.destroy("subject-1")

    Application.put_env(:chronicle, :erasure, keyring: InvalidKey)

    assert {:error, {:invalid_erasure_key_length, "subject-1", 5, 32}} =
             Chronicle.ErasureKeyring.fetch("subject-1")

    assert {:error, {:erasure_key_destruction_failed, "subject-1"}} =
             Chronicle.ErasureKeyring.destroy("subject-1")

    assert {:error, :invalid_erasure_key_id} = Chronicle.ErasureKeyring.fetch("")
    assert {:error, :invalid_erasure_key_id} = Chronicle.ErasureKeyring.destroy(nil)
  end

  test "the bang encryption error contains the safe matchable reason" do
    Application.delete_env(:chronicle, :erasure)

    error =
      assert_raise Chronicle.Erasure.Error, ~r/erasure_keyring_not_configured/, fn ->
        Chronicle.Erasure.encrypt!("private", "subject-1")
      end

    assert error.reason == :erasure_keyring_not_configured
  end

  defp random_key, do: :crypto.strong_rand_bytes(32)
end
