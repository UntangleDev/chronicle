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

    result = Chronicle.Erasure.encrypt("private", "subject-1")

    assert result == {:error, {:erasure_keyring_failure, :fetch, RuntimeError}}
    refute inspect(result) =~ "SECRET-PROBE"
  end

  test "a failed non-bang write returns a structured error and stores no plaintext" do
    Application.delete_env(:chronicle, :erasure)

    assert {:error, %Chronicle.Error{reason: :erasure_key_unavailable}} =
             Chronicle.record("personal.changed", %{
               email: Chronicle.erasable("person@example.test", "subject-1")
             })
  end

  defp random_key, do: :crypto.strong_rand_bytes(32)
end
