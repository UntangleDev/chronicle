defmodule Chronicle.Ecto.IntegrityIntegrationTest do
  use ExUnit.Case, async: false

  alias Chronicle.{Event, Group}
  alias Chronicle.Provider.Ecto, as: EctoProvider

  defmodule Repo do
    use Ecto.Repo,
      otp_app: :chronicle,
      adapter: Ecto.Adapters.SQLite3
  end

  setup_all do
    database =
      Path.join(
        System.tmp_dir!(),
        "audit-integrity-#{System.unique_integer([:positive, :monotonic])}.sqlite3"
      )

    start_supervised!({Repo, database: database, pool_size: 1, log: false})
    :ok = Ecto.Migrator.up(Repo, 20_260_724_01, Chronicle.Ecto.Migration, log: false)

    on_exit(fn -> File.rm(database) end)
    :ok
  end

  test "migration, provider, verifier, and external checkpoint work on a real Ecto repo" do
    key = :crypto.strong_rand_bytes(32)

    opts = [
      repo: Repo,
      integrity: [ledger: "primary", key_id: "key-1", key: key, lock: false]
    ]

    standalone = Event.new("account.created", %{account_id: "a-1"}, outcome: :success)
    assert {:ok, first_checkpoint} = EctoProvider.write_event(standalone, opts)

    group =
      "account.activation"
      |> Group.new()
      |> Group.complete(:success, 100, 1)

    child =
      Event.new("email.requested", %{template: "welcome"}, outcome: :success)
      |> Event.put_group(group.id, 1)

    assert {:ok, final_checkpoint} = EctoProvider.write_group(group, [child], opts)

    assert {:ok, ^final_checkpoint} = Chronicle.Ecto.Integrity.verify(Repo, opts)

    assert {:ok, ^final_checkpoint} =
             Chronicle.Ecto.Integrity.verify(
               Repo,
               Keyword.put(opts, :verification_batch_size, 1)
             )

    assert {:ok, %{"primary" => ^final_checkpoint}} =
             Chronicle.Ecto.Integrity.verify_all(Repo, opts)

    assert {:ok, ^final_checkpoint} =
             Chronicle.Ecto.Integrity.verify(
               Repo,
               Keyword.put(opts, :checkpoint, first_checkpoint)
             )

    Ecto.Adapters.SQL.query!(
      Repo,
      "UPDATE audit_events SET type = ? WHERE id = ?",
      ["account.forged", standalone.id],
      log: false
    )

    assert {:error, {:content_digest_mismatch, 1}} =
             Chronicle.Ecto.Integrity.verify(Repo, opts)
  end
end
