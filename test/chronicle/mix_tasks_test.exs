defmodule Chronicle.MixTasksTest do
  use ExUnit.Case, async: false

  test "chronicle.install generates safe host scaffolding and refuses overwrite" do
    root =
      Path.join(
        System.tmp_dir!(),
        "audit-install-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    File.cd!(root, fn ->
      Mix.Tasks.Chronicle.Install.run([
        "--repo",
        "Example.Repo",
        "--migrations-path",
        "migrations",
        "--phoenix"
      ])

      [migration] = Path.wildcard("migrations/*_install_audit.exs")
      assert File.read!(migration) =~ "defmodule Example.Repo.Migrations.InstallAudit"

      config = File.read!("config/audit.runtime.exs.example")
      assert config =~ ~s(config :chronicle)
      assert config =~ "repo: Example.Repo"
      assert config =~ ~s({:system, "CHRONICLE_SIGNING_KEY_BASE64", :base64})
      refute config =~ ~s(stores:)
      refute config =~ ~s(key_epochs:)
      refute config =~ ~r/key: "[A-Za-z0-9+\/=]{40,}"/

      assert_raise Mix.Error, ~r/refusing to overwrite/, fn ->
        Mix.Tasks.Chronicle.Install.run([
          "--repo",
          "Example.Repo",
          "--migrations-path",
          "migrations"
        ])
      end
    end)
  end

  test "chronicle.install rejects a module name that could inject source" do
    assert_raise Mix.Error, ~r/module name/, fn ->
      Mix.Tasks.Chronicle.Install.run(["--repo", "Example.Repo; System.halt()"])
    end
  end
end
