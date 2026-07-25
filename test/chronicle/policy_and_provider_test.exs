defmodule Chronicle.PolicyAndProviderTest do
  @moduledoc """
  Schema policy validation, the in-memory provider, and the remaining
  configuration and write-path branches.
  """

  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.Ecto.Policy
  alias Chronicle.Provider.Memory
  alias Chronicle.Test.Databases

  describe "schema policy validation" do
    test "rejects options that are not a literal keyword list" do
      assert_raise ArgumentError, ~r/must be a literal keyword list/, fn ->
        defmodule Dynamic do
          use Ecto.Schema
          use Chronicle.Schema, Application.get_env(:chronicle, :nope, [])
          schema("dynamic", do: field(:a, :string))
        end
      end
    end

    test "rejects an unknown option" do
      assert_raise ArgumentError, ~r/unknown options: \[:nonsense\]/, fn ->
        defmodule UnknownOption do
          use Ecto.Schema
          use Chronicle.Schema, nonsense: [:a]
          schema("unknown", do: field(:a, :string))
        end
      end
    end

    test "rejects a value that is not a list of field atoms" do
      assert_raise ArgumentError, ~r/must be a list of field atoms/, fn ->
        defmodule BadRedact do
          use Ecto.Schema
          use Chronicle.Schema, redact: "secret"
          schema("bad_redact", do: field(:a, :string))
        end
      end

      assert_raise ArgumentError, ~r/only must be :all or a list/, fn ->
        defmodule BadOnly do
          use Ecto.Schema
          use Chronicle.Schema, only: :some
          schema("bad_only", do: field(:a, :string))
        end
      end
    end

    test "rejects a field claiming two protection strategies" do
      assert_raise ArgumentError, ~r/more than one protection strategy/, fn ->
        defmodule DoubleProtected do
          use Ecto.Schema
          use Chronicle.Schema, redact: [:a], hash: [:a]
          schema("double", do: field(:a, :string))
        end
      end
    end

    test "rejects a policy naming a field the schema does not have" do
      assert_raise ArgumentError, ~r/unknown fields: \[:absent\]/, fn ->
        defmodule UnknownField do
          use Ecto.Schema
          use Chronicle.Schema, redact: [:absent]

          schema "unknown_field" do
            field :a, :string
          end
        end
      end
    end

    test "a schema without a policy gets the defaults" do
      defmodule NoPolicy do
        use Ecto.Schema

        schema "no_policy" do
          field :a, :string
        end
      end

      policy = Policy.get(NoPolicy)
      assert policy.only == :all
      assert policy.except == []
      assert Policy.tracked?(policy, :a)
    end

    test "only and except narrow which changes are tracked" do
      defmodule Narrowed do
        use Ecto.Schema
        use Chronicle.Schema, only: [:a, :b], except: [:b]

        schema "narrowed" do
          field :a, :string
          field :b, :string
          field :c, :string
        end
      end

      policy = Policy.get(Narrowed)
      assert Policy.tracked?(policy, :a)
      refute Policy.tracked?(policy, :b)
      refute Policy.tracked?(policy, :c)
    end

    test "get/1 on nil yields defaults" do
      assert Policy.get(nil).only == :all
    end
  end

  describe "in-memory provider" do
    test "collects events and groups in order" do
      {:ok, server} = Memory.start_link()
      opts = [provider: {Memory, server: server}]

      Chronicle.record!("first", %{}, opts)
      Chronicle.Scope.group("unit", opts, fn -> Chronicle.record!("child", %{}, opts) end)
      Chronicle.record!("last", %{}, opts)

      assert [{:event, first}, {:group, group, [child]}, {:event, last}] = Memory.entries(server)
      assert first.type == "first"
      assert group.type == "unit"
      assert child.type == "child"
      assert last.type == "last"
    end

    test "clear/1 empties it" do
      {:ok, server} = Memory.start_link()
      Chronicle.record!("x", %{}, provider: {Memory, server: server})

      assert :ok = Memory.clear(server)
      assert Memory.entries(server) == []
    end

    test "requires a server" do
      assert {:error, %Chronicle.Error{}} = Chronicle.record("x", %{}, provider: Memory)
    end

    test "has a child_spec so it can be supervised in a test tree" do
      assert %{id: Memory, restart: :temporary} = Memory.child_spec([])
      assert %{id: :named} = Memory.child_spec(name: :named)
    end
  end

  describe "store configuration" do
    test "the two-key form yields a working Ecto store" do
      {repo, _prefix} = Databases.start!(:sqlite)
      :ok = Ecto.Migrator.up(repo, 20_260_724_02, Chronicle.Ecto.Migration, log: false)

      previous = Application.get_env(:chronicle, :stores, :__missing__)
      Application.delete_env(:chronicle, :stores)
      Application.put_env(:chronicle, :repo, repo)
      Application.put_env(:chronicle, :signing_key, :crypto.strong_rand_bytes(32))

      on_exit(fn ->
        Application.delete_env(:chronicle, :repo)
        Application.delete_env(:chronicle, :signing_key)

        case previous do
          :__missing__ -> Application.delete_env(:chronicle, :stores)
          value -> Application.put_env(:chronicle, :stores, value)
        end
      end)

      assert {:ok, store} = Chronicle.Config.fetch_store(:primary)
      assert store.provider == Chronicle.Provider.Ecto
      assert Chronicle.Config.store_names() == [:primary]

      # SQLite cannot take a row lock, so the simple form turns it off for us.
      refute store.options |> Keyword.fetch!(:integrity) |> Keyword.fetch!(:lock)

      assert {:ok, _} = Chronicle.record("configured.simply", %{})
      assert {:ok, _} = Chronicle.verify_all()
    end

    test "an unnamed store is only synthesised for the default name" do
      assert {:error, {:store_not_configured, :other}} = Chronicle.Config.fetch_store(:other)
    end

    test "a store without a provider is reported" do
      Application.put_env(:chronicle, :stores, broken: [repo: SomeRepo])
      assert {:error, {:store_provider_missing, :broken}} = Chronicle.Config.fetch_store(:broken)
    end

    test "an unusable provider value is reported" do
      Application.put_env(:chronicle, :stores, broken: [provider: "nope"])
      assert {:error, {:invalid_provider, "nope"}} = Chronicle.Config.fetch_store(:broken)
    end

    test "a provider may carry its own options" do
      {:ok, server} = Memory.start_link()
      Application.put_env(:chronicle, :stores, mem: [provider: {Memory, server: server}])

      assert {:ok, store} = Chronicle.Config.fetch_store(:mem)
      assert store.provider == Memory
      assert Keyword.fetch!(store.options, :server) == server
    end

    test "store_name/1 falls back to the default" do
      assert Chronicle.Config.store_name([]) == Chronicle.Config.default_store()
      assert Chronicle.Config.store_name(store: :explicit) == :explicit
    end
  end

  describe "install task" do
    test "writes a migration and a config example, and never overwrites" do
      in_tmp(fn ->
        output =
          ExUnit.CaptureIO.capture_io(fn ->
            Mix.Tasks.Chronicle.Install.run(["--repo", "MyApp.Repo", "--phoenix"])
          end)

        assert output =~ "Generated"
        assert output =~ "plug Chronicle.Phoenix.Plug"
        assert [migration] = Path.wildcard("priv/repo/migrations/*_install_audit.exs")
        assert File.read!(migration) =~ "Chronicle.Ecto.Migration.up()"

        config = File.read!("config/audit.runtime.exs.example")
        assert config =~ "MyApp.Repo"

        assert_raise Mix.Error, ~r/refusing to overwrite/, fn ->
          ExUnit.CaptureIO.capture_io(fn ->
            Mix.Tasks.Chronicle.Install.run(["--repo", "MyApp.Repo"])
          end)
        end
      end)
    end

    test "requires a valid repo module name" do
      assert_raise Mix.Error, ~r/--repo is required/, fn ->
        Mix.Tasks.Chronicle.Install.run([])
      end

      assert_raise Mix.Error, ~r/must be an Elixir module name/, fn ->
        Mix.Tasks.Chronicle.Install.run(["--repo", "not a module"])
      end

      assert_raise Mix.Error, ~r/invalid arguments/, fn ->
        Mix.Tasks.Chronicle.Install.run(["stray", "--repo", "MyApp.Repo"])
      end
    end
  end

  defp in_tmp(fun) do
    path =
      Path.join(System.tmp_dir!(), "audit-met-install-#{System.unique_integer([:positive])}")

    File.mkdir_p!(path)
    original = File.cwd!()

    try do
      File.cd!(path, fun)
    after
      File.cd!(original)
      File.rm_rf(path)
    end
  end
end
