defmodule Chronicle.Test.Databases do
  @moduledoc """
  Database setup shared by the integration, concurrency, and adversarial suites.

  SQLite covers the portable paths. PostgreSQL covers the one the production
  concurrency model actually depends on: `SELECT ... FOR UPDATE` on the ledger
  head. SQLite has no row locking and the suite runs it with `lock: false`, so
  a SQLite-only suite never executes the mechanism that establishes total
  order.
  """

  @default_url "ecto://postgres:postgres@127.0.0.1:5432/chronicle_test"
  @pool_size 25

  defmodule PostgresRepo do
    @moduledoc false
    use Ecto.Repo, otp_app: :chronicle, adapter: Ecto.Adapters.Postgres
  end

  defmodule SQLiteRepo do
    @moduledoc false
    use Ecto.Repo, otp_app: :chronicle, adapter: Ecto.Adapters.SQLite3
  end

  @doc """
  Returns the PostgreSQL URL the suite should use.
  """
  @spec postgres_url() :: String.t()
  def postgres_url, do: System.get_env("CHRONICLE_TEST_DATABASE_URL", @default_url)

  @doc """
  Prepares PostgreSQL for the run and reports whether it is usable.

  Call once from `test_helper.exs`: the repository must be started outside any
  test process so it outlives individual tests.
  """
  @spec setup_postgres() :: boolean()
  def setup_postgres do
    options = Ecto.Repo.Supervisor.parse_url(postgres_url())

    with true <- Ecto.Adapters.Postgres.storage_up(options) in [:ok, {:error, :already_up}],
         {:ok, _pid} <-
           PostgresRepo.start_link(Keyword.merge(options, pool_size: @pool_size, log: false)) do
      drop_stale_schemas!()
      true
    else
      {:error, {:already_started, _pid}} -> true
      _other -> false
    end
  catch
    _kind, _reason -> false
  end

  @doc """
  Starts an isolated repository and returns `{repo, prefix}`.

  PostgreSQL shares one repository across the run and gives each test its own
  schema; SQLite gets its own database file.
  """
  @spec start!(:postgres | :sqlite, keyword()) :: {module(), String.t() | nil}
  def start!(adapter, opts \\ [])

  def start!(:postgres, _opts) do
    prefix = "chronicle_test_#{System.unique_integer([:positive, :monotonic])}"

    schema!(~s(CREATE SCHEMA "#{prefix}"))
    ExUnit.Callbacks.on_exit(fn -> schema!(~s(DROP SCHEMA IF EXISTS "#{prefix}" CASCADE)) end)

    {PostgresRepo, prefix}
  end

  def start!(:sqlite, opts) do
    database =
      Path.join(
        System.tmp_dir!(),
        "audit-met-test-#{System.unique_integer([:positive, :monotonic])}.sqlite3"
      )

    {:ok, pid} =
      SQLiteRepo.start_link(
        database: database,
        pool_size: Keyword.get(opts, :pool_size, 1),
        log: false
      )

    ExUnit.Callbacks.on_exit(fn ->
      # The pool may already be winding down when the test process exits.
      if Process.alive?(pid) do
        try do
          Supervisor.stop(pid)
        catch
          :exit, _reason -> :ok
        end
      end

      File.rm(database)
    end)

    {SQLiteRepo, nil}
  end

  @doc """
  Runs the audit migration and configures a store for the given repository.

  PostgreSQL keeps `lock: true` so `FOR UPDATE` is exercised; SQLite relies on
  its own transaction serialization and must disable it.
  """
  @spec configure!(module(), String.t() | nil, keyword()) :: keyword()
  def configure!(repo, prefix, opts \\ []) do
    prefix_options = if prefix, do: [prefix: prefix], else: []

    :ok =
      Ecto.Migrator.up(repo, 20_260_724_02, Chronicle.Ecto.Migration, log: false, prefix: prefix)

    integrity = [
      ledger: "primary",
      key_id: "test-key",
      key: Keyword.get_lazy(opts, :key, fn -> :crypto.strong_rand_bytes(32) end),
      lock: repo.__adapter__() != Ecto.Adapters.SQLite3
    ]

    store_options =
      [provider: Chronicle.Provider.Ecto, repo: repo, integrity: integrity] ++ prefix_options

    previous = snapshot_env()
    Application.put_env(:chronicle, :stores, primary: store_options)
    Application.put_env(:chronicle, :default_store, :primary)
    ExUnit.Callbacks.on_exit(fn -> restore_env(previous) end)

    store_options
  end

  @doc """
  Creates a plain domain table used by the integration fixtures.
  """
  @spec create_table!(module(), String.t() | nil, String.t(), String.t()) :: :ok
  def create_table!(repo, prefix, name, columns) do
    qualified = if prefix, do: ~s("#{prefix}"."#{name}"), else: ~s("#{name}")
    Ecto.Adapters.SQL.query!(repo, "CREATE TABLE #{qualified} (#{columns})", [], log: false)
    :ok
  end

  defp schema!(statement),
    do: Ecto.Adapters.SQL.query!(PostgresRepo, statement, [], log: false)

  defp drop_stale_schemas! do
    %{rows: rows} =
      Ecto.Adapters.SQL.query!(
        PostgresRepo,
        """
        SELECT schema_name FROM information_schema.schemata
        WHERE schema_name LIKE 'chronicle_test_%'
        """,
        [],
        log: false
      )

    Enum.each(rows, fn [schema] -> schema!(~s(DROP SCHEMA IF EXISTS "#{schema}" CASCADE)) end)
  end

  defp snapshot_env do
    for key <- [:stores, :default_store, :repo, :signing_key, :key_id, :integrity, :prefix],
        into: %{} do
      {key, Application.get_env(:chronicle, key, :__missing__)}
    end
  end

  defp restore_env(previous) do
    Enum.each(previous, fn
      {key, :__missing__} -> Application.delete_env(:chronicle, key)
      {key, value} -> Application.put_env(:chronicle, key, value)
    end)
  end
end
