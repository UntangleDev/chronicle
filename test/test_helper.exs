postgres? = Chronicle.Test.Databases.setup_postgres()
required? = System.get_env("CHRONICLE_REQUIRE_POSTGRES") in ~w(1 true)

# Skipping the PostgreSQL suite is a convenience when working locally and a trap
# anywhere that reports a result to somebody else. `setup_postgres/0` treats
# every failure as "not reachable", so a wrong URL, a missing server and a
# permissions problem all look identical to a deliberate SQLite-only run — and
# the suite then passes having never exercised the ledger-head lock. CI sets
# CHRONICLE_REQUIRE_POSTGRES so that difference is fatal rather than invisible.
cond do
  postgres? ->
    :ok

  required? ->
    raise """
    PostgreSQL is required but was not reachable.

        #{Chronicle.Test.Databases.postgres_url()}

    CHRONICLE_REQUIRE_POSTGRES is set, so this fails instead of excluding the
    concurrency suite. That suite covers the ledger-head row lock
    (SELECT ... FOR UPDATE) which establishes total order, and which SQLite
    cannot execute — excluding it would report success for something that never
    ran.

    Start a server and point CHRONICLE_TEST_DATABASE_URL at it, or unset
    CHRONICLE_REQUIRE_POSTGRES to allow the skip.
    """

  true ->
    IO.puts("""

    PostgreSQL is not reachable, so the concurrency suite is being skipped.
    It covers the ledger-head row lock (SELECT ... FOR UPDATE), which SQLite
    cannot exercise. Point CHRONICLE_TEST_DATABASE_URL at a disposable server
    to run it:

        CHRONICLE_TEST_DATABASE_URL=#{Chronicle.Test.Databases.postgres_url()} mix test
    """)
end

ExUnit.start(exclude: if(postgres?, do: [], else: [:postgres]))
