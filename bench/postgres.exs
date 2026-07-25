unless url = System.get_env("CHRONICLE_BENCH_DATABASE_URL") do
  raise """
  CHRONICLE_BENCH_DATABASE_URL is required.

  Use a disposable PostgreSQL database. The benchmark creates and drops a
  uniquely named schema, including all data below it.
  """
end

defmodule Chronicle.Bench.Repo do
  use Ecto.Repo,
    otp_app: :chronicle,
    adapter: Ecto.Adapters.Postgres
end

defmodule Chronicle.Bench.Item do
  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "chronicle_bench_items" do
    field :value, :integer
  end
end

parse_positive = fn name, default ->
  case System.get_env(name) do
    nil ->
      default

    value ->
      case Integer.parse(value) do
        {integer, ""} when integer > 0 -> integer
        _ -> raise "#{name} must be a positive integer"
      end
  end
end

writes = parse_positive.("CHRONICLE_BENCH_WRITES", 1_000)
concurrency = parse_positive.("CHRONICLE_BENCH_CONCURRENCY", 16)
pool_size = max(concurrency + 2, 10)
prefix = "chronicle_bench_#{System.unique_integer([:positive, :monotonic])}"

{:ok, _repo} =
  Chronicle.Bench.Repo.start_link(
    url: url,
    pool_size: pool_size,
    queue_target: 5_000,
    queue_interval: 5_000,
    log: false
  )

quoted_prefix = ~s("#{prefix}")
Ecto.Adapters.SQL.query!(Chronicle.Bench.Repo, "CREATE SCHEMA #{quoted_prefix}", [], log: false)

try do
  :ok =
    Ecto.Migrator.up(
      Chronicle.Bench.Repo,
      System.unique_integer([:positive, :monotonic]),
      Chronicle.Ecto.Migration,
      prefix: prefix,
      log: false
    )

  Ecto.Adapters.SQL.query!(
    Chronicle.Bench.Repo,
    "CREATE TABLE #{quoted_prefix}.chronicle_bench_items (id uuid PRIMARY KEY, value bigint)",
    [],
    log: false
  )

  Application.delete_env(:chronicle, :stores)
  Application.put_env(:chronicle, :repo, Chronicle.Bench.Repo)
  Application.put_env(:chronicle, :prefix, prefix)
  Application.put_env(:chronicle, :signing_key, :crypto.strong_rand_bytes(32))
  Application.put_env(:chronicle, :key_id, "benchmark-key")

  write = fn value ->
    started = System.monotonic_time()

    result =
      Chronicle.Bench.Item
      |> struct()
      |> Ecto.Changeset.change(value: value)
      |> Chronicle.insert(ecto_options: [prefix: prefix])

    elapsed =
      System.monotonic_time()
      |> Kernel.-(started)
      |> System.convert_time_unit(:native, :microsecond)

    case result do
      {:ok, _item} -> elapsed
      {:error, error} -> raise "benchmark write failed: #{inspect(error)}"
    end
  end

  Enum.each(1..min(25, writes), write)

  started = System.monotonic_time()

  latencies =
    1..writes
    |> Task.async_stream(write,
      max_concurrency: concurrency,
      ordered: false,
      timeout: :infinity
    )
    |> Enum.map(fn {:ok, latency} -> latency end)
    |> Enum.sort()

  elapsed_us =
    System.monotonic_time()
    |> Kernel.-(started)
    |> System.convert_time_unit(:native, :microsecond)

  percentile = fn fraction ->
    index = min(length(latencies) - 1, floor((length(latencies) - 1) * fraction))
    Enum.at(latencies, index)
  end

  verification_started = System.monotonic_time()
  {:ok, _checkpoints} = Chronicle.verify_all()

  verification_us =
    System.monotonic_time()
    |> Kernel.-(verification_started)
    |> System.convert_time_unit(:native, :microsecond)

  IO.puts("""
  writes: #{writes}
  concurrency: #{concurrency}
  throughput_writes_per_second: #{Float.round(writes * 1_000_000 / elapsed_us, 1)}
  write_latency_ms_p50: #{Float.round(percentile.(0.50) / 1_000, 2)}
  write_latency_ms_p95: #{Float.round(percentile.(0.95) / 1_000, 2)}
  write_latency_ms_p99: #{Float.round(percentile.(0.99) / 1_000, 2)}
  verification_ms: #{Float.round(verification_us / 1_000, 2)}
  """)
after
  Ecto.Adapters.SQL.query!(
    Chronicle.Bench.Repo,
    "DROP SCHEMA #{quoted_prefix} CASCADE",
    [],
    log: false
  )
end
