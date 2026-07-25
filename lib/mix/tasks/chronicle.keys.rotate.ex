defmodule Mix.Tasks.Chronicle.Keys.Rotate do
  use Mix.Task

  @shortdoc "Verifies the ledger and generates a new audit signing key"

  @moduledoc """
  Verifies the complete named store and generates replacement key material.
  By default it does not mutate the ledger, configuration, or a secret manager.

      mix chronicle.keys.rotate --key-id audit-hmac-2026-08
      mix chronicle.keys.rotate security --key-id security-hmac-2026-08

  `--append-transition` invokes the low-level transition operation. Use it only
  while writers are drained and before atomically deploying the returned epoch
  boundary and both keys to every writer.
  """

  @switches [key_id: :string, append_transition: :boolean]

  @impl true
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] or length(positional) > 1 do
      Mix.raise("invalid arguments; run `mix help chronicle.keys.rotate`")
    end

    Mix.Task.run("app.start")
    store = parse_store(List.first(positional))
    key_id = Keyword.get(opts, :key_id) || Mix.raise("--key-id is required")

    if String.trim(key_id) == "", do: Mix.raise("--key-id must not be empty")

    status =
      case Chronicle.keys(store) do
        {:ok, %{current: current, required: required} = status} ->
          if key_id == current or key_id in required do
            Mix.raise("key id #{inspect(key_id)} already appears in the ledger")
          end

          status

        {:error, error} ->
          Mix.raise("cannot inspect ledger keys: #{Exception.message(error)}")
      end

    case Chronicle.verify_all(store) do
      {:ok, checkpoints} ->
        Mix.shell().info("Verified #{map_size(checkpoints)} ledgers in #{inspect(store)}.")

      {:error, error} ->
        Mix.raise("refusing rotation because verification failed: #{Exception.message(error)}")
    end

    encoded_key = Chronicle.Keys.generate()
    {:ok, key} = Base.decode64(encoded_key)

    plan =
      if opts[:append_transition] do
        case Chronicle.Keys.rotate(store, key_id, key) do
          {:ok, plan} -> plan
          {:error, error} -> Mix.raise("rotation transition failed: #{Exception.message(error)}")
        end
      else
        nil
      end

    Mix.shell().info("")
    Mix.shell().info("New key id: #{key_id}")
    Mix.shell().info("New 256-bit Base64 key:")
    Mix.shell().info(encoded_key)
    Mix.shell().info("")

    if plan do
      Mix.shell().info(
        "Transition appended at sequence #{plan.transition_sequence}; " <>
          "new key activates at sequence #{plan.activates_at_sequence}."
      )

      Mix.shell().info(
        "Configure #{inspect(plan.old_key_id)} through: #{plan.transition_sequence}; " <>
          "#{inspect(plan.new_key_id)} from: #{plan.activates_at_sequence}."
      )
    else
      Mix.shell().info(
        "No transition was appended. The tentative transition sequence is " <>
          "#{status.next_sequence}; it is not reserved and may change."
      )

      Mix.shell().info(
        "Drain writers before rerunning with --append-transition and establishing the epoch boundary."
      )
    end
  end

  defp parse_store(nil), do: Chronicle.Config.default_store()

  defp parse_store(name) do
    Enum.find(Chronicle.Config.store_names(), &(Atom.to_string(&1) == name)) ||
      Mix.raise("unknown audit store #{inspect(name)}")
  end
end
