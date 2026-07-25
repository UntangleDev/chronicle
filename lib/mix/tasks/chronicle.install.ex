defmodule Mix.Tasks.Chronicle.Install do
  use Mix.Task

  @shortdoc "Generates the Ecto audit migration and runtime configuration example"

  @moduledoc """
  Generates a host migration and `config/audit.runtime.exs.example`.

      mix chronicle.install --repo MyApp.Repo
      mix chronicle.install --repo MyApp.Repo --migrations-path priv/custom/migrations

  Existing files are never overwritten.
  """

  @switches [repo: :string, migrations_path: :string, phoenix: :boolean]
  @aliases [r: :repo]

  @impl true
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches, aliases: @aliases)

    if positional != [] or invalid != [] do
      Mix.raise("invalid arguments; run `mix help chronicle.install`")
    end

    repo = Keyword.get(opts, :repo) || Mix.raise("--repo is required")
    validate_module!(repo)

    migrations_path = Keyword.get(opts, :migrations_path, "priv/repo/migrations")
    timestamp = Calendar.strftime(DateTime.utc_now(), "%Y%m%d%H%M%S")
    migration_path = Path.join(migrations_path, "#{timestamp}_install_audit.exs")
    config_path = "config/audit.runtime.exs.example"

    write_new!(migration_path, migration(repo))
    write_new!(config_path, runtime_config(repo))

    Mix.shell().info("Generated #{migration_path}")
    Mix.shell().info("Generated #{config_path}")
    Mix.shell().info("Run your repository migration command.")

    if Keyword.get(opts, :phoenix, false) do
      Mix.shell().info("")
      Mix.shell().info("Add this after authentication in the relevant Phoenix pipeline:")
      Mix.shell().info("plug Chronicle.Phoenix.Plug, actor_assign: :current_user")
    end

    Mix.shell().info("")
    Mix.shell().info("Fresh 256-bit development key (not written to disk):")
    Mix.shell().info(Chronicle.Keys.generate())
  end

  defp migration(repo) do
    """
    defmodule #{repo}.Migrations.InstallAudit do
      use Ecto.Migration

      def up, do: Chronicle.Ecto.Migration.up()
      def down, do: Chronicle.Ecto.Migration.down()
    end
    """
  end

  defp runtime_config(repo) do
    """
    import Config

    config :chronicle,
      repo: #{repo},
      signing_key: {:system, "CHRONICLE_SIGNING_KEY_BASE64", :base64}

    # Before rotating keys, move to the explicit keyring configuration
    # documented under "Key rotation and operations".
    #
    # For rollback detection, implement an external Chronicle.CheckpointStore
    # and add this to your supervision tree:
    #
    # {Chronicle.Verifier, name: MyApp.AuditVerifier, store: :primary}
    """
  end

  defp write_new!(path, contents) do
    if File.exists?(path), do: Mix.raise("refusing to overwrite existing file #{path}")
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, contents, [:exclusive])
  end

  defp validate_module!(module) do
    unless Regex.match?(~r/^[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/, module) do
      Mix.raise("--repo must be an Elixir module name, got: #{inspect(module)}")
    end
  end
end
