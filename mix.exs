defmodule Chronicle.MixProject do
  use Mix.Project

  @version "0.1.2"

  def project do
    [
      app: :chronicle,
      version: @version,
      # 1.17 is the first release requiring Erlang/OTP 25, which is where
      # `:crypto.hash_equals/2` arrived. Mix has no OTP constraint of its own,
      # so the Elixir floor is how that requirement gets stated.
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      deps: deps(),
      test_coverage: [
        threshold: 90,
        ignore_modules: [
          ~r/^Chronicle\.Test\./,
          Chronicle.Test.Databases,
          Chronicle.Test.AdversarialCases
        ]
      ],
      description: "Tamper-evident audit facts and restorable Ecto record versions",
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:crypto, :logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:telemetry, "~> 1.2"},
      {:ecto_sql, "~> 3.11", optional: true},
      {:plug, "~> 1.15", optional: true},
      {:ecto_sqlite3, "~> 0.24", only: :test},
      {:postgrex, "~> 0.22.3", only: [:dev, :test]},
      {:jason, "~> 1.4", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"Documentation" => "https://hexdocs.pm/chronicle"},
      files: ~w(lib bench .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],

      # Internal modules — `@moduledoc false`, so ExDoc has no page to link to
      # and warns on every mention. They are still worth naming in prose: a
      # reader who wants the detail can open the source, and the alternative is
      # vaguer documentation written around a tooling constraint. Add an entry
      # when a published doc needs to name another internal module; `mix docs`
      # will say so.
      skip_code_autolink_to: [
        "Chronicle.Digest",
        "Chronicle.Ecto.Schema.Event.content_fields/0",
        "Chronicle.Reference",
        "Chronicle.Reference.id/1",
        "Chronicle.Scope",
        "Chronicle.Value"
      ]
    ]
  end
end
