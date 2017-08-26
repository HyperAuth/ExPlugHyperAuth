defmodule HyperAuth.Mixfile do
  use Mix.Project

  def project do
    [
      app: :plug_hyper_auth,
      version: "0.1.0",
      elixir: "~> 1.3",
      description: "Plug for HTTP authentication",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: [
        licenses: ["AGPLv3"],
        source_url: "https://github.com/HyperAuth/ExHyperAuth",
        homepage_url: "https://github.com/HyperAuth/ExHyperAuth",
        links: %{},
        maintainers: [
          "Jesús Hernández Gormaz"
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      applications: [:logger, :plug]
      # extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
      {:plug, "~> 1.3.3 or ~> 1.4"}
    ]
  end
end
