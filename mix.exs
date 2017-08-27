defmodule HyperAuth.Mixfile do
  use Mix.Project

  def project do
    [
      app: :plug_hyper_auth,
      version: "0.1.1",
      elixir: "~> 1.3",
      description: "Plug for HTTP authentication",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: [
        licenses: ["AGPLv3"],
        source_url: "https://github.com/HyperAuth/ExHyperAuth",
        homepage_url: "https://github.com/HyperAuth/ExHyperAuth",
        links: %{
          "Github" => "https://github.com/HyperAuth/ExHyperAuth"
        },
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
      # TODO: Remove :applications and uncomment
      # the next line when not support Elixir 1.3
      # extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.3.3 or ~> 1.4"},
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end
end
