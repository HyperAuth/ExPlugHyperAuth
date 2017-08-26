defmodule HyperAuth.Authenticator.Dummy do
  @behaviour HyperAuth.Authenticator
  @moduledoc """
  Dummy authenticator.
  """

  @doc """
  Dummy authentication to use in test environment.

  ## Examples

    iex> HyperAuth.Authenticator.Dummy.authenticate(%{
    ...> "User-Name" => "test",
    ...> "User-Password" => "tset"
    ...> }, [authenticator_dummy_password: "tset"])
    %{
      "uid" => "test"
    }
  """
  def authenticate(credentials, opts) do
    username = credentials["User-Name"]
    password = credentials["User-Password"]
    if opts[:authenticator_dummy_password] == password do
      %{
        "uid" => username
      }
    else
      nil
    end
  end
end
