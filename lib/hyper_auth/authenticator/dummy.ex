defmodule HyperAuth.Authenticator.Dummy do
  @behaviour HyperAuth.Authenticator
  @moduledoc """
  Dummy authenticator.
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
