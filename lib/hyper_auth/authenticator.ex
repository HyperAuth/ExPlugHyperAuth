defmodule HyperAuth.Authenticator do
  @moduledoc """
  Authenticator adapter.
  """

  @doc """
  Authenticate the suplicant.
  """
  @callback authenticate(authorization :: map, opts :: Plug.opts) :: nil | map
end
