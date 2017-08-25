defmodule HyperAuth.Scheme do
  @moduledoc """
  Specification of the HTTP authentication scheme adapter.
  """

  @doc """
  Process the authorization to return the credentials map or nil.
  """
  @callback process_authorization(conn :: Plug.Conn.t, tokens :: list(String.t), authorization :: map, opts :: Plug.opts) :: nil | map

  @doc """
  Authenticate request to send to the client.
  """
  @callback request_authenticate(conn :: Plug.Conn.t, opts :: Plug.opts) :: String.t
end
