defmodule HyperAuth.Scheme.Basic do
  @behaviour HyperAuth.Scheme
  @moduledoc """
  Adapter for scheme Basic.
  """

  @doc """
  Process authorization with scheme Basic.

  ## Examples

    iex> HyperAuth.Scheme.Basic.process_authorization Plug.Test.conn(:get, "/"), ["AXBlcC5hDWUGcGFzc3dvcmQ="], %{}, []
    nil

    iex> HyperAuth.Scheme.Basic.process_authorization Plug.Test.conn(:get, "/"), ["AXBlcC5hDWUGcGFzc3dvcmQ"], %{}, []
    nil
  """
  def process_authorization(_conn, tokens, _authorization, _opts) do
    [token|_] = tokens
    case Base.decode64 token do
      {:ok, credentials} ->
        case String.split credentials, ":" do
          [username, password] ->
            %{
              "User-Name" => username,
              "User-Password" => password
            }
          _ ->
            nil
        end
      _ ->
        nil
    end
  end

  @doc ~S"""
  Value of www-authenticate for scheme Basic.

    iex> HyperAuth.Scheme.Basic.request_authenticate Plug.Test.conn(:get, "/"), []
    "basic"

    iex> HyperAuth.Scheme.Basic.request_authenticate Plug.Test.conn(:get, "/"), realm: "admin@localhost"
    "basic realm=\"admin@localhost\""
  """
  def request_authenticate(_conn, opts) do
    case opts[:realm] do
      realm when is_binary realm ->
        "basic realm=\""<>realm<>"\""
      _ ->
        "basic"
    end
  end
end
