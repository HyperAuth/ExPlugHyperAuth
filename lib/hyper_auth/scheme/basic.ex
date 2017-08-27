# This file is part of HyperAuth.
# Copyright (C) 2017  Jesús Hernández Gormaz
#
# HyperAuth is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# HyperAuth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
