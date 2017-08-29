# This file is part of PlugHyperAuth.
# Copyright (C) 2017  Jesús Hernández Gormaz
#
# PlugHyperAuth is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# PlugHyperAuth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
defmodule PlugHyperAuth.Scheme do
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
