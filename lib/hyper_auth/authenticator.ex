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
defmodule HyperAuth.Authenticator do
  @moduledoc """
  Specification of the authenticator adapter.
  """

  @doc """
  Authenticate the suplicant.
  """
  @callback authenticate(scheme :: String.t, authorization :: map, opts :: Plug.opts) :: nil | map
end
