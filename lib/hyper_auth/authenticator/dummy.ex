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
defmodule HyperAuth.Authenticator.Dummy do
  @behaviour HyperAuth.Authenticator
  @moduledoc """
  Dummy authenticator.
  """

  @doc """
  Dummy authentication to use in test environment.

  ## Examples

    iex> HyperAuth.Authenticator.Dummy.authenticate("basic", %{
    ...> "User-Name" => "test",
    ...> "User-Password" => "tset"
    ...> }, [authenticator_dummy_password: "tset"])
    %{
      "uid" => "test"
    }
  """
  def authenticate(_scheme, credentials, opts) do
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
