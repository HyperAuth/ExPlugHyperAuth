# ExHyperAuth
# Copyright (C) 2017  Jesús Hernández Gormaz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
defmodule HyperAuth.HTTP do
  @moduledoc """
  HTTP helpers for authentication framework.
  """

  @doc ~S"""
  Parse the authorization value.

  ## Examples

    iex> HyperAuth.HTTP.parse_authorization "Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    {"basic", [
      "dXNlcm5hbWU6cGFzc3dvcmQ="
    ], %{}}

    iex> HyperAuth.HTTP.parse_authorization "Basic dXNlcm5hbWU6cGFzc3dvcmQ=, realm=\"admin\""
    {"basic", [
      "dXNlcm5hbWU6cGFzc3dvcmQ="
    ], %{
      "realm" => "admin"
    }}

    iex> HyperAuth.HTTP.parse_authorization "Digest username=\"root\", realm=\"admin\", nonce=\"012345\", opaque=\"012345\", uri=\"/\", response=\"0a1b2c\""
    {"digest", [], %{
      "username" => "root",
      "realm" => "admin",
      "nonce" => "012345",
      "opaque" => "012345",
      "uri" => "/",
      "response" => "0a1b2c"
    }}

    iex> HyperAuth.HTTP.parse_authorization "Nothig"
    {"nothig", [], %{}}

    iex> HyperAuth.HTTP.parse_authorization ""
    nil
  """
  def parse_authorization(authorization) do
    case String.split authorization, " ", parts: 2 do
      [scheme, token] ->
        token
        |> parse_authorization_token()
        |> parse_authorization_values(scheme)
      [scheme] ->
        parse_authorization_values [], scheme
      _ ->
        nil
    end
  end

  defp parse_authorization_token(token) do
    for value <- String.split token, ", " do
      case String.split(value, "=\"", parts: 2) do
        [key, value_raw] when value_raw != "" ->
          value_cleaned = value_raw
          |> String.split("\"")
          |> List.first()
          {key, value_cleaned}
        _ ->
          value
      end
    end
  end

  defp parse_authorization_values(_, "") do
    nil
  end
  defp parse_authorization_values(values, scheme) do
    tokens = Enum.filter values, fn value ->
      is_binary value
    end
    credentials = Enum.filter(values, fn value ->
      is_tuple value
    end)
    |> Enum.into(%{})
    {String.downcase(scheme), tokens, credentials}
  end
end
