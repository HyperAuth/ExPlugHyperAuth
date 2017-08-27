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
defmodule HyperAuth do
  import Plug.Conn
  @moduledoc """
  Plug for HTTP AAA using the HTTP auth framework.

  When a configured scheme is found in the authorization header
  it will use that to process the values of the header (with
  access to the connection but the modifications are ignored),
  with that values and other generic values the authenticator
  will authenticate the user (without access to connection).

  This plug is extensible with the behaviours:
    * `HyperAuth.Scheme`
    * `HyperAuth.Authenticator`

  This library support the common schemes then often you only need
  extend it with modules of `HyperAuth.Authenticator` behaviour
  (more safe than extend the schemes) like.

  The behaviour of `HyperAuth` is showed in the next table where:
    * **TLS**: If the connection is secure (HTTPS, HTTP over SSL/TLS).
    * **Public**: If the resource is configured as public access allowed.
    * **Header**: If exists the authorization header in the request.
    * **Auth**: If the credentials are valid.
    * **Status**: The HTTP status code response.
    * **User**: The user authenticated.

  | TLS | Public | Header | Auth | Status | User |
  |-----|--------|--------|------|--------|------|
  | NO  |  NO    |  NO    | NO   |  403   | anon |
  | NO  |  NO    |  YES   | NO   |  403   | anon |
  | NO  |  NO    |  YES   | YES  |  403   | anon |
  | NO  |  YES   |  NO    | NO   |  200   | anon |
  | NO  |  YES   |  YES   | NO   |  403   | anon |
  | NO  |  YES   |  YES   | YES  |  403   | anon |
  | YES |  NO    |  NO    | NO   |  401   | anon |
  | YES |  NO    |  YES   | NO   |  401   | anon |
  | YES |  YES   |  NO    | NO   |  200   | anon |
  | YES |  YES   |  YES   | NO   |  200   | anon |
  | YES |  NO    |  YES   | YES  |  200   | user |
  | YES |  YES   |  YES   | YES  |  200   | user |
  """

  @doc """
  Configure the schemes alloweds and the authenticator.

  The default schemes are:
    * Basic: HyperAuth.Scheme.Basic
    * Digest: HyperAuth.Scheme.Digest
  """
  def init(opts) do
    schemes = Keyword.get(opts, :schemes, %{})
    |> Map.put_new("basic", __MODULE__.Scheme.Basic)
    |> Map.put_new("digest", __MODULE__.Scheme.Digest)
    Keyword.put(opts, :schemes, schemes)
  end

  def call(conn, opts) do
    authorization = conn
    |> get_req_header("authorization")
    |> List.first
    cond do
      # Allow public without authorization
      opts[:public] && is_nil(authorization) ->
        conn
      # Forbidden authorization for not public over HTTP
      # Auth only allowed over secure connection
      conn.scheme != :https && conn.remote_ip != {127, 0, 0, 1} ->
        forbidden conn, opts
      # Check if not exists authorization
      is_nil(authorization) || String.length(authorization) == 0 ->
        unauthorized conn, opts
      # Limit the authorization size
      String.length(authorization) > 4096 ->
        header_fields_too_large conn, opts
      true ->
        # Parse authorization header value
        case __MODULE__.HTTP.parse_authorization authorization do
          {scheme, tokens, authorization_properties} ->
            # Process authorization credentials
            credentials = process_authorization conn, scheme, tokens, authorization_properties, opts
            if is_map credentials do
              # Authenticate
              user = authenticate credentials, opts
              if is_map user do
                # Put the user in the connection
                put_private conn, :auth_user, credentials
              else
                unauthorized conn, opts
              end
            else
              unauthorized conn, opts
            end
          _ ->
            unauthorized conn, opts
        end
    end
  end

  defp process_authorization(conn, scheme, tokens, authorization_properties, opts) do
    # Call the scheme module
    scheme_module = opts[:schemes][scheme]
    if is_nil scheme_module do
      nil
    else
      scheme_module.process_authorization conn, tokens, authorization_properties, opts
    end
  end

  defp authenticate(credentials, opts) do
    # Call the configured authenticator module
    authenticator_module = opts[:authenticator]
    if is_nil authenticator_module do
      nil
    else
      # Add common credentials values
      nas_identifier = Atom.to_string(node())
      credentials = Map.put(credentials, "NAS-Identifier", nas_identifier)
      user = authenticator_module.authenticate credentials, opts
      # All user map need an UID
      if is_nil user["uid"] do
        nil
      else
        user
      end
    end
  end

  defp request_authenticate(conn, opts) do
    opts[:schemes]
    |> Map.values()
    |> Enum.map(fn(scheme_module) ->
      # Call the scheme module
      scheme_module.request_authenticate(conn, opts)
    end)
    |> Enum.join(" ")
  end

  defp unauthorized(conn, opts) do
    if opts[:public] do
      conn
    else
      authorization_request = request_authenticate conn, opts
      conn
      |> put_resp_header("www-authenticate", authorization_request)
      |> send_resp(:unauthorized, "unauthorized")
      |> halt()
    end
  end

  defp forbidden(conn, _opts) do
    conn
    |> send_resp(:forbidden, "forbidden")
    |> halt()
  end

  defp header_fields_too_large(conn, _opts) do
    conn
    |> send_resp(:request_header_fields_too_large, "request header fields too large")
    |> halt()
  end
end
