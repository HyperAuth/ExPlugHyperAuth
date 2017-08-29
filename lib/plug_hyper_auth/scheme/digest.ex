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
defmodule PlugHyperAuth.Scheme.Digest do
  @behaviour PlugHyperAuth.Scheme
  @moduledoc """
  Adapter for scheme Digest.

  The opaque value is used to store a signed timestamp
  in UTC timezone, used to re-generate the nonce value,
  checking the opaque is not modified and the time.
  """

  @doc """
  Process authorization with scheme Digest.

  ## Examples

    iex> PlugHyperAuth.Scheme.Digest.process_authorization Plug.Test.conn(:get, "/"), [], %{}, []
    nil

    iex> PlugHyperAuth.Scheme.Digest.process_authorization Plug.Test.conn(:get, "/"), [], %{}, []
    nil
  """
  def process_authorization(conn, _tokens, authorization, opts) do
    opaque = authorization["opaque"]
    username = authorization["username"]
    realm = authorization["realm"]
    response = authorization["response"]
    algorithm = authorization["algorithm"] || "MD5"
    secret_key_base = Application.get_env(:auth, :secret_key_base, "test")
    # Check required values
    cond do
      is_nil secret_key_base ->
        nil
      is_nil(opaque) || is_nil(username) || is_nil(realm) || is_nil(response) ->
        nil
      realm != opts[:realm] ->
        nil
      true ->
        # Check the opaque, the time
        # and get timestamp for re-generate
        # the once value
        case verify_opaque opaque, secret_key_base do
          {:ok, timestamp} ->
            nonce = nonce_hash timestamp, secret_key_base
            %{
              "Digest-Username" => username,
              "Digest-Response" => response,
              "Digest-Realm" => realm,
              "Digest-Opaque" => opaque,
              "Digest-Nonce" => nonce,
              # "Digest-Nonce-Count" => timestamp,
              "Digest-Method" => conn.method,
              "Digest-URI" => conn.request_path,
              "Digest-Algorithm" => algorithm
              # "Digest-Algorithm" => "SHA-256"
            }
          :error ->
            nil
        end
    end
  end

  defp nonce_hash(clear_text, secret_key_base) do
    sha384_encode64 clear_text<>secret_key_base<>"nonce"
  end

  @doc """
  Hash md5 encoded in hexadecimal in lowercase.

  ## Examples

    iex> PlugHyperAuth.Scheme.Digest.md5 "Test"
    "0cbc6611f5540bd0809a388dc95a615b"
  """
  def md5(clear_text) do
    :md5
    |> :crypto.hash(clear_text)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Hash sha256 encoded in hexadecimal in lowercase.

  ## Examples

    iex> PlugHyperAuth.Scheme.Digest.sha256 "Test"
    "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"
  """
  def sha256(clear_text) do
    :sha256
    |> :crypto.hash(clear_text)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Hash sha384 encoded in base64.

  This is used to have a nonce more secure than with md5.

  ## Examples

    iex> PlugHyperAuth.Scheme.Digest.sha384_encode64 "Test"
    "e49GVAdrgOuWORHxnPrRqvQoXtSOgm9s3hsBp5qnP621RG5mf8T5BBd4LJEnBUDz"
  """
  def sha384_encode64(clear_text) do
    :sha384
    |> :crypto.hash(clear_text)
    |> Base.encode64
  end

  @doc """
  Verify timestamps difference in UTC timezone in seconds.

  ## Examples

    iex> PlugHyperAuth.Scheme.Digest.verify_timestamp 20, 15, 5
    true

    iex> PlugHyperAuth.Scheme.Digest.verify_timestamp 23, 15, 5
    false

    iex> old_timestamp = DateTime.utc_now()
    ...> |> DateTime.to_unix()
    ...> DateTime.utc_now()
    ...> |> DateTime.to_unix()
    ...> |> PlugHyperAuth.Scheme.Digest.verify_timestamp(old_timestamp, 10)
    true
  """
  def verify_timestamp(new_timestamp, old_timestamp, seconds) do
    (round(new_timestamp / seconds) - div(old_timestamp, seconds)) < 2
  end

  @doc """
  Verify timestamp difference in UTC timezone in seconds using now as new.

  ## Examples

    iex> old_timestamp = DateTime.utc_now()
    ...> |> DateTime.to_unix()
    ...> old_timestamp
    ...> |> PlugHyperAuth.Scheme.Digest.verify_timestamp(10)
    true
  """
  def verify_timestamp(old_timestamp, seconds) do
    DateTime.utc_now()
    |> DateTime.to_unix()
    |> verify_timestamp(old_timestamp, seconds)
  end

  defp generate_opaque(timestamp, secret_key_base) do
    Plug.Crypto.MessageVerifier.sign timestamp, secret_key_base<>"opaque"
  end

  defp verify_opaque(opaque, secret_key_base) do
    case Plug.Crypto.MessageVerifier.verify opaque, secret_key_base<>"opaque" do
      {:ok, timestamp} ->
          valid? = timestamp
          |> String.to_integer
          |> verify_timestamp(60)
          if valid? do
            timestamp
          else
            :error
          end
      :error ->
        :error
    end
  end

  @doc ~S"""
  Value of www-authenticate for scheme Digest.

  ## Examples

    iex> www_authenticate = PlugHyperAuth.Scheme.Digest.request_authenticate Plug.Test.conn(:get, "/"), realm: "admin@localhost"
    ...> www_authenticate =~ "algorithm=\"SHA-256\""
    true
    ...> www_authenticate =~ "realm=\"admin@localhost\""
    true
    ...> www_authenticate =~ "opaque"
    true
    ...> www_authenticate =~ "nonce"
    true
  """
  def request_authenticate(_conn, opts) do
    secret_key_base = Application.get_env(:auth, :secret_key_base, "test")
    algorithm = opts[:algorithm] || "SHA-256"
    realm = opts[:realm]
    timestamp = DateTime.utc_now
    |> DateTime.to_unix
    |> Integer.to_string
    opaque = generate_opaque timestamp, secret_key_base
    nonce = nonce_hash timestamp, secret_key_base
    "digest algorithm=\"#{algorithm}\", realm=\"#{realm}\", opaque=\"#{opaque}\", nonce=\"#{nonce}\""
  end
end
