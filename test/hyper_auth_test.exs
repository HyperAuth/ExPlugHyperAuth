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
defmodule HyperAuthTest do
  use ExUnit.Case, async: true
  use Plug.Test

  doctest HyperAuth
  doctest HyperAuth.HTTP
  doctest HyperAuth.Scheme.Basic
  doctest HyperAuth.Scheme.Digest
  doctest HyperAuth.Authenticator.Dummy

  test "HTTP public access 200" do
    opts = HyperAuth.init([public: true])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :http}
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 200
  end

  test "HTTPS public access 200" do
    opts = HyperAuth.init([public: true])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :https}
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 200
  end

  test "HTTPS unauthorized 401" do
    opts = HyperAuth.init([])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :https}
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 401
  end

  test "HTTP forbidden 403" do
    opts = HyperAuth.init([])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :http}
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 403
  end

  test "HTTP forbidden 403 authorization" do
    opts = HyperAuth.init([])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :http}
    |> put_req_header("authorization", "Basic dGVzdDp0ZXN0")
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 403
  end

  test "HTTP public access forbidden 403 authorization" do
    opts = HyperAuth.init([public: true])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :http}
    |> put_req_header("authorization", "Basic dGVzdDp0ZXN0")
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 403
  end

  test "HTTPS unauthorized 401 bad scheme" do
    opts = HyperAuth.init([
        authenticator: HyperAuth.Authenticator.Dummy,
        authenticator_dummy_password: "test"
      ])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :https}
    |> put_req_header("authorization", "NotExists dGVzdDp0ZXN0")
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 401
  end

  test "HTTPS dummy authorized 200" do
    opts = HyperAuth.init([
        authenticator: HyperAuth.Authenticator.Dummy,
        authenticator_dummy_password: "test"
      ])
    conn = %{conn(:get, "/") | remote_ip: {192, 168, 1, 1}, scheme: :https}
    |> put_req_header("authorization", "Basic dGVzdDp0ZXN0")
    |> put_status(200)
    |> HyperAuth.call(opts)
    assert conn.status == 200
  end
end
