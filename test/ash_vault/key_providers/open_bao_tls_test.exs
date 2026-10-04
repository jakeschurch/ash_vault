defmodule AshVault.KeyProviders.OpenBaoTlsTest do
  @moduledoc """
  `:cacertfile` and `:connect_options` reach `Req`, and a private CA is actually trusted
  with peer and hostname verification on — proved by a real TLS handshake against a
  local `:ssl` listener whose certificate a throwaway CA signed.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao.Transport

  @provider AshVault.Test.TlsProvider

  setup do
    directory =
      Path.join(System.tmp_dir!(), "ash_vault_tls_#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)

    on_exit(fn ->
      Application.delete_env(:ash_vault, @provider)
      File.rm_rf!(directory)
    end)

    {:ok, directory: directory}
  end

  describe "base_options/1" do
    test "without TLS config, no connect_options are added" do
      Application.put_env(:ash_vault, @provider, address: "https://bao:8200")
      assert {:ok, options} = Transport.base_options(@provider)
      refute Keyword.has_key?(options, :connect_options)
      assert options[:base_url] == "https://bao:8200"
    end

    test ":cacertfile becomes a verify_peer transport option, merged over connect_options",
         %{directory: directory} do
      path = Path.join(directory, "ca.crt")
      File.write!(path, "placeholder")

      Application.put_env(:ash_vault, @provider,
        cacertfile: path,
        connect_options: [timeout: 1_000, transport_opts: [versions: [:"tlsv1.3"]]]
      )

      assert {:ok, options} = Transport.base_options(@provider)
      connect_options = options[:connect_options]
      assert connect_options[:timeout] == 1_000
      transport_opts = connect_options[:transport_opts]
      assert transport_opts[:cacertfile] == path
      assert transport_opts[:verify] == :verify_peer
      assert transport_opts[:versions] == [:"tlsv1.3"]
      refute Keyword.has_key?(transport_opts, :customize_hostname_check)
    end

    test "a missing :cacertfile is its own error, not a transport outage", %{directory: directory} do
      path = Path.join(directory, "absent.crt")
      Application.put_env(:ash_vault, @provider, cacertfile: path, token: "t")

      assert {:error, %ProviderUnavailable{reason: {:cacertfile_unreadable, ^path}} = error} =
               Transport.get(@provider, "/v1/sys/health")

      assert Exception.message(error) =~ "No connection was attempted"
    end

    test "verify: :verify_none is refused" do
      Application.put_env(:ash_vault, @provider,
        token: "t",
        connect_options: [transport_opts: [verify: :verify_none]]
      )

      assert_raise ArgumentError, ~r/verify_none/, fn -> Transport.get(@provider, "/v1/x") end
    end
  end

  describe "a real handshake against a private CA" do
    setup %{directory: directory} do
      {ca_path, server_options} = certificates(directory)

      {:ok, listener} =
        :ssl.listen(0, [:binary, active: false, reuseaddr: true] ++ server_options)

      {:ok, {_address, port}} = :ssl.sockname(listener)
      acceptor = spawn_link(fn -> accept_loop(listener) end)

      on_exit(fn ->
        Process.exit(acceptor, :kill)
        :ssl.close(listener)
      end)

      {:ok, ca_path: ca_path, port: port}
    end

    test "is trusted via :cacertfile", %{ca_path: ca_path, port: port} do
      Application.put_env(:ash_vault, @provider,
        address: "https://localhost:#{port}",
        token: "t",
        cacertfile: ca_path,
        max_retries: 0
      )

      assert {:ok, %{status: 200, body: %{"ok" => true}}} =
               Transport.get(@provider, "/v1/sys/health")
    end

    test "is refused without it", %{port: port} do
      Application.put_env(:ash_vault, @provider,
        address: "https://localhost:#{port}",
        token: "t",
        max_retries: 0
      )

      assert {:error, %ProviderUnavailable{reason: {:transport, _reason}}} =
               Transport.get(@provider, "/v1/sys/health")
    end

    test "is refused when the address does not match the certificate's name",
         %{ca_path: ca_path, port: port} do
      Application.put_env(:ash_vault, @provider,
        address: "https://127.0.0.1:#{port}",
        token: "t",
        cacertfile: ca_path,
        max_retries: 0
      )

      assert {:error, %ProviderUnavailable{reason: {:transport, _reason}}} =
               Transport.get(@provider, "/v1/sys/health")
    end
  end

  defp certificates(directory) do
    san = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"localhost"]}

    %{server_config: server_config, client_config: client_config} =
      :public_key.pkix_test_data(%{
        server_chain: %{
          root: [key: {:namedCurve, :secp256r1}, digest: :sha256],
          intermediates: [],
          peer: [key: {:namedCurve, :secp256r1}, digest: :sha256, extensions: [san]]
        },
        client_chain: %{root: [], intermediates: [], peer: []}
      })

    ca_path = Path.join(directory, "ca.crt")

    pem =
      client_config
      |> Keyword.fetch!(:cacerts)
      |> Enum.map(&{:Certificate, &1, :not_encrypted})
      |> :public_key.pem_encode()

    File.write!(ca_path, pem)
    {ca_path, Keyword.take(server_config, [:cert, :key, :cacerts])}
  end

  defp accept_loop(listener) do
    with {:ok, socket} <- :ssl.transport_accept(listener) do
      spawn(fn -> serve(socket) end)
      accept_loop(listener)
    end
  end

  defp serve(socket) do
    with {:ok, socket} <- :ssl.handshake(socket, 5_000),
         {:ok, _request} <- :ssl.recv(socket, 0, 5_000) do
      body = ~s({"ok":true})

      :ssl.send(socket, [
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n",
        "content-length: #{byte_size(body)}\r\n\r\n",
        body
      ])

      :ssl.close(socket)
    end
  end
end
