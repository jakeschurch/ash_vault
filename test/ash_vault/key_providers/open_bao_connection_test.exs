defmodule AshVault.KeyProviders.OpenBaoConnectionTest do
  @moduledoc """
  Over real sockets: with `reuse_connections: false` (the default) every OpenBao request
  is made on a new TCP connection, and with `true` the pool reuses one.

  The server is a minimal HTTP/1.1 listener that behaves like Go's `net/http`, which
  OpenBao is built on: a request carrying `connection: close` is answered with
  `Connection: close` and the socket is closed; anything else stays keep-alive. Counting
  accepted connections is what shows a request reaching the `-active` Service afresh,
  rather than riding a connection pinned to a node that has since been demoted.

  `async: false`: the provider's configuration is global.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.OpenBaoTransit, as: Transit

  @health ~s({"initialized":true,"sealed":false,"standby":false,"version":"2.6.3"})

  setup do
    previous = Application.get_env(:ash_vault, Transit)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ash_vault, Transit, previous),
        else: Application.delete_env(:ash_vault, Transit)
    end)

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, accepted} = Agent.start_link(fn -> 0 end)
    acceptor = spawn_link(fn -> accept(listen, accepted) end)

    on_exit(fn ->
      Process.exit(acceptor, :kill)
      :gen_tcp.close(listen)
    end)

    %{address: "http://127.0.0.1:#{port}", accepted: accepted}
  end

  test "by default, every request opens a new connection", %{address: address, accepted: accepted} do
    configure(address, [])

    for _ <- 1..3, do: assert({:ok, :active} = Transit.node_status())

    assert Agent.get(accepted, & &1) == 3
  end

  test "reuse_connections: true reuses one pooled connection", %{
    address: address,
    accepted: accepted
  } do
    configure(address, reuse_connections: true)

    for _ <- 1..3, do: assert({:ok, :active} = Transit.node_status())

    assert Agent.get(accepted, & &1) == 1
  end

  defp configure(address, overrides) do
    Application.put_env(
      :ash_vault,
      Transit,
      Keyword.merge([address: address, token: "unused", max_retries: 0], overrides)
    )
  end

  defp accept(listen, accepted) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        Agent.update(accepted, &(&1 + 1))
        handler = spawn(fn -> serve(socket, "") end)
        :ok = :gen_tcp.controlling_process(socket, handler)
        send(handler, :go)
        accept(listen, accepted)

      {:error, _reason} ->
        :ok
    end
  end

  defp serve(socket, buffer) do
    receive do
      :go -> loop(socket, buffer)
    end
  end

  defp loop(socket, buffer) do
    case :binary.split(buffer, "\r\n\r\n") do
      [head, rest] ->
        close? = head |> String.downcase() |> String.contains?("\r\nconnection: close")
        respond(socket, close?)
        if close?, do: :gen_tcp.close(socket), else: loop(socket, rest)

      [_partial] ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> loop(socket, buffer <> data)
          {:error, _reason} -> :gen_tcp.close(socket)
        end
    end
  end

  defp respond(socket, close?) do
    connection = if close?, do: "close", else: "keep-alive"

    :gen_tcp.send(socket, [
      "HTTP/1.1 200 OK\r\n",
      "content-type: application/json\r\n",
      "content-length: #{byte_size(@health)}\r\n",
      "connection: #{connection}\r\n\r\n",
      @health
    ])
  end
end
