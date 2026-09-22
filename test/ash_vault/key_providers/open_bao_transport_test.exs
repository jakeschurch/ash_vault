defmodule AshVault.KeyProviders.OpenBaoTransportTest do
  @moduledoc """
  A missing OTP application must not look like an OpenBao outage.

  With `:req` unstarted, every call into the provider used to come back as
  `%ProviderUnavailable{reason: {:transport, ArgumentError}}` — byte-for-byte what a
  genuinely unreachable server produces. That sends an operator to page whoever owns the
  secrets infrastructure over a missing line in `extra_applications`, and the reason
  payload gives them nothing to act on either.

  `async: false` because the `:req` application is global: these tests stop it and start
  it again.
  """

  use ExUnit.Case, async: false

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao

  describe "transport_status/0" do
    test "is :ready when :req is running" do
      {:ok, _apps} = Application.ensure_all_started(:req)
      assert OpenBao.transport_status() == :ready
    end

    test "names :req — not :finch — when both are missing" do
      with_req_stopped(fn ->
        # Starting `:req` starts `:finch` with it, so naming `:finch` to someone who is
        # missing both sends them to fix the wrong dependency.
        assert OpenBao.transport_status() == {:not_started, :req}
      end)
    end
  end

  describe "a call made with :req unstarted" do
    setup do
      previous = Application.get_env(:ash_vault, OpenBao)

      Application.put_env(:ash_vault, OpenBao,
        address: "http://127.0.0.1:8200",
        token: "irrelevant-no-request-is-made"
      )

      on_exit(fn ->
        if previous do
          Application.put_env(:ash_vault, OpenBao, previous)
        else
          Application.delete_env(:ash_vault, OpenBao)
        end
      end)

      :ok
    end

    test "reports the unstarted application, not a transport failure" do
      with_req_stopped(fn ->
        assert {:error, %ProviderUnavailable{provider: OpenBao, reason: reason}} =
                 OpenBao.setup()

        assert reason == {:not_started, :req}
        refute reason == {:transport, ArgumentError}
      end)
    end

    test "the message tells an operator what to do, and that it is not an outage" do
      with_req_stopped(fn ->
        assert {:error, error} = OpenBao.setup()
        message = Exception.message(error)

        assert message =~ ":req application is not started"
        assert message =~ "This is not an outage"
        assert message =~ "Retrying will not help"
        assert message =~ "extra_applications"
        assert message =~ "Application.ensure_all_started(:req)"
      end)
    end
  end

  defp with_req_stopped(fun) do
    :ok = Application.stop(:req)
    :ok = Application.stop(:finch)

    try do
      fun.()
    after
      {:ok, _apps} = Application.ensure_all_started(:req)
    end
  end
end
