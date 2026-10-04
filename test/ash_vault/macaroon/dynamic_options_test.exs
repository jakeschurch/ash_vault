defmodule AshVault.Macaroon.DynamicOptionsTest do
  # Not async: Memory, the clock seam and the window answer are global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Errors.InvalidMacaroon
  alias AshVault.Errors.MacaroonRevoked
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.DynamicApiClient
  alias AshVault.Test.Support.Windows

  setup do
    start_supervised!({Memory, name: Memory})
    on_exit(&Windows.reset!/0)
    %{record: Ash.create!(DynamicApiClient, %{})}
  end

  defp mint(record, input \\ %{}, plan \\ nil) do
    DynamicApiClient.mint_dyn(record.id, input, context: %{plan: plan})
  end

  defp expires_in(token) do
    {:ok, record} = DynamicApiClient.dyn_by_token(token)
    DateTime.diff(record.__metadata__.macaroon.expires_at, DateTime.utc_now())
  end

  describe "default_ttl as a function" do
    test "is evaluated with the mint input", %{record: record} do
      {:ok, token} = mint(record)
      assert expires_in(token) in 25..30
    end

    test "is clamped to max_ttl, including :infinity", %{record: record} do
      {:ok, long} = mint(record, %{}, "long")
      {:ok, forever} = mint(record, %{}, "forever")

      assert expires_in(long) in 95..100
      assert expires_in(forever) in 95..100
    end

    test "an invalid result or a raise refuses the mint", %{record: record} do
      assert {:error, error} = mint(record, %{}, "bad")
      assert Exception.message(error) =~ "invalid lifetime"
      assert {:error, error} = mint(record, %{}, "raise")
      assert Exception.message(error) =~ "raised"
    end

    test "an explicit :ttl above max_ttl is refused; within it is honoured", %{record: record} do
      assert {:error, error} = mint(record, %{ttl: 101})
      assert Exception.message(error) =~ "max_ttl"

      {:ok, token} = mint(record, %{ttl: 60})
      assert expires_in(token) in 55..60
    end
  end

  describe "accepted_key_versions as an MFA" do
    setup %{record: record} do
      {:ok, token} = mint(record)
      {:ok, 2} = AshVault.rotate_key!(AshVault.Test.GlobalVault, "global", nil, purpose: :mac)
      %{token: token}
    end

    defp reason({:error, %Ash.Error.Invalid{errors: [%{reason: reason} = error]}}),
      do: {error.__struct__, reason}

    defp reason(other), do: other

    test "a wider answer keeps the previous version", %{token: token} do
      Windows.set!(2)
      assert {:ok, _} = DynamicApiClient.dyn_by_token(token)
      Windows.set!(:all)
      assert {:ok, _} = DynamicApiClient.dyn_by_token(token)
    end

    test "the default answer of 1 retires it", %{token: token} do
      assert reason(DynamicApiClient.dyn_by_token(token)) == {MacaroonRevoked, :key_retired}
    end

    test "an invalid answer fails closed to 1", %{token: token} do
      Windows.set!(:bogus)

      log =
        capture_log(fn ->
          assert reason(DynamicApiClient.dyn_by_token(token)) == {MacaroonRevoked, :key_retired}
        end)

      assert log =~ "failing closed to 1"
      refute log =~ "global\""
    end

    test "a raise fails closed to 1", %{token: token} do
      Windows.set!({:raise, "window service down"})

      capture_log(fn ->
        assert reason(DynamicApiClient.dyn_by_token(token)) == {MacaroonRevoked, :key_retired}
      end)
    end
  end

  describe "caveat check as an inline fn" do
    test ":ok admits and {:error, reason} refuses", %{record: record} do
      {:ok, token} = mint(record, %{caveats: %{tier: "gold"}})

      assert {:ok, _} = DynamicApiClient.dyn_by_token(token, context: %{tier: "gold"})

      assert {:error,
              %Ash.Error.Invalid{errors: [%InvalidMacaroon{reason: {:caveat_failed, :tier}}]}} =
               DynamicApiClient.dyn_by_token(token, context: %{tier: "silver"})
    end
  end
end
