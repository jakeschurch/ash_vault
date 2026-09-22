defmodule AshVaultRustler.PanicTest do
  @moduledoc """
  A panic in Rust must reach the calling process as an ordinary Elixir error and leave
  the node running.

  This is worth a test rather than a sentence, because the failure mode it guards against
  is not "one request 500s" — it is every process on the node dying at once, including
  whatever was holding the only reference to a key that has not yet been persisted.
  """

  use ExUnit.Case, async: false

  alias AshVaultRustler.Native

  test "a panicking NIF raises in the caller and the VM survives" do
    parent = self()

    {pid, ref} =
      spawn_monitor(fn ->
        send(parent, {:result, catch_panic()})
      end)

    assert_receive {:result, result}, 5_000
    assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, 5_000

    assert {:raised, _} = result

    # The node is still here, and still working.
    assert node() == node()
    assert {:ok, _} = Native.encrypt(:crypto.strong_rand_bytes(32), "still alive", "aad")
    assert Native.deliberate_test_panic_atom() == :deliberate_test_panic
  end

  test "a bad slot is a clean error value, not a crash" do
    cache = Native.cache_new(8, 4_096)

    for bad <- [0, -3, -99] do
      assert {:error, :invalid_slot} = Native.cache_fetch(cache, "acme", bad),
             "slot #{bad} should be refused"
    end

    # And the cache is still usable afterwards.
    assert :ok = Native.cache_put(cache, "acme", -1, <<1::256>>, <<0>>, 60_000, 0)
    assert {:ok, _, _, 0} = Native.cache_fetch(cache, "acme", -1)
  end

  test "a wrong-typed argument is a clean error" do
    cache = Native.cache_new(8, 4_096)

    assert_raise ArgumentError, fn -> Native.cache_fetch(cache, :not_a_binary, -1) end
    assert_raise ArgumentError, fn -> Native.encrypt(:not_a_binary, "x", "y") end
  end

  defp catch_panic do
    Native.panic_for_test()
    :no_panic
  rescue
    error -> {:raised, error}
  catch
    kind, reason -> {:raised, {kind, reason}}
  end
end
