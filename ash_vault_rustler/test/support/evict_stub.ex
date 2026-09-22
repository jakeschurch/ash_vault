defmodule AshVaultRustler.Test.EvictStub do
  @moduledoc """
  A cache backend that does nothing but answer `evict_scope/2`, however the node it is
  running on has been told to.

  It exists so `AshVault.KeyProviders.Cached.evict_scope/2` can be driven across a real
  `:erpc.multicall/5` against real peer nodes without standing up a NIF-backed cache on
  each of them. The answer is read from `:persistent_term` at call time, which is
  per-node state, so the same module name can acknowledge on one peer and fail on
  another — exactly the asymmetry the fan-out has to notice.

  Only the two callbacks the destroy path actually reaches are implemented. It is not an
  `AshVault.KeyCache`; the real backends are covered by their own contract suites.
  """

  @answer_key {__MODULE__, :answer}

  @doc """
  Set this node's answer. Call it on the node whose behaviour you want to change,
  usually through `:erpc.call/4`.

  Accepts `:ok`, `{:error, reason}`, `:raise` (the RPC raises, which `:erpc` reports as
  an exception), and `{:sleep, ms}` (the RPC never answers in time, which `:erpc` reports
  as a timeout).
  """
  @spec answer(term()) :: :ok
  def answer(answer), do: :persistent_term.put(@answer_key, answer)

  @doc "Clear this node's answer, returning it to the acknowledging default."
  @spec reset() :: boolean()
  def reset, do: :persistent_term.erase(@answer_key)

  @doc "Evict a scope, or don't, according to `answer/1`."
  @spec evict_scope(atom(), binary()) :: :ok | {:error, term()}
  def evict_scope(_cache_name, scope) when is_binary(scope) do
    case :persistent_term.get(@answer_key, :ok) do
      :ok -> :ok
      # `:erlang.error/1` and `:timer.sleep/1`, not `raise` and `Process.sleep/1`: this
      # module is pushed to a bare `:peer` node with `:code.load_binary/3`, which has the
      # Erlang kernel but no Elixir standard library. An Elixir call here fails as an
      # `:undef` on `RuntimeError` or `Process` and the test asserts the wrong shape.
      :raise -> :erlang.error(:evict_stub_told_to_raise)
      {:sleep, ms} -> :timer.sleep(ms)
      {:error, _reason} = error -> error
    end
  end

  @doc "Report a miss, so the destroy path's tombstone read has somewhere to go."
  @spec fetch(atom(), binary(), term()) :: {:miss, non_neg_integer()}
  def fetch(_cache_name, _scope, _slot), do: {:miss, 0}

  @doc "Accept and discard a write, so the destroy path's tombstone `put` has somewhere to go."
  @spec put(atom(), binary(), term(), term(), timeout(), term()) :: :ok
  def put(_cache_name, _scope, _slot, _entry, _ttl, _generation), do: :ok
end
