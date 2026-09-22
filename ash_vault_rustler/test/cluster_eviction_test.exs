defmodule AshVaultRustler.ClusterEvictionTest do
  @moduledoc """
  The branch that decides whether a `destroy!` is allowed to report success.

  `AshVault.KeyProviders.Cached.evict_scope/1` fans out to `Node.list(:connected)`, which
  is empty on a single node, so the whole `:erpc.multicall/5` path is skipped in an
  ordinary test run. That is precisely the branch where "reporting success while a peer
  still holds the key" would live, so it is tested directly against the shapes `:erpc`
  actually produces rather than left to a cluster nobody stands up.

  Reference for the shapes: `:erpc.multicall/5` returns `{:ok, Result}`,
  `{:error, {:erpc, Reason}}`, `{:throw, Term}` or `{:exit, Reason}` per node.
  """

  use ExUnit.Case, async: true

  alias AshVault.KeyProviders.Cached

  @nodes [:a@host, :b@host, :c@host]

  test "every node acknowledging is the only success" do
    results = [{:ok, :ok}, {:ok, :ok}, {:ok, :ok}]
    assert Cached.classify_evictions(results, @nodes) == []
  end

  test "a node that answered with an error is reported by name" do
    results = [{:ok, :ok}, {:ok, {:error, :cache_unavailable}}, {:ok, :ok}]

    assert Cached.classify_evictions(results, @nodes) == [{:b@host, :cache_unavailable}]
  end

  test "an unreachable node is a failure, not an absence" do
    results = [{:ok, :ok}, {:error, {:erpc, :noconnection}}, {:ok, :ok}]

    assert [{:b@host, {:error, {:erpc, :noconnection}}}] =
             Cached.classify_evictions(results, @nodes)
  end

  test "a timed-out node is a failure" do
    results = [{:ok, :ok}, {:ok, :ok}, {:error, {:erpc, :timeout}}]

    assert [{:c@host, _}] = Cached.classify_evictions(results, @nodes)
  end

  test "an exit and a throw are both failures" do
    results = [{:exit, {:exception, :killed}}, {:throw, :nope}, {:ok, :ok}]

    assert [{:a@host, _}, {:b@host, _}] = Cached.classify_evictions(results, @nodes)
  end

  test "a node whose RPC raised is a failure, carrying what erpc reported" do
    results = [
      {:ok, :ok},
      {:error, {:exception, %RuntimeError{message: "boom"}, []}},
      {:ok, :ok}
    ]

    assert [{:b@host, {:error, {:exception, %RuntimeError{message: "boom"}, []}}}] =
             Cached.classify_evictions(results, @nodes)
  end

  test "a bare three-element result is still a failure" do
    results = [{:ok, :ok}, {:ok, :ok}, {:exit, :killed, [:stack]}]

    assert [{:c@host, {:exit, :killed}}] = Cached.classify_evictions(results, @nodes)
  end

  test "an answer nobody expected is a failure, never silently accepted" do
    results = [{:ok, :ok}, {:ok, :probably_fine}, :garbage]

    assert [{:b@host, {:unexpected, :probably_fine}}, {:c@host, {:unexpected, :garbage}}] =
             Cached.classify_evictions(results, @nodes)
  end

  test "several failing nodes are all reported, not just the first" do
    results = [{:ok, {:error, :a}}, {:ok, {:error, :b}}, {:ok, {:error, :c}}]

    assert [{:a@host, :a}, {:b@host, :b}, {:c@host, :c}] =
             Cached.classify_evictions(results, @nodes)
  end

  test "no nodes means nothing to fail" do
    assert Cached.classify_evictions([], []) == []
  end
end
